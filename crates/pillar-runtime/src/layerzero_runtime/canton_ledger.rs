//! The Canton ledger read behind the extra-context sender, as the published
//! `@layerzerolabs/common-canton` 1.2.66 performs it (`src/provider.ts`
//! `parseCantonChainUri`, `src/client/canton-client.ts` `fetchTransactionByUpdateId`)
//! and `RpcCantonSdk.getFromAddress` consumes it (`rpc-sdk/src/canton/index.ts:86-111,343-360`).
use super::canton_sequencer::js_trim;
use super::source_events_ton::hash_fields;
use super::*;
use crate::provider_health::TransactionFromObservation;
use pillar_config::ProviderConfig;
use zeroize::Zeroizing;

/// The query keys `parseCantonChainUri` removes before the rest becomes the JSON Ledger
/// API base URL.
const CANTON_URI_PARAMS: [&str; 12] = [
    "admin-api",
    "user-id",
    "act-as",
    "wallet-url",
    "sequencer-url",
    "sequencer-validators",
    "sequencer-quorum",
    "token-url",
    "client-id",
    "client-secret",
    "scope",
    "audience",
];

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CantonChainUri {
    pub(crate) json_api_url: String,
    pub(crate) act_as: Vec<String>,
    /// The OAuth2 fields as `searchParams.get` returns them; `Some("")` is kept, as `??` keeps it.
    pub(crate) token_url: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<Zeroizing<String>>,
    pub(crate) scope: Option<String>,
    pub(crate) audience: Option<String>,
}

impl std::fmt::Debug for CantonChainUri {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CantonChainUri")
            .field("json_api_url", &self.json_api_url)
            .field("act_as", &self.act_as)
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .field("audience", &self.audience)
            .finish()
    }
}

/// `parseCantonChainUri`. The `CANTON_CLIENT_SECRET` fallback is applied by
/// [`CantonLedgerAuth`], not here.
pub(crate) fn parse_canton_chain_uri(uri: &str) -> Result<CantonChainUri, String> {
    let mut url = reqwest::Url::parse(uri).map_err(|_| "Invalid URL".to_string())?;
    let first = |url: &reqwest::Url, name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if first(&url, "admin-api").is_none_or(|value| value.is_empty()) {
        return Err(
            "Canton provider URI missing required \"admin-api\" query parameter".to_string(),
        );
    }
    let act_as = first(&url, "act-as")
        .map(|value| {
            value
                .split(',')
                .map(js_trim)
                .filter(|party| !party.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if first(&url, "wallet-url").is_none_or(|value| value.is_empty()) {
        return Err(
            "Canton provider URI missing required \"wallet-url\" query parameter".to_string(),
        );
    }
    let token_url = first(&url, "token-url");
    let client_id = first(&url, "client-id");
    let client_secret = first(&url, "client-secret").map(Zeroizing::new);
    let scope = first(&url, "scope");
    let audience = first(&url, "audience");
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| !CANTON_URI_PARAMS.contains(&key.as_ref()))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    // `URLSearchParams.delete` re-serializes the query and drops it when nothing is left.
    if kept.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(kept);
    }
    let href = url.to_string();
    Ok(CantonChainUri {
        json_api_url: href.strip_suffix('/').unwrap_or(&href).to_string(),
        act_as,
        token_url,
        client_id,
        client_secret,
        scope,
        audience,
    })
}

/// `parseCantonChainUri(rpc[0].uri).actAs`: the parties ledger reads are scoped to.
pub(crate) fn canton_ledger_parties(config: &ProviderConfig) -> Vec<String> {
    config
        .uris
        .first()
        .and_then(|rpc| parse_canton_chain_uri(&provider_uri_parts(rpc).0).ok())
        .map(|uri| uri.act_as)
        .unwrap_or_default()
}

/// `TokenProvider` (`common-canton` `auth/token-provider.ts`): asked before every request.
#[async_trait]
pub(crate) trait CantonTokenProvider: Send + Sync {
    async fn get_token(&self) -> Result<String, AppCoreError>;
}

const CANTON_OAUTH2_REQUIRED: &str = "Canton provider requires OAuth2 credentials (token-url, \
     client-id, client-secret in URI or CANTON_CLIENT_SECRET)";
const TOKEN_BUFFER_SECONDS: f64 = 60.0;
/// Node's `setTimeout` treats a delay above this (or below 1, or NaN) as 1 ms.
const MAX_TIMER_DELAY_MS: f64 = 2_147_483_647.0;

/// `ClientCredentialsTokenProviderConfig`.
#[derive(Clone)]
pub(crate) struct CantonOAuth2Config {
    pub(crate) token_url: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: Zeroizing<String>,
    pub(crate) scope: Option<String>,
    pub(crate) audience: Option<String>,
}

impl std::fmt::Debug for CantonOAuth2Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CantonOAuth2Config")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("scope", &self.scope)
            .field("audience", &self.audience)
            .finish()
    }
}

struct CachedToken {
    token: Zeroizing<String>,
    expires_at: tokio::time::Instant,
}

/// `ClientCredentialsTokenProvider` (`auth/client-credentials-token-provider.ts`): RFC 6749
/// §4.4, cached until `expires_in - 60` seconds. Concurrent callers wait on one fetch; unlike
/// upstream's shared promise, callers queued behind a failed fetch try again.
pub(crate) struct CantonClientCredentials<T> {
    config: CantonOAuth2Config,
    transport: T,
    cached: tokio::sync::Mutex<Option<CachedToken>>,
}

impl<T> CantonClientCredentials<T> {
    pub(crate) fn new(config: CantonOAuth2Config, transport: T) -> Self {
        Self {
            config,
            transport,
            cached: tokio::sync::Mutex::new(None),
        }
    }
}

#[async_trait]
impl<T> CantonTokenProvider for CantonClientCredentials<T>
where
    T: JsonRpcTransport,
{
    async fn get_token(&self) -> Result<String, AppCoreError> {
        let mut cached = self.cached.lock().await;
        if let Some(token) = cached
            .as_ref()
            .filter(|token| tokio::time::Instant::now() < token.expires_at)
        {
            return Ok(token.token.to_string());
        }
        *cached = None;
        let (token, valid_for) = self.fetch_token().await?;
        if let Some(valid_for) = valid_for {
            *cached = Some(CachedToken {
                token: Zeroizing::new(token.clone()),
                expires_at: tokio::time::Instant::now() + valid_for,
            });
        }
        Ok(token)
    }
}

impl<T> CantonClientCredentials<T>
where
    T: JsonRpcTransport,
{
    async fn fetch_token(&self) -> Result<(String, Option<std::time::Duration>), AppCoreError> {
        let mut pairs = vec![
            ("grant_type", "client_credentials"),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
        ];
        for (key, value) in [
            ("scope", &self.config.scope),
            ("audience", &self.config.audience),
        ] {
            if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
                pairs.push((key, value));
            }
        }
        // `URLSearchParams.toString()` is the WHATWG form serializer, which `Url` also uses.
        let mut form = reqwest::Url::parse("http://form.invalid/").expect("static URL parses");
        form.query_pairs_mut().extend_pairs(&pairs);
        let body = Zeroizing::new(form.query().unwrap_or_default().to_string());
        let (status, text) = self
            .transport
            .post_form(
                self.config.token_url.clone(),
                HashMap::new(),
                body.to_string(),
            )
            .await
            .map_err(AppCoreError::Internal)?;
        if !(200..300).contains(&status) {
            let reason = reqwest::StatusCode::from_u16(status)
                .ok()
                .and_then(|status| status.canonical_reason())
                .unwrap_or_default();
            let suffix = if text.is_empty() {
                String::new()
            } else {
                format!(" — {text}")
            };
            return Err(AppCoreError::Internal(format!(
                "Client credentials token request failed: {status} {reason}{suffix}"
            )));
        }
        let response: Value = serde_json::from_str(&text).map_err(|_| {
            AppCoreError::Internal("Client credentials token response is not JSON".into())
        })?;
        // Stricter: upstream would send the ledger request without a token.
        let token = response
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                AppCoreError::Internal(
                    "Client credentials token response has no access_token".into(),
                )
            })?
            .to_string();
        let expires_in = match response.get("expires_in") {
            Some(Value::Number(number)) => number.as_f64(),
            Some(Value::String(text)) => js_trim(text).parse::<f64>().ok(),
            _ => None,
        };
        let delay_ms = expires_in.map(|seconds| (seconds - TOKEN_BUFFER_SECONDS) * 1000.0);
        let valid_for = delay_ms
            .filter(|delay| delay.is_finite() && (1.0..=MAX_TIMER_DELAY_MS).contains(delay))
            .map(|delay| std::time::Duration::from_millis(delay as u64));
        Ok((token, valid_for))
    }
}

/// `createTokenProvider` (`provider.ts:178-195`), one provider per `rpc` entry, built on
/// first use as upstream's multiprovider builds them. Sandbox/localnet would use a
/// self-signed admin JWT upstream; that development auth is not enabled here.
#[derive(Clone, Default)]
pub(crate) struct CantonLedgerAuth {
    local: bool,
    env_client_secret: Option<Zeroizing<String>>,
    providers: Arc<std::sync::Mutex<HashMap<String, Arc<dyn CantonTokenProvider>>>>,
}

impl std::fmt::Debug for CantonLedgerAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CantonLedgerAuth")
            .field("local", &self.local)
            .field(
                "env_client_secret",
                &self.env_client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl CantonLedgerAuth {
    /// `env_client_secret` is `process.env.CANTON_CLIENT_SECRET`.
    pub(crate) fn for_environment(environment: &str, env_client_secret: Option<String>) -> Self {
        Self {
            local: matches!(environment, "localnet" | "sandbox"),
            env_client_secret: env_client_secret.map(Zeroizing::new),
            providers: Arc::default(),
        }
    }

    pub(crate) fn token_provider<T: JsonRpcTransport>(
        &self,
        entry_uri: &str,
        uri: &CantonChainUri,
        transport: &T,
    ) -> Result<Arc<dyn CantonTokenProvider>, AppCoreError> {
        if self.local {
            return Err(AppCoreError::Internal(
                "Canton sandbox/localnet ledger auth (a self-signed admin JWT) is not enabled"
                    .into(),
            ));
        }
        let present = |value: Option<&String>| value.filter(|value| !value.is_empty()).cloned();
        let secret = uri
            .client_secret
            .as_ref()
            .or(self.env_client_secret.as_ref())
            .filter(|secret| !secret.is_empty())
            .cloned();
        let (Some(token_url), Some(client_id), Some(client_secret)) = (
            present(uri.token_url.as_ref()),
            present(uri.client_id.as_ref()),
            secret,
        ) else {
            return Err(AppCoreError::Internal(CANTON_OAUTH2_REQUIRED.into()));
        };
        let mut providers = self
            .providers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let provider = providers.entry(entry_uri.to_string()).or_insert_with(|| {
            Arc::new(CantonClientCredentials::new(
                CantonOAuth2Config {
                    token_url,
                    client_id,
                    client_secret,
                    scope: uri.scope.clone(),
                    audience: uri.audience.clone(),
                },
                transport.clone(),
            ))
        });
        Ok(provider.clone())
    }
}

/// `basePath + "/v2/updates/update-by-id"`. Stricter than upstream: a base URL that still
/// carries a query or fragment would move the path out of the URL path, so it is refused.
fn canton_update_by_id_url(json_api_url: &str) -> Result<String, AppCoreError> {
    let url = reqwest::Url::parse(json_api_url)
        .map_err(|_| AppCoreError::Internal("Invalid URL".to_string()))?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(AppCoreError::Internal(
            "Canton JSON Ledger API URL must not keep a query or fragment".to_string(),
        ));
    }
    Ok(format!("{json_api_url}/v2/updates/update-by-id"))
}

/// `GetUpdateByIdRequestToJSON` of `{ updateId, updateFormat: #buildUpdateFormat([party]) }`.
pub(crate) fn canton_update_by_id_request(update_id: &str, party: &str) -> Value {
    json!({
        "updateId": update_id,
        "updateFormat": {
            "includeTransactions": {
                "eventFormat": {
                    "filtersByParty": {
                        party: {
                            "cumulative": [{
                                "identifierFilter": {
                                    "WildcardFilter": {"value": {"includeCreatedEventBlob": false}},
                                },
                            }],
                        },
                    },
                    "verbose": false,
                },
                "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS",
            },
        },
    })
}

/// `#parseTransactionFromUpdate`: `{ update: { Transaction: { value } } }`.
pub(crate) fn canton_transaction_from_update<'a>(
    response: &'a Value,
    update_id: &str,
) -> Result<&'a Value, AppCoreError> {
    let update = response
        .get("update")
        .and_then(Value::as_object)
        .ok_or_else(|| AppCoreError::Internal("Canton update response has no update".into()))?;
    let transaction = update.get("Transaction").ok_or_else(|| {
        AppCoreError::Internal(format!("Update {update_id} is not a transaction"))
    })?;
    transaction
        .get("value")
        .filter(|value| value.is_object())
        .ok_or_else(|| AppCoreError::Internal("Canton update transaction has no value".into()))
}

/// `getFromAddress`: the first truthy `sender` of an exercise's `choiceArgument` or a
/// create's `createArgument`, else `''`. Stricter than upstream: a truthy sender that is
/// not a string, and an event wrapper that is not an object, are refused.
pub(crate) fn canton_transaction_sender(transaction: &Value) -> Result<String, AppCoreError> {
    let events = match transaction.get("events") {
        None | Some(Value::Null) => return Ok(String::new()),
        Some(Value::Array(events)) => events,
        Some(_) => {
            return Err(AppCoreError::Internal(
                "Canton transaction events are not an array".into(),
            ))
        }
    };
    for event in events {
        let event = event.as_object().ok_or_else(|| {
            AppCoreError::Internal("Canton transaction event is not an object".into())
        })?;
        let (wrapper, argument) = if let Some(exercised) = event.get("ExercisedEvent") {
            (exercised, "choiceArgument")
        } else if let Some(created) = event.get("CreatedEvent") {
            (created, "createArgument")
        } else {
            continue;
        };
        let wrapper = wrapper.as_object().ok_or_else(|| {
            AppCoreError::Internal("Canton transaction event is not an object".into())
        })?;
        match wrapper
            .get(argument)
            .and_then(|argument| argument.get("sender"))
        {
            None | Some(Value::Null) | Some(Value::Bool(false)) => {}
            Some(Value::String(sender)) if sender.is_empty() => {}
            Some(Value::Number(number)) if number.as_f64() == Some(0.0) => {}
            Some(Value::String(sender)) => return Ok(sender.clone()),
            Some(_) => {
                return Err(AppCoreError::Internal(
                    "Canton transaction sender is not a string".into(),
                ))
            }
        }
    }
    Ok(String::new())
}

/// `cantonTransactionQuorumFn` (`multiprovider/src/canton.ts:33-43`).
pub(crate) fn canton_transaction_fingerprint(transaction: &Value) -> String {
    let field = |key: &str| match transaction.get(key) {
        None | Some(Value::Null) => "EMPTY".to_string(),
        Some(Value::String(value)) => value.clone(),
        Some(value) => value.to_string(),
    };
    let events = match transaction.get("events") {
        Some(Value::Array(events)) => events.as_slice(),
        _ => &[],
    };
    let event_digests: Vec<String> = events
        .iter()
        .map(|event| hash_fields(std::iter::once(sort_keys_deep(event).to_string().as_str())))
        .collect();
    let events_digest = hash_fields(event_digests.iter().map(String::as_str));
    let fields = [
        field("updateId"),
        field("offset"),
        field("recordTime"),
        events_digest,
    ];
    hash_fields(fields.iter().map(String::as_str))
}

/// `sortKeysDeep` (`common-utils/src/encoding.ts:171-180`).
fn sort_keys_deep(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sort_keys_deep).collect()),
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), sort_keys_deep(&object[key])))
                    .collect(),
            )
        }
        other => other.clone(),
    }
}

async fn observe_canton_transaction_from<T>(
    transport: T,
    url: String,
    tokens: Arc<dyn CantonTokenProvider>,
    party: String,
    update_id: String,
) -> Result<TransactionFromObservation, AppCoreError>
where
    T: JsonRpcTransport,
{
    // `accessToken` is asked on every request; an empty token sends no header, as upstream.
    let token = Zeroizing::new(tokens.get_token().await?);
    let mut headers = HashMap::new();
    if !token.is_empty() {
        headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", token.as_str()),
        );
    }
    let response = transport
        .post_json_scoped(
            url,
            headers,
            canton_update_by_id_request(&update_id, &party),
        )
        .await
        .map_err(AppCoreError::from)?;
    let transaction = canton_transaction_from_update(&response, &update_id)?;
    Ok(TransactionFromObservation {
        from: canton_transaction_sender(transaction)?,
        fingerprint: canton_transaction_fingerprint(transaction),
    })
}

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    /// One quorum read per party, in order, returning the first that succeeds. `tokens`
    /// resolves each `rpc` entry's token provider (raw entry URI, parsed URI).
    pub(crate) async fn canton_transaction_from_address<B>(
        &self,
        parties: &[String],
        update_id: &str,
        tokens: B,
    ) -> Result<String, AppCoreError>
    where
        B: Fn(&str, &CantonChainUri) -> Result<Arc<dyn CantonTokenProvider>, AppCoreError>,
    {
        let mut last_error =
            AppCoreError::Internal("Canton RPC provider has no configured parties".into());
        for party in parties {
            match self
                .canton_party_transaction_from(party, update_id, &tokens)
                .await
            {
                Ok(from) => return Ok(from),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    async fn canton_party_transaction_from<B>(
        &self,
        party: &str,
        update_id: &str,
        tokens: &B,
    ) -> Result<String, AppCoreError>
    where
        B: Fn(&str, &CantonChainUri) -> Result<Arc<dyn CantonTokenProvider>, AppCoreError>,
    {
        crate::provider_health::rpc_scope("canton", async {
            let snapshot = self.providers.load();
            let ChainDispatch {
                config,
                quorum,
                plan,
            } = snapshot.dispatch(&self.rank_tracker, "canton").await?;
            // Upstream builds every provider (URI, then token provider) before reading.
            let mut targets = Vec::with_capacity(config.uris.len());
            for entry in &config.uris {
                let raw = provider_uri_parts(entry).0;
                let uri = parse_canton_chain_uri(&raw).map_err(AppCoreError::Internal)?;
                targets.push((
                    canton_update_by_id_url(&uri.json_api_url)?,
                    tokens(&raw, &uri)?,
                ));
            }
            let requests = FuturesUnordered::new();
            for DispatchEntry { index, delay, .. } in plan {
                let Some((url, token)) = targets.get(index).cloned() else {
                    continue;
                };
                let transport = self.transport.clone();
                let party = party.to_string();
                let update_id = update_id.to_string();
                requests.push(async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let observation = provider_response(
                        observe_canton_transaction_from(transport, url, token, party, update_id)
                            .await,
                    )
                    .map(|observation| {
                        observation
                            .map(|observation| (observation.fingerprint.clone(), observation))
                    });
                    (index, observation)
                });
            }
            let observation = resolve_provider_quorum(
                requests,
                config.uris.len(),
                quorum,
                "transaction-from for chain canton",
            )
            .await?;
            Ok(observation.from)
        })
        .await
    }
}
