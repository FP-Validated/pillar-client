//! Online, fail-closed DVN control-plane client. No policy decisions are cached.
use crate::{layerzero_runtime::config::runtime_chain_name_by_endpoint_id, ProviderSnapshotHandle};
use async_trait::async_trait;
use pillar_core::dvn::{
    intent_digest, now_ms, policy_error, sha256_hex, AssetCodec, AuthorizeRequest,
    AuthorizeResponse, ChainBinding, EnvelopeVerifier, Environment, PermitExpectation,
    RegistrySnapshot, RequestKind, SignedEnvelope, SigningAuthorization, SigningPolicy,
    SigningScope, Subject, VerifiedEnvelope, MAX_ENVELOPE_BYTES, REGISTRY_SCHEMA,
};
use pillar_core::{AppCoreError, LzSentEvent, SentEventResolver, SigningContext};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    collections::{HashMap, HashSet},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

pub(crate) struct DvnGateConfig {
    url: url::Url,
    token: String,
    verifier: EnvelopeVerifier,
    environment: Environment,
    workload_id: String,
    instance_id: String,
}

impl DvnGateConfig {
    pub(crate) fn from_env(vars: &HashMap<String, String>) -> Result<Self, String> {
        let required = |name: &str| {
            vars.get(name)
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .ok_or_else(|| format!("{name} is required for mandatory DVN authorization"))
        };
        let environment = match required("LAYERZERO_ENVIRONMENT")?.as_str() {
            "mainnet" => Environment::Mainnet,
            "testnet" => Environment::Testnet,
            _ => return Err("DVN policy supports only mainnet or testnet".into()),
        };
        let url = url::Url::parse(&required("PILLAR_DVN_GATE_URL")?)
            .map_err(|_| "Invalid PILLAR_DVN_GATE_URL".to_string())?;
        if !(url.scheme() == "https"
            || (url.scheme() == "http" && pillar_config::is_literal_loopback(&url)))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "PILLAR_DVN_GATE_URL must be an HTTPS origin (HTTP literal loopback only)".into(),
            );
        }
        let verifier = EnvelopeVerifier::new(
            required("PILLAR_DVN_GATE_KEY_ID")?,
            &required("PILLAR_DVN_GATE_PUBLIC_KEY")?,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            url,
            token: required("PILLAR_DVN_GATE_TOKEN")?,
            verifier,
            environment,
            workload_id: required("PILLAR_DVN_WORKLOAD_ID")?,
            instance_id: required("PILLAR_DVN_INSTANCE_ID")?,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstanceChain {
    eid: u32,
    name: String,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Registration<'a> {
    instance_id: &'a str,
    boot_id: &'a str,
    environment: Environment,
    registry_revision: u64,
    registry_digest: &'a str,
    chains: &'a [InstanceChain],
}

struct AppliedRegistry {
    snapshot: Arc<RegistrySnapshot>,
    packet_chain_names: Arc<HashMap<u32, String>>,
    digest: String,
    acknowledged_at: Instant,
    provider_generation: u64,
}

pub(crate) struct DvnGateClient {
    config: DvnGateConfig,
    client: reqwest::Client,
    boot_id: String,
    providers: ProviderSnapshotHandle,
    state: RwLock<Option<Arc<AppliedRegistry>>>,
    fence: Arc<pillar_core::dvn::RevisionFence>,
}

impl DvnGateClient {
    pub(crate) async fn connect(
        config: DvnGateConfig,
        providers: ProviderSnapshotHandle,
    ) -> Result<Arc<Self>, String> {
        // Kernel-generated randomness, not a pod name, timestamp or restart counter.
        let mut random = [0_u8; 32];
        std::io::Read::read_exact(
            &mut std::fs::File::open("/dev/urandom")
                .map_err(|_| "Cannot initialize DVN boot identity".to_string())?,
            &mut random,
        )
        .map_err(|_| "Cannot initialize DVN boot identity".to_string())?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| "Cannot initialize DVN Gate transport".to_string())?;
        let gate = Arc::new(Self {
            config,
            client,
            boot_id: hex::encode(random),
            providers,
            state: RwLock::new(None),
            fence: Arc::new(pillar_core::dvn::RevisionFence::default()),
        });
        let (chains, _) = gate.roster().map_err(|error| error.to_string())?;
        gate.register(0, "", &chains)
            .await
            .map_err(|error| error.to_string())?;
        gate.refresh().await.map_err(|error| error.to_string())?;
        Ok(gate)
    }

    fn roster(&self) -> Result<(Vec<InstanceChain>, u64), AppCoreError> {
        let snapshot = self.providers.load();
        let bindings = runtime_bindings(self.config.environment, snapshot.available_chain_names())?;
        let chains = bindings
            .into_iter()
            .map(|chain| InstanceChain {
                eid: chain.eid,
                name: chain.name,
                capabilities: vec![
                    "protocol:layerzero".to_string(),
                    format!("address-format:{}", chain.address_format),
                ],
            })
            .collect();
        Ok((chains, snapshot.generation()))
    }

    fn endpoint(&self, path: &str) -> Result<url::Url, AppCoreError> {
        self.config
            .url
            .join(path)
            .map_err(|_| policy_error("Invalid DVN endpoint"))
    }

    async fn register(
        &self,
        revision: u64,
        digest: &str,
        chains: &[InstanceChain],
    ) -> Result<(), AppCoreError> {
        let body = Registration {
            instance_id: &self.config.instance_id,
            boot_id: &self.boot_id,
            environment: self.config.environment,
            registry_revision: revision,
            registry_digest: digest,
            chains,
        };
        let response = self
            .client
            .post(self.endpoint("/internal/v1/dvn/instances")?)
            .bearer_auth(&self.config.token)
            .json(&body)
            .send()
            .await
            .map_err(|_| policy_error("DVN instance registration unavailable"))?;
        if !response.status().is_success() {
            return Err(policy_error("DVN instance registration refused"));
        }
        Ok(())
    }

    async fn refresh(&self) -> Result<(), AppCoreError> {
        let current = self.state.read().await.clone();
        let after = current.as_ref().map_or(0, |state| state.snapshot.revision);
        let (chains, generation) = self.roster()?;
        let mut endpoint = self.endpoint("/internal/v1/dvn/registry")?;
        endpoint
            .query_pairs_mut()
            .append_pair("environment", self.config.environment.as_str())
            .append_pair("after", &after.to_string());
        let response = self
            .client
            .get(endpoint)
            .bearer_auth(&self.config.token)
            .send()
            .await
            .map_err(|_| policy_error("DVN registry unavailable"))?;
        let (snapshot, digest, packet_chain_names) =
            if response.status() == reqwest::StatusCode::NO_CONTENT {
                let previous = current
                    .as_ref()
                    .ok_or_else(|| policy_error("DVN registry is unconfigured"))?;
                (
                    previous.snapshot.clone(),
                    previous.digest.clone(),
                    previous.packet_chain_names.clone(),
                )
            } else {
                let envelope: SignedEnvelope = response_json(response).await?;
                let snapshot: RegistrySnapshot =
                    self.config.verifier.verify(&envelope, REGISTRY_SCHEMA)?;
                if snapshot.revision < after
                    || current.as_ref().is_some_and(|state| {
                        snapshot.revision == after && envelope.sha256 != state.digest
                    })
                {
                    return Err(policy_error(
                        "DVN registry rollback or conflicting revision",
                    ));
                }
                let names = snapshot
                    .chains
                    .iter()
                    .map(|chain| chain.name.clone())
                    .collect::<Vec<_>>();
                let packet_chain_names =
                    runtime_chain_name_by_endpoint_id(self.config.environment.as_str(), &names)
                        .map_err(|_| policy_error("Invalid DVN registry endpoint identities"))?;
                (
                    Arc::new(snapshot),
                    envelope.sha256,
                    Arc::new(packet_chain_names),
                )
            };
        if current.as_ref().is_none_or(|previous| {
            previous.digest != digest || previous.provider_generation != generation
        }) {
            validate_registry(&snapshot, self.config.environment, &chains)?;
        }
        self.register(snapshot.revision, &digest, &chains).await?;
        if self.providers.generation() != generation {
            return Err(policy_error("DVN runtime roster changed during ACK"));
        }
        self.fence
            .registry_revision
            .store(snapshot.revision, Ordering::Release);
        *self.state.write().await = Some(Arc::new(AppliedRegistry {
            snapshot,
            packet_chain_names,
            digest,
            acknowledged_at: Instant::now(),
            provider_generation: generation,
        }));
        Ok(())
    }

    pub(crate) async fn ready(&self) -> bool {
        self.state.read().await.as_ref().is_some_and(|state| {
            state.acknowledged_at.elapsed() < Duration::from_secs(25)
                && state.provider_generation == self.providers.generation()
        })
    }

    pub(crate) fn spawn_refresh(
        self: &Arc<Self>,
        heartbeat: impl Fn() + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let gate = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                heartbeat();
                if gate.refresh().await.is_err() {
                    gate.fence.registry_revision.store(0, Ordering::Release);
                    // Do not log tokens, policy facts, addresses, or transport response bodies.
                    tracing::warn!(
                        "DVN registry refresh or ACK failed; signing remains fail-closed"
                    );
                    if let Some(state) = gate.state.write().await.as_mut() {
                        // Preserve the monotonic revision/digest for the next fetch, but revoke readiness.
                        Arc::make_mut(state).acknowledged_at =
                            Instant::now() - Duration::from_secs(25);
                    }
                }
            }
        })
    }
}

impl Clone for AppliedRegistry {
    fn clone(&self) -> Self {
        Self {
            snapshot: self.snapshot.clone(),
            digest: self.digest.clone(),
            packet_chain_names: self.packet_chain_names.clone(),
            acknowledged_at: self.acknowledged_at,
            provider_generation: self.provider_generation,
        }
    }
}

#[async_trait]
impl SigningPolicy for DvnGateClient {
    async fn authorize(
        &self,
        envelope: &VerifiedEnvelope<'_>,
        resolver: &dyn SentEventResolver,
        hash_call_data: &str,
        scopes: Vec<SigningScope>,
    ) -> Result<SigningAuthorization, AppCoreError> {
        if !self.ready().await {
            return Err(policy_error("DVN registry is not acknowledged or is stale"));
        }
        let state = self
            .state
            .read()
            .await
            .clone()
            .ok_or_else(|| policy_error("DVN registry missing"))?;
        let mut subject =
            subject_from_verified(envelope, &state.snapshot, &state.packet_chain_names)?;
        if let Some(binding) = state.snapshot.asset_bindings.iter().find(|binding| {
            binding.src_eid == subject.src_eid
                && binding.dst_eid == subject.dst_eid
                && binding.src_oapp == subject.src_oapp
                && binding.dst_oapp == subject.dst_oapp
        }) {
            subject.asset_binding_id = Some(binding.id.clone());
            if binding.codec == AssetCodec::OftV1 && subject.request_kind == RequestKind::Message {
                let (recipient, amount) = decode_oft_v1(&envelope.event().message)?;
                subject.token_recipient = Some(recipient);
                subject.amount_shared_units = Some(amount);
                let destination = state
                    .snapshot
                    .chains
                    .iter()
                    .find(|chain| chain.eid == subject.dst_eid)
                    .ok_or_else(|| policy_error("Unknown OFT destination"))?;
                validate_chain_address(
                    subject
                        .token_recipient
                        .as_deref()
                        .expect("decoded recipient"),
                    &destination.address_format,
                )?;
                if let Some(sender) = resolver
                    .verified_token_sender(envelope.event(), binding)
                    .await?
                {
                    subject.source_evidence_digest = sha256_hex(
                        format!(
                            "pillar.dvn-source-evidence/v1\0{}\0{}",
                            subject.source_evidence_digest, sender.evidence_digest
                        )
                        .as_bytes(),
                    );
                    subject.token_sender = Some(sender.address);
                }
            }
        }
        let request = AuthorizeRequest {
            instance_id: self.config.instance_id.clone(),
            boot_id: self.boot_id.clone(),
            registry_revision: state.snapshot.revision,
            subject,
            intent_digest: intent_digest(hash_call_data, &scopes)?,
            wallet_names: scopes
                .iter()
                .map(|scope| scope.wallet_name.clone())
                .collect(),
        };
        let raw_request = bytes::Bytes::from(
            serde_json::to_vec(&request)
                .map_err(|_| policy_error("DVN request encoding failed"))?,
        );
        // Send exactly these bytes; never reserialize the request after hashing it.
        let response = self
            .client
            .post(self.endpoint("/internal/v1/dvn/authorize")?)
            .bearer_auth(&self.config.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(raw_request.clone())
            .send()
            .await
            .map_err(|_| policy_error("DVN authorization unavailable"))?;
        let response: AuthorizeResponse = response_json(response).await?;
        let AuthorizeResponse::Allow { permit } = response else {
            return Err(policy_error("DVN signing denied by policy"));
        };
        if !self.ready().await
            || self.state.read().await.as_ref().is_none_or(|current| {
                current.snapshot.revision != state.snapshot.revision
                    || current.digest != state.digest
            })
        {
            return Err(policy_error("DVN registry changed during authorization"));
        }
        let (authorization, permit) = self.config.verifier.authorize(
            &permit,
            &PermitExpectation {
                request: &request,
                raw_request: &raw_request,
                workload_id: &self.config.workload_id,
                minimum_policy_revision: self.fence.policy_revision.load(Ordering::Acquire),
                minimum_safety_epoch: self.fence.safety_epoch.load(Ordering::Acquire),
            },
            hash_call_data,
            scopes,
            now_ms()?,
        )?;
        self.fence
            .policy_revision
            .fetch_max(permit.policy_revision, Ordering::AcqRel);
        self.fence
            .safety_epoch
            .fetch_max(permit.safety_epoch, Ordering::AcqRel);
        if permit.policy_revision < self.fence.policy_revision.load(Ordering::Acquire)
            || permit.safety_epoch < self.fence.safety_epoch.load(Ordering::Acquire)
        {
            return Err(policy_error("DVN permit superseded during authorization"));
        }
        Ok(authorization.with_revision_fence(
            self.fence.clone(),
            permit.policy_revision,
            permit.safety_epoch,
            state.snapshot.revision,
        ))
    }
}

async fn response_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, AppCoreError> {
    if !response.status().is_success() {
        return Err(policy_error("DVN Gate HTTP error"));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ENVELOPE_BYTES as u64)
    {
        return Err(policy_error("DVN Gate response exceeds size limit"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| policy_error("DVN Gate response interrupted"))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_ENVELOPE_BYTES {
            return Err(policy_error("DVN Gate response exceeds size limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| policy_error("Invalid DVN response text"))?;
    pillar_core::json::from_str(text).map_err(|_| policy_error("Invalid DVN response schema"))
}

fn address_format(name: &str) -> Result<&'static str, AppCoreError> {
    match pillar_config::static_chain_type_name(name)
        .map_err(|_| policy_error("Unknown DVN chain type"))?
    {
        "EVM" => Ok("evm"),
        "TRON" => Ok("tron"),
        "APTOS" => Ok("aptos"),
        "SOLANA" => Ok("solana"),
        "SUI" => Ok("sui"),
        "IOTAMOVE" => Ok("iota-move"),
        "STARKNET" => Ok("starknet"),
        "STELLAR" => Ok("stellar"),
        "INITIA" => Ok("initia"),
        "TON" => Ok("ton"),
        "CANTON" => Ok("canton"),
        _ => Err(policy_error("Unsupported DVN native address capability")),
    }
}

fn runtime_bindings(
    environment: Environment,
    names: &[String],
) -> Result<Vec<ChainBinding>, AppCoreError> {
    let mapping = runtime_chain_name_by_endpoint_id(environment.as_str(), names)
        .map_err(|_| policy_error("Cannot derive DVN runtime endpoint roster"))?;
    let mut bindings = Vec::with_capacity(names.len());
    for name in names {
        let mut candidates = mapping
            .iter()
            .filter(|(eid, candidate)| **eid >= 30_000 && *candidate == name);
        let eid = *candidates
            .next()
            .ok_or_else(|| policy_error("DVN runtime chain has no EndpointV2 id"))?
            .0;
        if candidates.next().is_some() {
            return Err(policy_error("Ambiguous DVN runtime EndpointV2 id"));
        }
        bindings.push(ChainBinding {
            eid,
            name: name.clone(),
            address_format: address_format(name)?.to_string(),
        });
    }
    bindings.sort_unstable_by_key(|chain| chain.eid);
    Ok(bindings)
}

fn validate_registry(
    snapshot: &RegistrySnapshot,
    environment: Environment,
    roster: &[InstanceChain],
) -> Result<(), AppCoreError> {
    if snapshot.schema_version != REGISTRY_SCHEMA
        || snapshot.environment != environment
        || snapshot.revision == 0
    {
        return Err(policy_error(
            "DVN registry schema, environment or revision mismatch",
        ));
    }
    let names = snapshot
        .chains
        .iter()
        .map(|chain| chain.name.clone())
        .collect::<Vec<_>>();
    let actual = runtime_bindings(environment, &names)?;
    let mut eids = HashSet::new();
    let mut chain_names = HashSet::new();
    for chain in &snapshot.chains {
        if !eids.insert(chain.eid) || !chain_names.insert(&chain.name) || !actual.contains(chain) {
            return Err(policy_error("DVN registry chain capability mismatch"));
        }
    }
    for chain in roster {
        if !snapshot.chains.iter().any(|binding| {
            binding.eid == chain.eid
                && binding.name == chain.name
                && chain
                    .capabilities
                    .contains(&format!("address-format:{}", binding.address_format))
        }) {
            return Err(policy_error("DVN registry omits an active runtime chain"));
        }
    }
    let mut ids = HashSet::new();
    let mut pathways = HashSet::new();
    for binding in &snapshot.asset_bindings {
        if binding.id.is_empty()
            || binding.asset_id.is_empty()
            || binding.asset_group.is_empty()
            || !ids.insert(&binding.id)
            || !pathways.insert((
                binding.src_eid,
                binding.dst_eid,
                &binding.src_oapp,
                &binding.dst_oapp,
            ))
        {
            return Err(policy_error("DVN registry has ambiguous asset bindings"));
        }
        for (eid, address) in [
            (binding.src_eid, &binding.src_oapp),
            (binding.dst_eid, &binding.dst_oapp),
        ] {
            let chain = snapshot
                .chains
                .iter()
                .find(|chain| chain.eid == eid)
                .ok_or_else(|| policy_error("DVN asset binding references an unknown chain"))?;
            if canonical_protocol_address(address)? != *address {
                return Err(policy_error("DVN asset OApp is not canonical"));
            }
            validate_chain_address(address, &chain.address_format)?;
        }
    }
    Ok(())
}

pub(crate) fn canonical_protocol_address(address: &str) -> Result<String, AppCoreError> {
    let raw = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .ok_or_else(|| policy_error("DVN packet address is not protocol hex"))?;
    if raw.is_empty() || raw.len() > 64 || raw.len() % 2 != 0 {
        return Err(policy_error("Invalid DVN protocol address width"));
    }
    let bytes = hex::decode(raw).map_err(|_| policy_error("Invalid DVN protocol address"))?;
    let mut canonical = [0_u8; 32];
    canonical[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(format!("0x{}", hex::encode(canonical)))
}

fn validate_chain_address(address: &str, format: &str) -> Result<(), AppCoreError> {
    let bytes = hex::decode(address.strip_prefix("0x").unwrap_or(address))
        .map_err(|_| policy_error("Invalid DVN chain address"))?;
    if bytes.len() != 32 || (matches!(format, "evm" | "tron") && bytes[..12] != [0; 12]) {
        return Err(policy_error("DVN address violates native chain width"));
    }
    Ok(())
}

fn packet_eid(event: &LzSentEvent, key: &str) -> Result<u32, AppCoreError> {
    let value = event
        .lz_message_id
        .pathway_id
        .extra
        .get(key)
        .ok_or_else(|| policy_error("Verified DVN packet lacks an endpoint id"))?;
    let number = match value {
        serde_json::Value::String(value)
            if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value.parse::<u32>().ok()
        }
        serde_json::Value::Number(value) => {
            value.as_u64().and_then(|value| u32::try_from(value).ok())
        }
        _ => None,
    };
    number.ok_or_else(|| policy_error("Invalid verified DVN endpoint id"))
}

fn source_endpoint_protocol(event: &LzSentEvent) -> Result<&'static str, AppCoreError> {
    // This is the resolved SOURCE library version: EVM resolution binds it to the
    // trusted emitter/event kind; native decoders bind it to their source event.
    // Core verifies that version before validation. ULN V2 receiver migration
    // preserves it when hydrating a packet, unlike the destination builder route.
    match event.lz_message_id.uln_send_version.as_str() {
        Some("V2" | "V301") => Ok("layerzero-v1"),
        Some("V302" | "ReadV1002") => Ok("layerzero-v2"),
        _ => Err(policy_error(
            "Unsupported verified DVN source endpoint generation",
        )),
    }
}

fn subject_from_verified(
    envelope: &VerifiedEnvelope<'_>,
    registry: &RegistrySnapshot,
    actual_ids: &HashMap<u32, String>,
) -> Result<Subject, AppCoreError> {
    let event = envelope.event();
    let pathway = &event.lz_message_id.pathway_id;
    let source = registry
        .chains
        .iter()
        .find(|chain| chain.name == pathway.src_chain_name)
        .ok_or_else(|| policy_error("Verified DVN source is absent from registry"))?;
    let destination = registry
        .chains
        .iter()
        .find(|chain| chain.name == pathway.dst_chain_name)
        .ok_or_else(|| policy_error("Verified DVN destination is absent from registry"))?;
    let read = matches!(envelope.context(), SigningContext::Read { .. });
    let src_eid = packet_eid(event, "srcEid")?;
    let dst_eid = packet_eid(event, "dstEid")?;
    if actual_ids.get(&dst_eid) != Some(&destination.name)
        || if read {
            !pillar_layerzero::is_lz_read_endpoint_id(src_eid) || source.name != destination.name
        } else {
            actual_ids.get(&src_eid) != Some(&source.name)
        }
    {
        return Err(policy_error(
            "Verified packet endpoint does not match runtime chain",
        ));
    }
    let address = |name: &str, format: &str| {
        let raw = pathway
            .extra
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| policy_error("Verified packet lacks OApp identity"))?;
        let address = canonical_protocol_address(raw)?;
        validate_chain_address(&address, format)?;
        Ok::<_, AppCoreError>(address)
    };
    let src_oapp = address("sender", &source.address_format)?;
    let dst_oapp = address("receiver", &destination.address_format)?;
    let message = hex::decode(event.message.strip_prefix("0x").unwrap_or(&event.message))
        .map_err(|_| policy_error("Invalid verified packet message"))?;
    // ULNv2 source packets have no GUID. Receiver migration synthesizes one for the
    // destination proof only; it must not change admission identity or payload hash.
    // Native V301/V302 GUIDs remain source facts and are preserved below.
    let source_guid = if event.lz_message_id.uln_send_version == "V2" {
        None
    } else {
        event.extra.get("guid")
    };
    let guid = source_guid
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| policy_error("Invalid verified packet guid"))?;
            let raw = value.strip_prefix("0x").unwrap_or(value);
            let bytes =
                hex::decode(raw).map_err(|_| policy_error("Invalid verified packet guid"))?;
            if bytes.len() != 32 {
                return Err(policy_error("Invalid verified packet guid width"));
            }
            Ok(hex::encode(bytes))
        })
        .transpose()?;
    let mut payload = Keccak256::new();
    if !read {
        if let Some(guid) = &guid {
            payload.update(hex::decode(guid).map_err(|_| policy_error("Invalid packet guid"))?);
        }
    }
    payload.update(&message);
    // Includes validated provider evidence (serde(skip) in the event), source block metadata,
    // READ block pins and exact validated packet, not caller-supplied asset/group labels.
    let pins = event
        .read_block_pins
        .iter()
        .map(|pin| (&pin.chain_name, pin.block_number, &pin.block_hash))
        .collect::<Vec<_>>();
    let source_evidence_digest =
        pillar_core::dvn::json_sha256(&(event, &event.source_evidence, pins))?;
    Ok(Subject {
        environment: registry.environment,
        protocol: source_endpoint_protocol(event)?.to_string(),
        request_kind: if read {
            RequestKind::Read
        } else {
            RequestKind::Message
        },
        src_eid: source.eid,
        dst_eid: destination.eid,
        src_endpoint_id: src_eid,
        dst_endpoint_id: dst_eid,
        src_oapp,
        dst_oapp,
        nonce: event.lz_message_id.nonce.to_string(),
        payload_hash: hex::encode(payload.finalize()),
        guid,
        source_evidence_digest,
        asset_binding_id: None,
        token_sender: None,
        token_recipient: None,
        amount_shared_units: None,
    })
}

fn decode_oft_v1(message: &str) -> Result<(String, String), AppCoreError> {
    // OFTMsgCodec: sendTo(bytes32) || amountSD(uint64 big endian) || optional compose bytes.
    // LayerZero OFT-EVM v2 contracts/oft/libs/OFTMsgCodec.sol, SEND_TO_OFFSET=32,
    // SEND_AMOUNT_SD_OFFSET=40. No local-decimals inference or floating-point conversion.
    let bytes = hex::decode(message.strip_prefix("0x").unwrap_or(message))
        .map_err(|_| policy_error("Invalid OFT message encoding"))?;
    if bytes.len() < 40 || (bytes.len() > 40 && bytes.len() < 72) {
        return Err(policy_error("Invalid OFT message length"));
    }
    let amount = u64::from_be_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| policy_error("Invalid OFT amount"))?,
    );
    Ok((
        format!("0x{}", hex::encode(&bytes[..32])),
        amount.to_string(),
    ))
}

#[cfg(test)]
pub(crate) mod tests;
