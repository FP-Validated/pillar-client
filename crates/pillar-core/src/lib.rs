use async_trait::async_trait;
use futures::{stream, StreamExt, TryStreamExt};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, sync::Arc, time::Instant};

pub mod audit;
pub mod execution;
mod provider_health_cache;

pub use provider_health_cache::{
    ProviderHealthCache, ProviderHealthSnapshot, ProviderHealthSource,
    PROVIDER_HEALTH_CACHE_STALE_ALLOWANCE_MS, PROVIDER_HEALTH_CACHE_STALE_MS,
    PROVIDER_HEALTH_CACHE_TTL_MS,
};

pub type ProviderHealthReport = IndexMap<String, ChainProviderHealthReport>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderHealthEntry {
    /// Redacted for display. This is a public HTTP payload, so it must never
    /// carry the path, query or userinfo an RPC key lives in.
    pub url: String,
    /// The URL this entry actually describes, as dispatched to.
    ///
    /// Never serialized - it is the same secret-bearing string `url` exists to
    /// hide - but provider ranking has to key off it: the redacted form is
    /// lossy, so it neither matches what dispatch looks up nor distinguishes
    /// two URLs on one host.
    #[serde(skip)]
    pub rank_key: String,
    pub response: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub healthy: bool,
    #[serde(default = "observed_by_default", skip_serializing_if = "is_observed")]
    pub observed: bool,
    pub numeric_response: Option<String>,
}

fn observed_by_default() -> bool {
    true
}
fn is_observed(value: &bool) -> bool {
    *value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChainProviderHealthReport {
    pub healthy: bool,
    pub checked_at_unix_ms: u64,
    pub providers: Vec<ProviderHealthEntry>,
}

pub const PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX: &str = "Payload already signed";
pub const EXPIRED_TIMESTAMP_ERROR_PREFIX: &str = "Expiration has already passed";
/// Marks the resolver's `BadRequest` for a trusted event that is not the requested packet.
pub const PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX: &str =
    "does not match the requested pathway identity";
const MAX_CONCURRENT_WALLET_SIGNS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub signature: String,
    pub address: String,
}

/// The v1 `lzMessageId` as the client sent it. Upstream reads these fields with
/// JavaScript coercions (`parseInt`, `toString`, `===`), so each keeps the JSON
/// value it arrived as; `None` is a field that was absent (`undefined`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LegacyLzMessageId {
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub src_chain_id: Option<Value>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub nonce: Option<Value>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub dst_chain_id: Option<Value>,
    #[serde(
        rename = "srcUAAddress",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub src_ua_address: Option<Value>,
    #[serde(
        rename = "dstUAAddress",
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub dst_ua_address: Option<Value>,
}

/// A present field, `null` included; only an absent one is `None`.
fn present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PillarApiRequestV1 {
    pub src_tx_hash: String,
    pub lz_message_id: LegacyLzMessageId,
    pub block_confirmation: i64,
    pub expiration: i64,
    pub uln_version: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_v_id: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dvn_address: Option<String>,
    pub message_hash: String,
}

/// Every member of the protocol's send-version enum. A value outside this set
/// is a malformed request; a value inside it that this service installs no
/// builder for is an *unsupported* one, and the two must not be conflated -
/// answering "expected one of V2, V301, V302, ReadV1002" to a `V1` request would
/// tell the caller that `V1` is not a LayerZero version.
///
/// The set mirrors upstream's enum, which likewise carries six members while its
/// builder map installs four (TS: `packages/common-model/src/v1/lzMessage.ts:48-55`
/// for the enum and `:57` for the `z.nativeEnum` schema the HTTP boundary parses
/// with; `apps/gasolina/src/app/hashCallDataBuilder/index.ts:31-36` for the map).
/// So a `V1` request reaching a missing builder is upstream's shape too, not a
/// divergence. Read from the tree `SECURITY.md` identifies by content hash.
///
/// Shared with `pillar-api` so the boundary and the core cannot drift apart.
pub const ULN_SEND_VERSIONS: [&str; 6] = ["V1", "V2", "V300", "V301", "V302", "ReadV1002"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PathwayId {
    pub src_chain_name: String,
    pub dst_chain_name: String,
    #[serde(flatten)]
    pub extra: IndexMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LzMessageId {
    pub pathway_id: PathwayId,
    pub nonce: u64,
    pub uln_send_version: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedTimestampTimeMarker {
    #[serde(rename = "blockConfirmation")]
    pub block_confirmation: i64,
    #[serde(rename = "isBlockNumber")]
    pub is_block_number: bool,
    #[serde(rename = "chainName")]
    pub chain_name: String,
    #[serde(rename = "blockNumber")]
    pub block_number: i64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "protocolType")]
pub enum SigningContext {
    #[serde(rename = "MESSAGE")]
    Message {
        expiration: i64,
        #[serde(rename = "skipVId", skip_serializing_if = "Option::is_none")]
        skip_v_id: Option<bool>,
        #[serde(rename = "dvnAddress", skip_serializing_if = "Option::is_none")]
        dvn_address: Option<String>,
        #[serde(rename = "blockConfirmation")]
        block_confirmation: i64,
    },
    #[serde(rename = "READ")]
    Read {
        expiration: i64,
        #[serde(rename = "skipVId", skip_serializing_if = "Option::is_none")]
        skip_v_id: Option<bool>,
        #[serde(rename = "dvnAddress", skip_serializing_if = "Option::is_none")]
        dvn_address: Option<String>,
        #[serde(rename = "resolvedTimestampTimeMarkers")]
        resolved_timestamp_time_markers: Vec<ResolvedTimestampTimeMarker>,
    },
}

impl SigningContext {
    pub fn skip_v_id(&self) -> Option<bool> {
        match self {
            SigningContext::Message { skip_v_id, .. } | SigningContext::Read { skip_v_id, .. } => {
                *skip_v_id
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PillarApiRequestV2 {
    pub src_tx_hash: String,
    pub lz_message_id: LzMessageId,
    pub signing_context: SigningContext,
    pub message_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DebugInfo {
    pub dvn_hash_call_data: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PillarApiResponse {
    pub signatures: Vec<Signature>,
    pub payload: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<DebugInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResponseEnvelope<T> {
    pub status_code: u16,
    pub body: T,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BadRequestError(pub String);
/// Binds readiness to the receipt and packet log agreed on during resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvmSourceEvidence {
    pub block_hash: String,
    pub block_number: i64,
    pub status: String,
    pub packet_log_index: u64,
    pub transaction_hash: String,
    pub packet_log_address: String,
    pub packet_log_topics: Vec<String>,
    pub packet_log_data: String,
}

/// The block a READ time marker was validated against, agreed on by provider
/// quorum during readiness. The payload resolver issues every `eth_call` for
/// that marker against this exact hash (EIP-1898, `requireCanonical`), so a
/// reorg at the same height between validation and the read fails the request
/// instead of reading state the validator never looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadBlockPin {
    pub chain_name: String,
    pub block_number: u64,
    pub block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LzSentEvent {
    pub lz_message_id: LzMessageId,
    pub message: String,
    pub tx_hash: String,
    #[serde(skip)]
    pub source_evidence: Option<EvmSourceEvidence>,
    /// Filled from readiness before the hash builder runs; never caller input.
    #[serde(skip)]
    pub read_block_pins: Vec<ReadBlockPin>,
    #[serde(flatten)]
    pub extra: IndexMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HashCallDataResult {
    pub hash_call_data: String,
    pub details: Value,
}

#[async_trait]
pub trait SentEventResolver: Send + Sync + 'static {
    async fn get_lz_sent_event(
        &self,
        src_tx_hash: &str,
        lz_message_id: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError>;

    /// Upstream's `lzSdk.getLZSentEvent(sentEvent)` on a ULNv2-sent event before it is
    /// rebuilt for a V3-family receive library (`hashCallDataBuilder/ulnV3.ts:54-61`);
    /// `None` is its "possible reorg" answer.
    async fn refresh_uln_v2_sent_event(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<Option<UlnV2RefreshedEvent>, AppCoreError> {
        Ok(Some(UlnV2RefreshedEvent {
            sent_event: sent_event.clone(),
            lz_receive_gas: None,
        }))
    }
}

/// A re-read ULNv2 send and the `dstGasLimit` its adapter params carry, which
/// `hydrateV1SentEventToV2` turns into the relayer `options`.
#[derive(Debug, Clone, PartialEq)]
pub struct UlnV2RefreshedEvent {
    pub sent_event: LzSentEvent,
    pub lz_receive_gas: Option<String>,
}

#[async_trait]
pub trait HashCallDataBuilder: Send + Sync + 'static {
    async fn build_dvn_hash_call_data(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<HashCallDataResult, AppCoreError>;
}

#[async_trait]
pub trait AppValidator: Send + Sync + 'static {
    async fn validate_message_hash(
        &self,
        request: &PillarApiRequestV2,
        sent_event: &LzSentEvent,
    ) -> Result<(), AppCoreError>;

    /// Returns the READ block identities readiness agreed on, empty for
    /// MESSAGE requests. The caller attaches them to the sent event so the
    /// read payload is fetched from the block that was validated.
    async fn validate_readiness(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<Vec<ReadBlockPin>, AppCoreError>;

    async fn validate_expiration(
        &self,
        dst_chain_name: &str,
        expiration: i64,
    ) -> Result<(), AppCoreError>;

    async fn validate_payload_signed(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: Option<&str>,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError>;

    async fn validate_extra_context(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError>;

    /// The ULN version of the library the destination receiver currently
    /// receives on, agreed by provider quorum. Asked only for V2 sends, before
    /// resolution and over the requested pathway, as upstream does.
    async fn uln_receive_version(
        &self,
        lz_message_id: &LzMessageId,
    ) -> Result<String, AppCoreError>;
}

#[async_trait]
pub trait SignerGetter: Send + Sync + 'static {
    async fn pillar_sign(
        &self,
        dst_chain_name: &str,
        wallet_name: &str,
        data_hex: &str,
    ) -> Result<Signature, AppCoreError>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignStageStatus {
    Success,
    Failure,
}

impl SignStageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::Failure => "error",
        }
    }
}

#[async_trait]
pub trait SignStageObserver: Send + Sync + 'static {
    async fn observe_stage(
        &self,
        stage: &str,
        src_chain: &str,
        dst_chain: &str,
        status: SignStageStatus,
        duration_seconds: f64,
    );
}

pub struct NoopSignStageObserver;

#[async_trait]
impl SignStageObserver for NoopSignStageObserver {
    async fn observe_stage(
        &self,
        _stage: &str,
        _src_chain: &str,
        _dst_chain: &str,
        _status: SignStageStatus,
        _duration_seconds: f64,
    ) {
    }
}

impl Default for NoopSignStageObserver {
    fn default() -> Self {
        Self
    }
}

pub trait LegacyChainNameResolver: Send + Sync + 'static {
    fn get_chain_name(&self, chain_id: &str) -> Result<String, AppCoreError>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AppCoreError {
    #[error("{0}")]
    BadRequest(String),
    /// Domain refusals are separate so provider failures cannot become non-retryable HTTP errors.
    #[error("{0}")]
    UnresolvableCommand(String),
    #[error("{0}")]
    Internal(String),
    #[error("{0}")]
    Admission(execution::BudgetError),
}

#[derive(Clone)]
pub struct WalletRef {
    pub wallet_name: String,
}

/// The chains this process will sign for, as of now.
///
/// Asked per request rather than held as a list because the provider
/// configuration can be replaced while the process runs. A request checked
/// against the roster present at startup would be admitted for a chain the
/// operator has since removed, and then fail deeper with a less useful error -
/// and it would disagree with what `GET /available-chains` reports.
pub trait AvailableChains: Send + Sync + 'static {
    fn contains(&self, chain_name: &str) -> bool;

    /// The roster, for the error message naming what *is* available.
    fn names(&self) -> Vec<String>;
}

/// A roster that cannot change.
impl AvailableChains for Vec<String> {
    fn contains(&self, chain_name: &str) -> bool {
        self.iter().any(|available| available == chain_name)
    }

    fn names(&self) -> Vec<String> {
        self.clone()
    }
}

pub struct PillarApp {
    pub available_chain_names: Arc<dyn AvailableChains>,
    pub wallets_by_chain_name: HashMap<String, Vec<WalletRef>>,
    pub hash_call_data_builders: HashMap<String, Arc<dyn HashCallDataBuilder>>,
    pub sent_event_resolver: Arc<dyn SentEventResolver>,
    pub validator: Arc<dyn AppValidator>,
    pub signer_getter: Arc<dyn SignerGetter>,
    pub legacy_chain_name_resolver: Arc<dyn LegacyChainNameResolver>,
    pub stage_observer: Arc<dyn SignStageObserver>,
    pub debug_mode: bool,
}

/// Upstream's `App.signRequestV1` conversion (`app/utils/index.ts:7-14`,
/// `app/app.ts:383-389`), in its order: both eids are `parseInt`ed, then each chain
/// name resolved through `chainId.toString()`, then the nonce is
/// `parseInt(nonce.toString())`.
pub fn legacy_lz_message_id(
    resolver: &dyn LegacyChainNameResolver,
    legacy: &LegacyLzMessageId,
    uln_send_version: Value,
) -> Result<LzMessageId, AppCoreError> {
    let chain_name = |chain_id: Option<&Value>| match chain_id {
        Some(Value::Null) | None => Err(type_error_reading_to_string(chain_id)),
        Some(value) => resolver.get_chain_name(&js_string(value)?),
    };
    let src_eid = js_parse_int(&js_string_of(legacy.src_chain_id.as_ref())?);
    let dst_eid = js_parse_int(&js_string_of(legacy.dst_chain_id.as_ref())?);
    let src_chain_name = chain_name(legacy.src_chain_id.as_ref())?;
    let dst_chain_name = chain_name(legacy.dst_chain_id.as_ref())?;
    let mut extra = IndexMap::from([
        ("srcEid".to_string(), js_integer_value(src_eid)),
        ("dstEid".to_string(), js_integer_value(dst_eid)),
    ]);
    for (key, value) in [
        ("sender", &legacy.src_ua_address),
        ("receiver", &legacy.dst_ua_address),
    ] {
        if let Some(value) = value {
            extra.insert(key.to_string(), value.clone());
        }
    }
    let nonce = match &legacy.nonce {
        Some(Value::Object(map)) if map.contains_key("toString") => {
            return Err(AppCoreError::Internal(
                "requestInput.lzMessageId.nonce.toString is not a function".to_string(),
            ))
        }
        Some(value) if !value.is_null() => js_parse_int(&js_string(value)?),
        missing => return Err(type_error_reading_to_string(missing.as_ref())),
    };
    // A nonce JavaScript keeps as NaN, negative or past 2^64 cannot reach the typed
    // resolver; upstream carries it on to a failed packet match.
    if !(0.0..18_446_744_073_709_551_616.0).contains(&nonce) {
        return Err(AppCoreError::BadRequest(format!(
            "lzMessageId.nonce {} is not a uint64",
            js_number_f64(nonce)
        )));
    }
    Ok(LzMessageId {
        pathway_id: PathwayId {
            src_chain_name,
            dst_chain_name,
            extra,
        },
        nonce: nonce as u64,
        uln_send_version,
    })
}

impl PillarApp {
    pub async fn sign_request_v1(
        &self,
        request_input: PillarApiRequestV1,
    ) -> Result<PillarApiResponse, AppCoreError> {
        let lz_message_id = legacy_lz_message_id(
            self.legacy_chain_name_resolver.as_ref(),
            &request_input.lz_message_id,
            request_input.uln_version.clone(),
        )?;

        // Upstream builds this pathway with `convertLegacyMessageIdToPathwayId`, whose
        // key order (`app/utils/index.ts:7-14`) is what its error bodies stringify.
        let v2_order = pathway_json(&lz_message_id.pathway_id);
        let v1_order = legacy_pathway_json(&lz_message_id.pathway_id);
        self.sign_request_v2(PillarApiRequestV2 {
            src_tx_hash: request_input.src_tx_hash,
            lz_message_id,
            message_hash: request_input.message_hash,
            signing_context: SigningContext::Message {
                expiration: request_input.expiration,
                skip_v_id: request_input.skip_v_id,
                dvn_address: request_input.dvn_address,
                block_confirmation: request_input.block_confirmation,
            },
        })
        .await
        .map_err(|error| match error {
            AppCoreError::BadRequest(message) => {
                AppCoreError::BadRequest(message.replace(&v2_order, &v1_order))
            }
            AppCoreError::UnresolvableCommand(message) => {
                AppCoreError::UnresolvableCommand(message.replace(&v2_order, &v1_order))
            }
            AppCoreError::Internal(message) => {
                AppCoreError::Internal(message.replace(&v2_order, &v1_order))
            }
            other => other,
        })
    }

    pub async fn sign_request_v2(
        &self,
        request: PillarApiRequestV2,
    ) -> Result<PillarApiResponse, AppCoreError> {
        let src = &request.lz_message_id.pathway_id.src_chain_name;
        let dst = &request.lz_message_id.pathway_id.dst_chain_name;
        self.check_chain_name_availability(src)?;
        self.check_chain_name_availability(dst)?;
        let Some(mut context) = execution::current().filter(|ctx| ctx.resources.is_some()) else {
            return self.sign_request_v2_inner(request).await;
        };
        let resources = context
            .resources
            .as_ref()
            .expect("filtered execution context")
            .clone();
        context.source_chain = Some(Arc::from(src.as_str()));
        let mut permit = resources
            .signing
            .acquire(src)
            .await
            .map_err(AppCoreError::Admission)?;
        let result = context.scope(self.sign_request_v2_inner(request)).await;
        permit.finish(if result.is_ok() {
            execution::Outcome::Success
        } else {
            execution::Outcome::Error
        });
        result
    }

    async fn sign_request_v2_inner(
        &self,
        request: PillarApiRequestV2,
    ) -> Result<PillarApiResponse, AppCoreError> {
        let workflow_started_at = Instant::now();
        let src_chain_name = &request.lz_message_id.pathway_id.src_chain_name;
        let dst_chain_name = &request.lz_message_id.pathway_id.dst_chain_name;
        let nonce = request.lz_message_id.nonce;
        let uln_send_version = request
            .lz_message_id
            .uln_send_version
            .as_str()
            .filter(|version| ULN_SEND_VERSIONS.contains(version))
            .unwrap_or("unknown");
        // Roster validation keeps caller-controlled chain names out of logs.
        self.check_chain_name_availability(src_chain_name)?;
        self.check_chain_name_availability(dst_chain_name)?;
        tracing::info!(
            src_chain = %src_chain_name,
            dst_chain = %dst_chain_name,
            nonce,
            uln_send_version,
            "sign workflow started"
        );

        if request.lz_message_id.uln_send_version == "ReadV1002"
            && !matches!(request.signing_context, SigningContext::Read { .. })
        {
            return Err(AppCoreError::BadRequest(format!(
                "Invalid protocol type for ReadV1002 on pathway {}",
                pathway_json(&request.lz_message_id.pathway_id)
            )));
        }

        if let SigningContext::Message {
            block_confirmation, ..
        } = &request.signing_context
        {
            if *block_confirmation < 0 {
                return Err(AppCoreError::BadRequest(
                    "blockConfirmation cannot be negative".to_string(),
                ));
            }
        }

        // Only a V2 send consults the receiver's library, before resolution and
        // over the requested pathway; a V3-family library takes its own builder
        // and every other answer keeps V2's (TS 1.2.66: `app.ts:254-279`).
        let resolver_started_at = Instant::now();
        let routed_version = if request.lz_message_id.uln_send_version == "V2" {
            match self
                .validator
                .uln_receive_version(&request.lz_message_id)
                .await
            {
                Ok(version) if version == "V301" || version == "V302" => Some(version),
                Ok(_) => None,
                Err(error) => {
                    self.stage_observer
                        .observe_stage(
                            "get_sent_event",
                            src_chain_name,
                            dst_chain_name,
                            SignStageStatus::Failure,
                            resolver_started_at.elapsed().as_secs_f64(),
                        )
                        .await;
                    return Err(error);
                }
            }
        } else {
            None
        };
        let builder = match &routed_version {
            Some(version) => self.hash_call_data_builders.get(version.as_str()),
            None => request
                .lz_message_id
                .uln_send_version
                .as_str()
                .and_then(|version| self.hash_call_data_builders.get(version)),
        }
        .ok_or_else(|| {
            let version = match &routed_version {
                Some(version) => version.clone(),
                None => js_string(&request.lz_message_id.uln_send_version)
                    .unwrap_or_else(|_| "undefined".to_string()),
            };
            AppCoreError::BadRequest(format!(
                "Unsupported hash call data builder version: {version}"
            ))
        })?;
        // `skipVId` is served only as a bounded Aptos ULN V2 oracle proposal; a V2 send whose
        // Aptos receiver migrated to a V3-family library would otherwise be signed without a vId.
        if request.signing_context.skip_v_id() == Some(true)
            && (routed_version.is_some()
                || request.lz_message_id.uln_send_version != "V2"
                || dst_chain_name != "aptos")
        {
            return Err(AppCoreError::BadRequest(
                "skipVId is not supported for v2 requests".to_string(),
            ));
        }

        // Protective, not upstream, so it sits where it changes no earlier answer:
        // the first sink of `srcTxHash` is this resolver, which splices it into
        // the path of an outbound GET on the operator's own node (Move transaction
        // fetch, TON trace fetch), where `..`, `?` or `#` would re-target that
        // request with the provider's API-key header attached.
        if !is_transaction_id_shaped(&request.src_tx_hash) {
            return Err(AppCoreError::BadRequest(
                SRC_TX_HASH_SHAPE_ERROR.to_string(),
            ));
        }

        let sent_event_result = async {
            let sent_event = self
                .sent_event_resolver
                .get_lz_sent_event(&request.src_tx_hash, &request.lz_message_id)
                .await
                .map_err(|error| {
                    map_sent_event_error(error, &request.src_tx_hash, &request.lz_message_id)
                })?;
            // The builder and vId follow the resolved destination, the wallets follow
            // the requested one; they must be the same chain.
            let resolved = &sent_event.lz_message_id.pathway_id.dst_chain_name;
            if resolved != dst_chain_name {
                return Err(AppCoreError::Internal(format!(
                    "resolved PacketSent destination {resolved} does not match requested destination {dst_chain_name}"
                )));
            }
            // V2 requests resolve as V2; routing rebuilds the event afterwards.
            let requested_version = request.lz_message_id.uln_send_version.as_str().unwrap_or_default();
            let resolved_version = sent_event.lz_message_id.uln_send_version.as_str().unwrap_or_default();
            if resolved_version != requested_version {
                return Err(AppCoreError::BadRequest(format!(
                    "resolved PacketSent ULN version {resolved_version} does not match requested ULN version {requested_version}"
                )));
            }
            // A V2 send verified on a V3-family library is signed over the
            // rebuilt V2 event (TS 1.2.66: `hashCallDataBuilder/ulnV3.ts:36-63`).
            if routed_version.is_some() {
                tracing::info!(
                    src_chain = %src_chain_name,
                    dst_chain = %dst_chain_name,
                    nonce,
                    receive_version = routed_version.as_deref().unwrap_or_default(),
                    "ULN V2-sent message routed to its V3 receive library"
                );
                let refreshed = self
                    .sent_event_resolver
                    .refresh_uln_v2_sent_event(&sent_event)
                    .await
                    .map_err(|error| {
                        map_sent_event_error(error, &request.src_tx_hash, &request.lz_message_id)
                    })?
                    .ok_or_else(|| {
                        AppCoreError::BadRequest(format!(
                            "Could not refresh V1 sent event for srcTxHash {} on pathway {} (possible reorg)",
                            request.src_tx_hash,
                            pathway_json(&request.lz_message_id.pathway_id)
                        ))
                    })?;
                return hydrate_uln_v2_sent_event(
                    &refreshed.sent_event,
                    refreshed.lz_receive_gas.as_deref(),
                );
            }
            Ok(sent_event)
        }
        .await;
        self.stage_observer
            .observe_stage(
                "get_sent_event",
                src_chain_name,
                dst_chain_name,
                if sent_event_result.is_ok() {
                    SignStageStatus::Success
                } else {
                    SignStageStatus::Failure
                },
                resolver_started_at.elapsed().as_secs_f64(),
            )
            .await;
        let mut sent_event = sent_event_result?;
        tracing::info!(
            src_chain = %src_chain_name,
            dst_chain = %dst_chain_name,
            nonce,
            tx_hash = %sent_event.tx_hash,
            duration_ms = resolver_started_at.elapsed().as_millis(),
            "sent event resolved"
        );
        let validation_started_at = Instant::now();
        let validation_result = async {
            // Upstream's message-hash check is synchronous inside the
            // `Promise.all` array, so a mismatch is thrown before any other
            // check is issued; the remaining checks race, and the first to
            // reject is the answer (TS 1.2.66: `app.ts:304-313,509-519`).
            // Extra-context runs only after everything else has passed.
            self.validator
                .validate_message_hash(&request, &sent_event)
                .await?;
            let (read_block_pins, (), ()) = tokio::try_join!(
                self.validator
                    .validate_readiness(&sent_event, &request.signing_context),
                self.validator
                    .validate_expiration(dst_chain_name, request.signing_context.expiration()),
                self.validator.validate_payload_signed(
                    &sent_event,
                    // Upstream gates the check on a truthy address (`app.ts:308-309`).
                    request
                        .signing_context
                        .dvn_address()
                        .filter(|address| !address.is_empty()),
                    dst_chain_name,
                ),
            )?;
            self.validator
                .validate_extra_context(&sent_event, &request.signing_context)
                .await?;
            Ok::<_, AppCoreError>(read_block_pins)
        }
        .await;
        self.stage_observer
            .observe_stage(
                "validate",
                src_chain_name,
                dst_chain_name,
                if validation_result.is_ok() {
                    SignStageStatus::Success
                } else {
                    SignStageStatus::Failure
                },
                validation_started_at.elapsed().as_secs_f64(),
            )
            .await;
        sent_event.read_block_pins = validation_result?;
        tracing::info!(
            src_chain = %src_chain_name,
            dst_chain = %dst_chain_name,
            nonce,
            duration_ms = validation_started_at.elapsed().as_millis(),
            "sign validation completed"
        );

        let hash_build_started_at = Instant::now();
        let build_result = builder
            .build_dvn_hash_call_data(&sent_event, &request.signing_context)
            .await;
        self.stage_observer
            .observe_stage(
                "build_hash_call_data",
                src_chain_name,
                dst_chain_name,
                if build_result.is_ok() {
                    SignStageStatus::Success
                } else {
                    SignStageStatus::Failure
                },
                hash_build_started_at.elapsed().as_secs_f64(),
            )
            .await;
        let HashCallDataResult {
            hash_call_data,
            details,
        } = build_result?;
        tracing::info!(
            src_chain = %src_chain_name,
            dst_chain = %dst_chain_name,
            nonce,
            uln_send_version,
            duration_ms = hash_build_started_at.elapsed().as_millis(),
            "sign hash call data built"
        );

        let sign_started_at = Instant::now();
        let intent = audit::prepare(&request, &sent_event, &hash_call_data)?;
        let sign_result = audit::scope_prepared(intent, async {
            let wallets = self
                .wallets_by_chain_name
                .get(dst_chain_name)
                .ok_or_else(|| {
                    AppCoreError::Internal(format!(
                        "No wallets configured for chain {dst_chain_name}"
                    ))
                })?;
            let hash_call_data_ref = &hash_call_data;
            let wallet_names = wallets
                .iter()
                .map(|wallet| wallet.wallet_name.clone())
                .collect::<Vec<_>>();
            stream::iter(wallet_names.into_iter().map(|wallet_name| async move {
                let wallet_sign_started_at = Instant::now();
                let signature = audit::sign_wallet(
                    &wallet_name,
                    self.signer_getter.pillar_sign(
                        dst_chain_name,
                        &wallet_name,
                        hash_call_data_ref,
                    ),
                )
                .await?;
                tracing::info!(
                    src_chain = %src_chain_name,
                    dst_chain = %dst_chain_name,
                    nonce,
                    wallet_name = %wallet_name,
                    duration_ms = wallet_sign_started_at.elapsed().as_millis(),
                    "wallet signed"
                );
                Ok::<Signature, AppCoreError>(signature)
            }))
            .buffered(MAX_CONCURRENT_WALLET_SIGNS)
            .try_collect::<Vec<_>>()
            .await
        })
        .await;
        self.stage_observer
            .observe_stage(
                "sign",
                src_chain_name,
                dst_chain_name,
                if sign_result.is_ok() {
                    SignStageStatus::Success
                } else {
                    SignStageStatus::Failure
                },
                sign_started_at.elapsed().as_secs_f64(),
            )
            .await;
        let signatures = sign_result?;

        let resolved_payload = details
            .pointer("/proof/resolvedPayload")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let request_payload = details
            .pointer("/proof/payload")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let payload = if sent_event.lz_message_id.uln_send_version.as_str() == Some("ReadV1002") {
            if resolved_payload.is_empty() {
                request_payload.to_string()
            } else {
                resolved_payload.to_string()
            }
        } else {
            details
                .pointer("/proof/resolvedPayload")
                .or_else(|| details.pointer("/proof/payload"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };

        let response = PillarApiResponse {
            signatures,
            payload,
            debug_info: self.debug_mode.then_some(DebugInfo {
                dvn_hash_call_data: hash_call_data,
                details,
            }),
        };
        tracing::info!(
            src_chain = %src_chain_name,
            dst_chain = %dst_chain_name,
            nonce,
            signatures = response.signatures.len(),
            duration_ms = workflow_started_at.elapsed().as_millis(),
            "sign workflow completed"
        );
        Ok(response)
    }

    /// Upstream's own text and class (`app.ts:554-562`): a plain `Error`, so a 500,
    /// and it says "dst chain" for the source too.
    fn check_chain_name_availability(&self, chain_name: &str) -> Result<(), AppCoreError> {
        if !self.available_chain_names.contains(chain_name) {
            return Err(AppCoreError::Internal(format!(
                "Unsupported dst chain {chain_name}. Available chains : {} ",
                self.available_chain_names.names().join(", ")
            )));
        }
        Ok(())
    }
}

impl SigningContext {
    pub fn expiration(&self) -> i64 {
        match self {
            SigningContext::Message { expiration, .. }
            | SigningContext::Read { expiration, .. } => *expiration,
        }
    }

    pub fn dvn_address(&self) -> Option<&str> {
        match self {
            SigningContext::Message { dvn_address, .. }
            | SigningContext::Read { dvn_address, .. } => dvn_address.as_deref(),
        }
    }
}

pub fn hash_sent_event_message_for_pillar(
    sent_event: &LzSentEvent,
) -> Result<String, AppCoreError> {
    if sent_event.message.is_empty() {
        return Ok(String::new());
    }
    let message = sent_event
        .message
        .strip_prefix("0x")
        .unwrap_or(&sent_event.message);
    let bytes = hex::decode(message).map_err(|error| AppCoreError::Internal(error.to_string()))?;
    let digest = Keccak256::digest(bytes);
    Ok(format!("0x{}", hex::encode(digest)))
}

pub fn validate_message_hash_for_pillar(
    request: &PillarApiRequestV2,
    sent_event: &LzSentEvent,
) -> Result<(), AppCoreError> {
    let message_hash = hash_sent_event_message_for_pillar(sent_event)?;
    if request.message_hash.to_lowercase() != message_hash.to_lowercase() {
        return Err(AppCoreError::BadRequest(format!(
            "Message hash mismatch, expected: {}, got: {}",
            request.message_hash, message_hash
        )));
    }
    Ok(())
}

/// `GUID.generate`: keccak256 of `nonce(u64) | srcEid(u32) | sender(bytes32) |
/// dstEid(u32) | receiver(bytes32)`, as `calculateGuid` in
/// `@layerzerolabs/lz-v2-utilities@3.0.168` computes it.
pub fn calculate_guid(
    nonce: u64,
    src_eid: u32,
    sender: &str,
    dst_eid: u32,
    receiver: &str,
) -> Result<String, AppCoreError> {
    let mut preimage = Vec::with_capacity(8 + 4 + 32 + 4 + 32);
    preimage.extend_from_slice(&nonce.to_be_bytes());
    preimage.extend_from_slice(&src_eid.to_be_bytes());
    preimage.extend_from_slice(&hex_address_to_bytes32(sender)?);
    preimage.extend_from_slice(&dst_eid.to_be_bytes());
    preimage.extend_from_slice(&hex_address_to_bytes32(receiver)?);
    Ok(format!("0x{}", hex::encode(Keccak256::digest(preimage))))
}

fn hex_address_to_bytes32(address: &str) -> Result<[u8; 32], AppCoreError> {
    let bytes = hex::decode(address.strip_prefix("0x").unwrap_or(address))
        .map_err(|error| AppCoreError::Internal(format!("address {address}: {error}")))?;
    if bytes.len() > 32 {
        return Err(AppCoreError::Internal(format!(
            "address {address} is longer than 32 bytes"
        )));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// Upstream's `hydrateV1SentEventToV2` (`lz-v2-sdk/src/utils/common/hydrateV1SentEvent.ts:36-88`):
/// the pathway, nonce and message are kept, the guid a V3 receive library hashes into
/// the payload is computed from them, and the relayer options carry the adapter
/// params' gas (default `200000`) with no native drop. Options never reach the DVN hash.
pub fn hydrate_uln_v2_sent_event(
    sent_event: &LzSentEvent,
    lz_receive_gas: Option<&str>,
) -> Result<LzSentEvent, AppCoreError> {
    if sent_event.lz_message_id.uln_send_version != "V2" {
        return Err(AppCoreError::Internal(format!(
            "only a ULN V2-sent event can be rebuilt for a V3 receive library, got {}",
            sent_event.lz_message_id.uln_send_version
        )));
    }
    // A guid here would mean the event did not come from a ULNv2 `Packet` log.
    if sent_event.extra.contains_key("guid") {
        return Err(AppCoreError::Internal(
            "a ULN V2-sent event must not already carry a guid".to_string(),
        ));
    }
    let pathway = &sent_event.lz_message_id.pathway_id.extra;
    let eid = |key: &str| {
        pathway
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|eid| u32::try_from(eid).ok())
            .ok_or_else(|| {
                AppCoreError::Internal(format!("lzMessageId.pathwayId.{key} is not a uint32"))
            })
    };
    let address = |key: &str| {
        pathway
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| AppCoreError::Internal(format!("Missing lzMessageId.pathwayId.{key}")))
    };
    let guid = calculate_guid(
        sent_event.lz_message_id.nonce,
        eid("srcEid")?,
        address("sender")?,
        eid("dstEid")?,
        address("receiver")?,
    )?;
    let mut hydrated = sent_event.clone();
    let payload = format!(
        "{guid}{}",
        sent_event
            .message
            .strip_prefix("0x")
            .unwrap_or(&sent_event.message)
    );
    hydrated.extra.insert("guid".to_string(), Value::from(guid));
    hydrated.extra.insert(
        "options".to_string(),
        serde_json::json!({
            "lzReceive": {"gas": lz_receive_gas.unwrap_or("200000"), "value": "0"},
            "ordered": true,
        }),
    );
    hydrated
        .extra
        .insert("payload".to_string(), Value::from(payload));
    if let Some(emitter) = sent_event.extra.get("packetEmitAddress").cloned() {
        hydrated.extra.insert("sendLibrary".to_string(), emitter);
    }
    Ok(hydrated)
}

pub fn validate_expiration_bounds(
    expiration: i64,
    current_timestamp: i64,
    maximum_expiration: i64,
    maximum_expiration_grace_period: i64,
) -> Result<(), AppCoreError> {
    let effective_expiration = expiration
        .checked_add(maximum_expiration_grace_period)
        .ok_or_else(|| {
            AppCoreError::BadRequest(format!(
                "expiration is outside supported range: expiration={expiration}"
            ))
        })?;
    if effective_expiration < current_timestamp {
        return Err(AppCoreError::BadRequest(format!(
            "{EXPIRED_TIMESTAMP_ERROR_PREFIX}: expiration={expiration}, currentTimestamp={current_timestamp}"
        )));
    }
    let max_allowed = current_timestamp
        .checked_add(maximum_expiration)
        .ok_or_else(|| {
            AppCoreError::Internal("Expiration validation range overflow".to_string())
        })?;
    if max_allowed < expiration {
        return Err(AppCoreError::BadRequest(format!(
            "expiration is too far in the future: expiration={expiration}, maxAllowed={max_allowed}"
        )));
    }
    Ok(())
}

fn map_sent_event_error(
    error: AppCoreError,
    src_tx_hash: &str,
    lz_message_id: &LzMessageId,
) -> AppCoreError {
    let message = error.to_string();
    let identity_mismatch = matches!(
        &error,
        AppCoreError::BadRequest(text) if text.contains(PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX)
    );
    // Upstream's NotFoundError is the quorum provider's null result, which this
    // workspace reports as `... not found for <hash>`; upstream's own plain
    // `Transaction not found` (Solana) is a 500 and must not match here.
    if message.contains("NotFoundError")
        || message.contains("Transaction receipt not found for ")
        || message.contains("Transaction not found for ")
    {
        AppCoreError::BadRequest(format!(
            "srcTxHash {src_tx_hash} not found on pathway {}",
            pathway_json(&lz_message_id.pathway_id)
        ))
    } else if message.contains("cannot find packet event")
        || message.contains("LZMessage not found")
        || message.contains("Packet does not match lzMessageId")
        || identity_mismatch
    {
        AppCoreError::BadRequest(format!(
            "cannot find packet event for srcTxHash {src_tx_hash} on pathway {}",
            pathway_json(&lz_message_id.pathway_id)
        ))
    } else {
        error
    }
}

pub fn pathway_json(pathway_id: &PathwayId) -> String {
    if let (Some(src_eid), Some(dst_eid), Some(sender), Some(receiver)) = (
        pathway_id.extra.get("srcEid"),
        pathway_id.extra.get("dstEid"),
        pathway_id.extra.get("sender"),
        pathway_id.extra.get("receiver"),
    ) {
        return format!(
            r#"{{"srcEid":{},"dstEid":{},"sender":{},"receiver":{},"srcChainName":{},"dstChainName":{}}}"#,
            js_json(src_eid),
            js_json(dst_eid),
            js_json(sender),
            js_json(receiver),
            serde_json::to_string(&pathway_id.src_chain_name).expect("src chain serializes"),
            serde_json::to_string(&pathway_id.dst_chain_name).expect("dst chain serializes")
        );
    }
    serde_json::to_string(pathway_id).expect("pathway serializes")
}

/// `JSON.stringify` of upstream's legacy pathway: its key order, and an absent
/// (`undefined`) sender or receiver left out.
fn legacy_pathway_json(pathway_id: &PathwayId) -> String {
    let field = |key: &str| js_json(pathway_id.extra.get(key).unwrap_or(&Value::Null));
    let mut members = vec![
        format!(r#""srcEid":{}"#, field("srcEid")),
        format!(r#""dstEid":{}"#, field("dstEid")),
        format!(
            r#""srcChainName":{}"#,
            serde_json::to_string(&pathway_id.src_chain_name).expect("src chain serializes")
        ),
        format!(
            r#""dstChainName":{}"#,
            serde_json::to_string(&pathway_id.dst_chain_name).expect("dst chain serializes")
        ),
    ];
    for key in ["sender", "receiver"] {
        if let Some(value) = pathway_id.extra.get(key) {
            members.push(format!(r#""{key}":{}"#, js_json(value)));
        }
    }
    format!("{{{}}}", members.join(","))
}

/// `JSON.stringify` for a value `JSON.parse` produced: numbers render as JavaScript
/// renders them, everything else as serde does (both escape the same way).
pub fn js_json(value: &Value) -> String {
    match value {
        Value::Number(number) => js_number(number),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(js_json).collect::<Vec<_>>().join(",")
        ),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(key, item)| format!(
                    "{}:{}",
                    serde_json::to_string(key).expect("key serializes"),
                    js_json(item)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
        other => serde_json::to_string(other).expect("JSON value serializes"),
    }
}

/// JavaScript's `String(number)` (ECMA-262 Number::toString) over the double that
/// `JSON.parse` would produce; Rust's `{:e}` yields the same shortest digits.
pub fn js_number(number: &serde_json::Number) -> String {
    js_number_f64(number.as_f64().unwrap_or_default())
}

pub fn js_number_f64(float: f64) -> String {
    if float.is_nan() {
        return "NaN".to_string();
    }
    if float.is_infinite() {
        return if float < 0.0 { "-Infinity" } else { "Infinity" }.to_string();
    }
    if float == 0.0 {
        return "0".to_string();
    }
    let sign = if float < 0.0 { "-" } else { "" };
    let scientific = format!("{:e}", float.abs());
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("LowerExp always has an exponent");
    let digits = mantissa.replace('.', "");
    let k = digits.len() as i32;
    let n = exponent
        .parse::<i32>()
        .expect("LowerExp exponent is an integer")
        + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let fraction = if k == 1 {
            String::new()
        } else {
            format!(".{}", &digits[1..])
        };
        let exponent_sign = if n - 1 < 0 { "-" } else { "+" };
        format!(
            "{}{fraction}e{exponent_sign}{}",
            &digits[..1],
            (n - 1).abs()
        )
    };
    format!("{sign}{body}")
}

/// `String(value)` for a value `JSON.parse` produced. An object whose own
/// `toString` shadows the inherited method with a non-function cannot be
/// rendered, exactly as there.
pub fn js_string(value: &Value) -> Result<String, AppCoreError> {
    Ok(match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => js_number(number),
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Null => Ok(String::new()),
                item => js_string(item),
            })
            .collect::<Result<Vec<_>, _>>()?
            .join(","),
        Value::Object(map) if map.contains_key("toString") => {
            return Err(AppCoreError::Internal(
                "Cannot convert object to primitive value".to_string(),
            ))
        }
        Value::Object(_) => "[object Object]".to_string(),
    })
}

/// `String(value)` where `None` is `undefined`.
fn js_string_of(value: Option<&Value>) -> Result<String, AppCoreError> {
    value.map_or(Ok("undefined".to_string()), js_string)
}

/// Node's TypeError for `value.toString()` on `null` or `undefined`.
fn type_error_reading_to_string(value: Option<&Value>) -> AppCoreError {
    let name = if value.is_some() { "null" } else { "undefined" };
    AppCoreError::Internal(format!(
        "Cannot read properties of {name} (reading 'toString')"
    ))
}

/// An integral double as the JSON integer `JSON.stringify` writes for it.
fn js_integer_value(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        Value::from(value as i64)
    } else {
        serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number)
    }
}

/// JavaScript's global `parseInt(text)` with no radix: leading whitespace, an
/// optional sign, `0x` for hex, then the longest run of digits; none is `NaN`.
pub fn js_parse_int(text: &str) -> f64 {
    let trimmed = text.trim_start_matches(|c: char| {
        matches!(
            c,
            '\u{9}'
                | '\u{a}'
                | '\u{b}'
                | '\u{c}'
                | '\u{d}'
                | ' '
                | '\u{a0}'
                | '\u{1680}'
                | '\u{2000}'
                ..='\u{200a}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
                    | '\u{feff}'
        )
    });
    let (negative, unsigned) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let (radix, body) = match unsigned.get(..2) {
        Some("0x" | "0X") => (16, &unsigned[2..]),
        _ => (10, unsigned),
    };
    let digits_len = body
        .bytes()
        .take_while(|byte| (*byte as char).is_digit(radix))
        .count();
    if digits_len == 0 {
        return f64::NAN;
    }
    let digits = &body[..digits_len];
    let magnitude = if radix == 10 {
        digits.parse::<f64>().unwrap_or(f64::NAN)
    } else {
        // One correctly rounded conversion, as V8 does: up to 32 hex digits fit a
        // u128 exactly; past that the leading 32 plus a sticky bit round the same.
        let significant = digits.trim_start_matches('0');
        let (head, tail) = significant.split_at(significant.len().min(32));
        let mut mantissa = u128::from_str_radix(head, 16).unwrap_or_default();
        if tail.bytes().any(|byte| byte != b'0') {
            mantissa |= 1;
        }
        (mantissa as f64) * 2f64.powi(4 * tail.len() as i32)
    };
    if negative {
        -magnitude
    } else {
        magnitude
    }
}

#[cfg(test)]
#[test]
fn pathway_echo_renders_numbers_like_json_stringify() {
    let pathway = PathwayId {
        src_chain_name: "ethereum".to_string(),
        dst_chain_name: "bsc".to_string(),
        extra: indexmap::IndexMap::from([
            ("srcEid".to_string(), serde_json::json!(1e21)),
            (
                "dstEid".to_string(),
                serde_json::json!(1_152_921_504_606_846_976_u64),
            ),
            ("sender".to_string(), serde_json::json!("0xs")),
            ("receiver".to_string(), serde_json::json!(0.000001)),
        ]),
    };
    assert_eq!(
        pathway_json(&pathway),
        r#"{"srcEid":1e+21,"dstEid":1152921504606847000,"sender":"0xs","receiver":0.000001,"srcChainName":"ethereum","dstChainName":"bsc"}"#
    );
}

pub const SRC_TX_HASH_SHAPE_ERROR: &str =
    "srcTxHash: expected 1-128 characters of [0-9a-zA-Z_-] with an optional 0x prefix";

/// Transaction ids across the supported families are hex (EVM, Move, TON),
/// base58 (Solana) or base64url (TON trace ids): never a path separator, dot,
/// query mark or fragment mark.
pub fn is_transaction_id_shaped(value: &str) -> bool {
    let body = value.strip_prefix("0x").unwrap_or(value);
    !body.is_empty()
        && body.len() <= 128
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::sync::Mutex;

    type RecordedStage = (String, String, String, String);

    struct RecordingObserver {
        events: Arc<Mutex<Vec<RecordedStage>>>,
    }

    #[async_trait]
    impl SignStageObserver for RecordingObserver {
        async fn observe_stage(
            &self,
            stage: &str,
            src_chain: &str,
            dst_chain: &str,
            status: SignStageStatus,
            _duration_seconds: f64,
        ) {
            self.events.lock().await.push((
                stage.to_string(),
                src_chain.to_string(),
                dst_chain.to_string(),
                status.as_str().to_string(),
            ));
        }
    }

    struct FixedResolver;

    #[async_trait]
    impl SentEventResolver for FixedResolver {
        async fn get_lz_sent_event(
            &self,
            src_tx_hash: &str,
            lz_message_id: &LzMessageId,
        ) -> Result<LzSentEvent, AppCoreError> {
            Ok(LzSentEvent {
                lz_message_id: lz_message_id.clone(),
                message: "0xabc".to_string(),
                tx_hash: src_tx_hash.to_string(),
                source_evidence: None,
                read_block_pins: Vec::new(),
                extra: IndexMap::new(),
            })
        }
    }

    struct ReceiptNotFoundResolver;

    #[async_trait]
    impl SentEventResolver for ReceiptNotFoundResolver {
        async fn get_lz_sent_event(
            &self,
            src_tx_hash: &str,
            _lz_message_id: &LzMessageId,
        ) -> Result<LzSentEvent, AppCoreError> {
            Err(AppCoreError::Internal(format!(
                "Transaction receipt not found for {src_tx_hash}"
            )))
        }
    }

    struct TransactionNotFoundResolver;

    #[async_trait]
    impl SentEventResolver for TransactionNotFoundResolver {
        async fn get_lz_sent_event(
            &self,
            src_tx_hash: &str,
            _lz_message_id: &LzMessageId,
        ) -> Result<LzSentEvent, AppCoreError> {
            Err(AppCoreError::Internal(format!(
                "Transaction not found for {src_tx_hash}"
            )))
        }
    }

    struct FixedBuilder;

    #[async_trait]
    impl HashCallDataBuilder for FixedBuilder {
        async fn build_dvn_hash_call_data(
            &self,
            _sent_event: &LzSentEvent,
            _signing_context: &SigningContext,
        ) -> Result<HashCallDataResult, AppCoreError> {
            Ok(HashCallDataResult {
                hash_call_data: "0xfeed".to_string(),
                details: serde_json::json!({
                    "proof": {
                        "payload": "0xpayload",
                        "resolvedPayload": "0xresolved"
                    }
                }),
            })
        }
    }

    struct NoopValidator;

    #[async_trait]
    impl AppValidator for NoopValidator {
        async fn validate_message_hash(
            &self,
            _request: &PillarApiRequestV2,
            _sent_event: &LzSentEvent,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn validate_readiness(
            &self,
            _sent_event: &LzSentEvent,
            _signing_context: &SigningContext,
        ) -> Result<Vec<ReadBlockPin>, AppCoreError> {
            Ok(Vec::new())
        }

        async fn validate_expiration(
            &self,
            _dst_chain_name: &str,
            _expiration: i64,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn validate_payload_signed(
            &self,
            _sent_event: &LzSentEvent,
            _verifier_address: Option<&str>,
            _dst_chain_name: &str,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn validate_extra_context(
            &self,
            _sent_event: &LzSentEvent,
            _signing_context: &SigningContext,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn uln_receive_version(
            &self,
            _lz_message_id: &LzMessageId,
        ) -> Result<String, AppCoreError> {
            Err(AppCoreError::Internal(
                "no receive library in this test".to_string(),
            ))
        }
    }

    struct ReadinessFailsValidator;

    #[async_trait]
    impl AppValidator for ReadinessFailsValidator {
        async fn validate_message_hash(
            &self,
            _request: &PillarApiRequestV2,
            _sent_event: &LzSentEvent,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn validate_readiness(
            &self,
            _sent_event: &LzSentEvent,
            _signing_context: &SigningContext,
        ) -> Result<Vec<ReadBlockPin>, AppCoreError> {
            Err(AppCoreError::Internal(
                "No block timestamp quorum for chain solana: {Missing: 1}".to_string(),
            ))
        }

        async fn validate_expiration(
            &self,
            _dst_chain_name: &str,
            _expiration: i64,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn validate_payload_signed(
            &self,
            _sent_event: &LzSentEvent,
            _verifier_address: Option<&str>,
            _dst_chain_name: &str,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn validate_extra_context(
            &self,
            _sent_event: &LzSentEvent,
            _signing_context: &SigningContext,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn uln_receive_version(
            &self,
            _lz_message_id: &LzMessageId,
        ) -> Result<String, AppCoreError> {
            Err(AppCoreError::Internal(
                "no receive library in this test".to_string(),
            ))
        }
    }

    struct FixedSigner;

    #[async_trait]
    impl SignerGetter for FixedSigner {
        async fn pillar_sign(
            &self,
            dst_chain_name: &str,
            wallet_name: &str,
            data_hex: &str,
        ) -> Result<Signature, AppCoreError> {
            Ok(Signature {
                signature: format!("sig:{dst_chain_name}:{wallet_name}:{data_hex}"),
                address: "0xsigner".to_string(),
            })
        }
    }

    struct DelayedSigner {
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    #[async_trait]
    impl SignerGetter for DelayedSigner {
        async fn pillar_sign(
            &self,
            _dst_chain_name: &str,
            wallet_name: &str,
            _data_hex: &str,
        ) -> Result<Signature, AppCoreError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(120)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(Signature {
                signature: format!("sig:{wallet_name}"),
                address: format!("address:{wallet_name}"),
            })
        }
    }

    struct FixedChainResolver;

    impl LegacyChainNameResolver for FixedChainResolver {
        fn get_chain_name(&self, chain_id: &str) -> Result<String, AppCoreError> {
            match chain_id {
                "1" => Ok("ethereum".to_string()),
                "56" => Ok("bsc".to_string()),
                other => Err(AppCoreError::Internal(format!("Unknown chain id {other}"))),
            }
        }
    }

    fn app() -> PillarApp {
        PillarApp {
            available_chain_names: Arc::new(vec!["ethereum".to_string(), "bsc".to_string()]),
            wallets_by_chain_name: HashMap::from([(
                "bsc".to_string(),
                vec![WalletRef {
                    wallet_name: "wallet-1".to_string(),
                }],
            )]),
            hash_call_data_builders: HashMap::from([(
                "V302".to_string(),
                Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
            )]),
            sent_event_resolver: Arc::new(FixedResolver),
            validator: Arc::new(NoopValidator),
            signer_getter: Arc::new(FixedSigner),
            legacy_chain_name_resolver: Arc::new(FixedChainResolver),
            stage_observer: Arc::new(NoopSignStageObserver),
            debug_mode: true,
        }
    }

    /// Upstream indexes its builder map with whatever version arrives - V1 and
    /// V300 from the v2 route, anything at all from the v1 route - and answers a
    /// missing builder with `BadRequestError`, before any resolution, rendering
    /// the version with JavaScript's `${}` (TS 1.2.66: `app.ts:273-279`).
    #[tokio::test]
    async fn versions_without_a_builder_fail_like_upstreams_missing_builder() {
        for (version, rendered) in [
            (Value::from("V1"), "V1"),
            (Value::from("V300"), "V300"),
            (Value::from("V999"), "V999"),
            (Value::from(302), "302"),
            (Value::Null, "null"),
            (serde_json::json!({"a": 1}), "[object Object]"),
        ] {
            let mut request = request_v2("V302");
            request.lz_message_id.uln_send_version = version.clone();
            let resolved = Arc::new(AtomicUsize::new(0));
            let app = app_with_resolver(Arc::new(CountingResolver(resolved.clone())));

            let error = app.sign_request_v2(request).await.unwrap_err();

            assert_eq!(
                error,
                AppCoreError::BadRequest(format!(
                    "Unsupported hash call data builder version: {rendered}"
                )),
                "{version}"
            );
            assert_eq!(resolved.load(Ordering::SeqCst), 0);
        }
    }

    struct CountingResolver(Arc<AtomicUsize>);

    #[async_trait]
    impl SentEventResolver for CountingResolver {
        async fn get_lz_sent_event(
            &self,
            src_tx_hash: &str,
            lz_message_id: &LzMessageId,
        ) -> Result<LzSentEvent, AppCoreError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            FixedResolver
                .get_lz_sent_event(src_tx_hash, lz_message_id)
                .await
        }
    }

    fn app_with_resolver(sent_event_resolver: Arc<dyn SentEventResolver>) -> PillarApp {
        PillarApp {
            sent_event_resolver,
            ..app()
        }
    }

    /// srcTxHash is spliced into an outbound provider URL path, so path
    /// metacharacters must never reach a transport.
    #[test]
    fn transaction_id_shape_refuses_path_metacharacters() {
        for accepted in [
            "0xdeadbeef",
            "deadbeef",
            "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe",
            "abc-DEF_123",
            &"a".repeat(128),
        ] {
            assert!(
                is_transaction_id_shaped(accepted),
                "{accepted} must be accepted"
            );
        }
        for refused in [
            "",
            "0x",
            "../../admin",
            "abc/def",
            "abc?query=1",
            "abc#frag",
            "abc def",
            "abc%2fdef",
            "abc.def",
            "abc:def",
            "abc@def",
            &"a".repeat(129),
        ] {
            assert!(
                !is_transaction_id_shaped(refused),
                "{refused:?} must be refused"
            );
        }
    }

    /// Both routes reach the resolver through `sign_request_v2_inner`, so one gate
    /// in front of it covers v1 too; upstream's earlier, RPC-free errors still win.
    #[tokio::test]
    async fn a_path_shaped_src_tx_hash_never_reaches_the_resolver_on_either_route() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = app_with_resolver(Arc::new(CountingResolver(calls.clone())));
        let mut v2 = request_v2("V302");
        v2.src_tx_hash = "../../../admin/keys".to_string();
        assert_eq!(
            app.sign_request_v2(v2).await.unwrap_err(),
            AppCoreError::BadRequest(SRC_TX_HASH_SHAPE_ERROR.to_string())
        );
        let mut v1_style = request_v2("V1");
        v1_style.src_tx_hash = "../../../admin/keys".to_string();
        assert_eq!(
            app.sign_request_v2(v1_style).await.unwrap_err(),
            AppCoreError::BadRequest("Unsupported hash call data builder version: V1".to_string()),
            "upstream's builder lookup comes first"
        );
        let v1 = app
            .sign_request_v1(PillarApiRequestV1 {
                src_tx_hash: "../../../admin/keys".to_string(),
                lz_message_id: legacy_message_id(),
                block_confirmation: 1,
                expiration: 123,
                uln_version: Value::from("V302"),
                skip_v_id: None,
                dvn_address: None,
                message_hash: "0xhash".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(
            v1,
            AppCoreError::BadRequest(SRC_TX_HASH_SHAPE_ERROR.to_string())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    fn lz_message_id(uln_send_version: &str) -> LzMessageId {
        LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 7,
            uln_send_version: Value::from(uln_send_version),
        }
    }

    fn legacy_message_id() -> LegacyLzMessageId {
        LegacyLzMessageId {
            src_chain_id: Some(Value::from("1")),
            nonce: Some(Value::from(9)),
            dst_chain_id: Some(Value::from("56")),
            src_ua_address: Some(Value::from("0xsrc")),
            dst_ua_address: Some(Value::from("0xdst")),
        }
    }

    fn request_v2(uln_send_version: &str) -> PillarApiRequestV2 {
        PillarApiRequestV2 {
            src_tx_hash: "0xtx".to_string(),
            lz_message_id: lz_message_id(uln_send_version),
            signing_context: SigningContext::Message {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 1,
            },
            message_hash: "0xhash".to_string(),
        }
    }

    #[tokio::test]
    async fn sign_request_v2_observes_all_upstream_stages_and_labels() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut app = app();
        app.stage_observer = Arc::new(RecordingObserver {
            events: events.clone(),
        });

        app.sign_request_v2(request_v2("V302")).await.unwrap();

        let events = events.lock().await.clone();
        assert_eq!(
            events
                .iter()
                .map(|(stage, _, _, _)| stage.as_str())
                .collect::<Vec<_>>(),
            vec!["get_sent_event", "validate", "build_hash_call_data", "sign"]
        );
        assert!(events
            .iter()
            .all(|(_, src, dst, status)| { src == "ethereum" && dst == "bsc" && status == "ok" }));
    }

    #[tokio::test]
    async fn sign_request_v2_observes_failure_status_for_failed_stage() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut app = app_with_resolver(Arc::new(ReceiptNotFoundResolver));
        app.stage_observer = Arc::new(RecordingObserver {
            events: events.clone(),
        });

        app.sign_request_v2(request_v2("V302")).await.unwrap_err();

        let events = events.lock().await.clone();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            (
                "get_sent_event".to_string(),
                "ethereum".to_string(),
                "bsc".to_string(),
                "error".to_string()
            )
        );
    }

    #[tokio::test]
    async fn sign_request_v2_follows_ts_response_shape() {
        let response = app().sign_request_v2(request_v2("V302")).await.unwrap();
        assert_eq!(response.payload, "0xresolved");
        assert_eq!(response.signatures.len(), 1);
        assert_eq!(response.signatures[0].signature, "sig:bsc:wallet-1:0xfeed");
        assert_eq!(response.debug_info.unwrap().dvn_hash_call_data, "0xfeed");
    }

    #[tokio::test]
    async fn sign_request_v2_signs_wallets_concurrently_in_configured_order() {
        let signer = Arc::new(DelayedSigner {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let mut app = app();
        app.wallets_by_chain_name.insert(
            "bsc".to_string(),
            vec![
                WalletRef {
                    wallet_name: "wallet-1".to_string(),
                },
                WalletRef {
                    wallet_name: "wallet-2".to_string(),
                },
            ],
        );
        app.signer_getter = signer.clone();

        let started_at = Instant::now();
        let response = app.sign_request_v2(request_v2("V302")).await.unwrap();
        let elapsed = started_at.elapsed();

        assert!(
            elapsed < Duration::from_millis(220),
            "wallet signing was serialized: elapsed={elapsed:?}"
        );
        assert_eq!(signer.max_active.load(Ordering::SeqCst), 2);
        assert_eq!(
            response
                .signatures
                .iter()
                .map(|signature| signature.signature.as_str())
                .collect::<Vec<_>>(),
            vec!["sig:wallet-1", "sig:wallet-2"]
        );
    }

    struct DelayedValidator {
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    impl DelayedValidator {
        async fn observe(&self) {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(120)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl AppValidator for DelayedValidator {
        async fn validate_message_hash(
            &self,
            _request: &PillarApiRequestV2,
            _sent_event: &LzSentEvent,
        ) -> Result<(), AppCoreError> {
            self.observe().await;
            Ok(())
        }

        async fn validate_readiness(
            &self,
            _sent_event: &LzSentEvent,
            _signing_context: &SigningContext,
        ) -> Result<Vec<ReadBlockPin>, AppCoreError> {
            self.observe().await;
            Ok(Vec::new())
        }

        async fn validate_expiration(
            &self,
            _dst_chain_name: &str,
            _expiration: i64,
        ) -> Result<(), AppCoreError> {
            self.observe().await;
            Ok(())
        }

        async fn validate_payload_signed(
            &self,
            _sent_event: &LzSentEvent,
            _verifier_address: Option<&str>,
            _dst_chain_name: &str,
        ) -> Result<(), AppCoreError> {
            self.observe().await;
            Ok(())
        }

        async fn validate_extra_context(
            &self,
            _sent_event: &LzSentEvent,
            _signing_context: &SigningContext,
        ) -> Result<(), AppCoreError> {
            // Upstream holds extra-context back until the rest have passed, so
            // it must never overlap with them.
            self.observe().await;
            Ok(())
        }

        async fn uln_receive_version(
            &self,
            _lz_message_id: &LzMessageId,
        ) -> Result<String, AppCoreError> {
            Err(AppCoreError::Internal(
                "no receive library in this test".to_string(),
            ))
        }
    }

    /// Readiness, expiration and payload-signed each cost at least one provider
    /// round trip and upstream issues them together; the message hash is a
    /// synchronous check evaluated first (TS 1.2.66: `app.ts:304-310`).
    #[tokio::test]
    async fn sign_request_v2_runs_the_provider_validations_concurrently() {
        let validator = Arc::new(DelayedValidator {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let mut app = app();
        app.validator = validator.clone();

        let request = request_v2("V302");

        let started_at = Instant::now();
        app.sign_request_v2(request).await.unwrap();
        let elapsed = started_at.elapsed();

        // Message hash, then three concurrent checks, then extra-context: three
        // waits, not five. Serial execution would take at least 600ms.
        assert_eq!(
            validator.max_active.load(Ordering::SeqCst),
            3,
            "provider validations were serialized"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "validation did not overlap: elapsed={elapsed:?}"
        );
    }

    /// `Promise.all` answers with the first rejection in time, and the message
    /// hash, evaluated synchronously while the array is built, preempts every
    /// provider check (TS 1.2.66: `app.ts:304-310,509-519`).
    #[tokio::test]
    async fn sign_request_v2_reports_the_first_validation_to_fail() {
        struct Failing {
            message_hash_fails: bool,
            issued: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl AppValidator for Failing {
            async fn validate_message_hash(
                &self,
                _request: &PillarApiRequestV2,
                _sent_event: &LzSentEvent,
            ) -> Result<(), AppCoreError> {
                if self.message_hash_fails {
                    return Err(AppCoreError::BadRequest("message hash".to_string()));
                }
                Ok(())
            }

            async fn validate_readiness(
                &self,
                _sent_event: &LzSentEvent,
                _signing_context: &SigningContext,
            ) -> Result<Vec<ReadBlockPin>, AppCoreError> {
                self.issued.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                Err(AppCoreError::BadRequest("readiness".to_string()))
            }

            async fn validate_expiration(
                &self,
                _dst_chain_name: &str,
                _expiration: i64,
            ) -> Result<(), AppCoreError> {
                self.issued.fetch_add(1, Ordering::SeqCst);
                Err(AppCoreError::BadRequest("expiration".to_string()))
            }

            async fn validate_payload_signed(
                &self,
                _sent_event: &LzSentEvent,
                _verifier_address: Option<&str>,
                _dst_chain_name: &str,
            ) -> Result<(), AppCoreError> {
                self.issued.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                Err(AppCoreError::BadRequest("payload signed".to_string()))
            }

            async fn validate_extra_context(
                &self,
                _sent_event: &LzSentEvent,
                _signing_context: &SigningContext,
            ) -> Result<(), AppCoreError> {
                Ok(())
            }

            async fn uln_receive_version(
                &self,
                _lz_message_id: &LzMessageId,
            ) -> Result<String, AppCoreError> {
                Err(AppCoreError::Internal(
                    "no receive library in this test".to_string(),
                ))
            }
        }

        for (message_hash_fails, expected) in [(false, "expiration"), (true, "message hash")] {
            let counter = Arc::new(AtomicUsize::new(0));
            let mut app = app();
            app.validator = Arc::new(Failing {
                message_hash_fails,
                issued: counter.clone(),
            });
            let error = app.sign_request_v2(request_v2("V302")).await.unwrap_err();
            assert_eq!(error, AppCoreError::BadRequest(expected.to_string()));
            if message_hash_fails {
                assert_eq!(counter.load(Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test]
    async fn sign_request_v2_rejects_negative_block_confirmation() {
        let mut request = request_v2("V302");
        request.signing_context = SigningContext::Message {
            expiration: 123,
            skip_v_id: None,
            dvn_address: None,
            block_confirmation: -1,
        };
        let err = app().sign_request_v2(request).await.unwrap_err();
        assert_eq!(
            err,
            AppCoreError::BadRequest("blockConfirmation cannot be negative".to_string())
        );
    }

    #[tokio::test]
    async fn sign_request_v2_rejects_read_uln_with_message_context() {
        let err = app()
            .sign_request_v2(request_v2("ReadV1002"))
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .starts_with("Invalid protocol type for ReadV1002 on pathway"));
    }

    #[tokio::test]
    async fn sign_request_v2_maps_receipt_not_found_to_bad_request() {
        let err = app_with_resolver(Arc::new(ReceiptNotFoundResolver))
            .sign_request_v2(request_v2("V302"))
            .await
            .unwrap_err();
        assert!(matches!(err, AppCoreError::BadRequest(_)));
        assert!(err
            .to_string()
            .starts_with("srcTxHash 0xtx not found on pathway "));
        assert!(err.to_string().contains(r#""srcChainName":"ethereum""#));
        assert!(err.to_string().contains(r#""dstChainName":"bsc""#));
    }

    #[tokio::test]
    async fn sign_request_v2_maps_transaction_not_found_to_bad_request_like_upstream() {
        let err = app_with_resolver(Arc::new(TransactionNotFoundResolver))
            .sign_request_v2(request_v2("V302"))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            AppCoreError::BadRequest(
                r#"srcTxHash 0xtx not found on pathway {"srcChainName":"ethereum","dstChainName":"bsc"}"#
                    .to_string()
            )
        );
    }

    /// Upstream's Solana sdk throws a plain `Transaction not found` for a failed
    /// transaction; only its NotFoundError class is remapped, so this stays a 500.
    #[tokio::test]
    async fn plain_transaction_not_found_is_not_remapped() {
        struct FailedSolanaTransaction;

        #[async_trait]
        impl SentEventResolver for FailedSolanaTransaction {
            async fn get_lz_sent_event(
                &self,
                _src_tx_hash: &str,
                _lz_message_id: &LzMessageId,
            ) -> Result<LzSentEvent, AppCoreError> {
                Err(AppCoreError::Internal("Transaction not found".to_string()))
            }
        }

        let err = app_with_resolver(Arc::new(FailedSolanaTransaction))
            .sign_request_v2(request_v2("V302"))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            AppCoreError::Internal("Transaction not found".to_string())
        );
    }

    #[tokio::test]
    async fn transaction_not_found_pathway_uses_upstream_field_order_when_extra_fields_exist() {
        let mut request = request_v2("V302");
        request.lz_message_id.pathway_id.extra = IndexMap::from([
            ("srcEid".to_string(), Value::from(30_111_u64)),
            ("dstEid".to_string(), Value::from(30_184_u64)),
            (
                "sender".to_string(),
                Value::from("0x1111111111111111111111111111111111111111"),
            ),
            (
                "receiver".to_string(),
                Value::from("0x2222222222222222222222222222222222222222"),
            ),
        ]);
        let err = app_with_resolver(Arc::new(TransactionNotFoundResolver))
            .sign_request_v2(request)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            AppCoreError::BadRequest(
                r#"srcTxHash 0xtx not found on pathway {"srcEid":30111,"dstEid":30184,"sender":"0x1111111111111111111111111111111111111111","receiver":"0x2222222222222222222222222222222222222222","srcChainName":"ethereum","dstChainName":"bsc"}"#
                    .to_string()
            )
        );
    }

    /// Upstream checks src then dst with one message that always says "dst" and
    /// throws a plain Error, so the client sees a 500 (`app.ts:434-436,554-562`).
    #[tokio::test]
    async fn unavailable_chains_fail_with_upstreams_message_src_first() {
        for (src, dst, named) in [
            ("not-a-chain", "bsc", "not-a-chain"),
            ("ethereum", "not-a-chain", "not-a-chain"),
            ("src-x", "dst-y", "src-x"),
        ] {
            let mut request = request_v2("V302");
            request.lz_message_id.pathway_id.src_chain_name = src.to_string();
            request.lz_message_id.pathway_id.dst_chain_name = dst.to_string();
            assert_eq!(
                app().sign_request_v2(request).await.unwrap_err(),
                AppCoreError::Internal(format!(
                    "Unsupported dst chain {named}. Available chains : ethereum, bsc "
                ))
            );
        }
    }

    /// Upstream reaches the Solana builder's `!dvnPda` throw only after resolution
    /// and every validation, so a failing validation wins; with validation passing
    /// the builder's thrown string is a 500 (`app.ts:494-519`).
    #[tokio::test]
    async fn solana_destination_missing_dvn_address_is_reported_at_the_build_stage() {
        struct SolanaBuilder;

        #[async_trait]
        impl HashCallDataBuilder for SolanaBuilder {
            async fn build_dvn_hash_call_data(
                &self,
                _sent_event: &LzSentEvent,
                signing_context: &SigningContext,
            ) -> Result<HashCallDataResult, AppCoreError> {
                signing_context
                    .dvn_address()
                    .filter(|address| !address.is_empty())
                    .ok_or_else(|| {
                        AppCoreError::Internal(
                            "Solana: DVN Address is required for verify payload".to_string(),
                        )
                    })?;
                unreachable!("only the missing-address path is exercised")
            }
        }

        let solana_app = |validator: Arc<dyn AppValidator>| {
            let mut app = app();
            app.available_chain_names = Arc::new(vec![
                "ethereum".to_string(),
                "bsc".to_string(),
                "solana".to_string(),
            ]);
            app.hash_call_data_builders = HashMap::from([(
                "V302".to_string(),
                Arc::new(SolanaBuilder) as Arc<dyn HashCallDataBuilder>,
            )]);
            app.validator = validator;
            app
        };
        let mut request = request_v2("V302");
        request.lz_message_id.pathway_id.dst_chain_name = "solana".to_string();

        let err = solana_app(Arc::new(ReadinessFailsValidator))
            .sign_request_v2(request.clone())
            .await
            .unwrap_err();
        assert_ne!(
            err,
            AppCoreError::Internal(
                "Solana: DVN Address is required for verify payload".to_string()
            ),
            "a failing validation must be reported first"
        );

        assert_eq!(
            solana_app(Arc::new(NoopValidator))
                .sign_request_v2(request)
                .await
                .unwrap_err(),
            AppCoreError::Internal(
                "Solana: DVN Address is required for verify payload".to_string()
            )
        );
    }

    /// A resolver handing back a Solana event for a request that named another
    /// destination would route to the Solana builder and sign its digest with the
    /// requested chain's wallets. The production resolver never does this.
    #[tokio::test]
    async fn resolved_destination_must_match_the_request_before_any_digest_or_signature() {
        struct SolanaEventResolver;

        #[async_trait]
        impl SentEventResolver for SolanaEventResolver {
            async fn get_lz_sent_event(
                &self,
                src_tx_hash: &str,
                lz_message_id: &LzMessageId,
            ) -> Result<LzSentEvent, AppCoreError> {
                let mut lz_message_id = lz_message_id.clone();
                lz_message_id.pathway_id.dst_chain_name = "solana".to_string();
                FixedResolver
                    .get_lz_sent_event(src_tx_hash, &lz_message_id)
                    .await
            }
        }

        struct CountingBuilder(Arc<AtomicUsize>);

        #[async_trait]
        impl HashCallDataBuilder for CountingBuilder {
            async fn build_dvn_hash_call_data(
                &self,
                sent_event: &LzSentEvent,
                signing_context: &SigningContext,
            ) -> Result<HashCallDataResult, AppCoreError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                FixedBuilder
                    .build_dvn_hash_call_data(sent_event, signing_context)
                    .await
            }
        }

        let built = Arc::new(AtomicUsize::new(0));
        let mut app = app_with_resolver(Arc::new(SolanaEventResolver));
        app.hash_call_data_builders = HashMap::from([(
            "V302".to_string(),
            Arc::new(CountingBuilder(built.clone())) as Arc<dyn HashCallDataBuilder>,
        )]);
        let request = request_v2("V302");

        let err = app.sign_request_v2(request).await.unwrap_err();

        assert_eq!(
            err,
            AppCoreError::Internal(
                "resolved PacketSent destination solana does not match requested destination bsc"
                    .to_string()
            )
        );
        assert_eq!(built.load(Ordering::SeqCst), 0);
    }

    /// The v1 route's error bodies stringify upstream's legacy pathway, whose keys
    /// come in `convertLegacyMessageIdToPathwayId` order.
    #[tokio::test]
    async fn sign_request_v1_errors_use_the_legacy_pathway_key_order() {
        let err = app_with_resolver(Arc::new(TransactionNotFoundResolver))
            .sign_request_v1(PillarApiRequestV1 {
                src_tx_hash: "0xtx".to_string(),
                lz_message_id: legacy_message_id(),
                block_confirmation: 1,
                expiration: 123,
                uln_version: Value::from("V302"),
                skip_v_id: None,
                dvn_address: None,
                message_hash: "0xhash".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(
            err,
            AppCoreError::BadRequest(
                r#"srcTxHash 0xtx not found on pathway {"srcEid":1,"dstEid":56,"srcChainName":"ethereum","dstChainName":"bsc","sender":"0xsrc","receiver":"0xdst"}"#
                    .to_string()
            )
        );
    }

    #[tokio::test]
    async fn sign_request_v1_converts_legacy_message_to_v2() {
        let response = app()
            .sign_request_v1(PillarApiRequestV1 {
                src_tx_hash: "0xtx".to_string(),
                lz_message_id: legacy_message_id(),
                block_confirmation: 1,
                expiration: 123,
                uln_version: Value::from("V302"),
                skip_v_id: None,
                dvn_address: None,
                message_hash: "0xhash".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(response.payload, "0xresolved");
    }

    #[test]
    fn hashes_sent_event_message_like_typescript_client() {
        let sent_event = LzSentEvent {
            lz_message_id: lz_message_id("V302"),
            message: "0x68656c6c6f".to_string(),
            tx_hash: "0xtx".to_string(),
            source_evidence: None,
            read_block_pins: Vec::new(),
            extra: IndexMap::new(),
        };
        assert_eq!(
            hash_sent_event_message_for_pillar(&sent_event).unwrap(),
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn validate_message_hash_uses_case_insensitive_compare() {
        let sent_event = LzSentEvent {
            lz_message_id: lz_message_id("V302"),
            message: "0x68656c6c6f".to_string(),
            tx_hash: "0xtx".to_string(),
            source_evidence: None,
            read_block_pins: Vec::new(),
            extra: IndexMap::new(),
        };
        let mut request = request_v2("V302");
        request.message_hash =
            "0x1C8AFF950685C2ED4BC3174F3472287B56D9517B9C948127319A09A7A36DEAC8".to_string();
        validate_message_hash_for_pillar(&request, &sent_event).unwrap();
    }

    #[test]
    fn validate_message_hash_error_text_matches_ts() {
        let sent_event = LzSentEvent {
            lz_message_id: lz_message_id("V302"),
            message: "0x68656c6c6f".to_string(),
            tx_hash: "0xtx".to_string(),
            source_evidence: None,
            read_block_pins: Vec::new(),
            extra: IndexMap::new(),
        };
        let mut request = request_v2("V302");
        request.message_hash = "0xwrong".to_string();
        let err = validate_message_hash_for_pillar(&request, &sent_event).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Message hash mismatch, expected: 0xwrong, got: 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    /// Upstream 1.2.66's own `validateExpiration` over a clock fixed at `now`,
    /// with the bootstrap's one-week bound and 30-second grace
    /// (`scripts/gasolina-parity/emit-expiration-bound.ts`).
    #[test]
    fn validate_expiration_bounds_matches_gasolina() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/gasolina_parity/expiration_bound.json"
        ))
        .unwrap();
        let now = fixture["now"].as_i64().unwrap();
        let maximum = fixture["maximumExpiration"].as_i64().unwrap();
        let grace = fixture["maximumExpirationGracePeriod"].as_i64().unwrap();
        for case in fixture["results"].as_array().unwrap() {
            let expiration = case["expiration"].as_i64().unwrap();
            let outcome = validate_expiration_bounds(expiration, now, maximum, grace);
            match case["outcome"].as_str().unwrap() {
                "accepted" => assert_eq!(outcome, Ok(()), "{expiration}"),
                _ => assert_eq!(
                    outcome,
                    Err(AppCoreError::BadRequest(
                        case["message"].as_str().unwrap().to_string()
                    )),
                    "{expiration}"
                ),
            }
        }
    }

    #[test]
    fn validate_expiration_bounds_rejects_integer_overflow() {
        assert_eq!(
            validate_expiration_bounds(i64::MAX, 100, 604800, 30)
                .unwrap_err()
                .to_string(),
            format!(
                "expiration is outside supported range: expiration={}",
                i64::MAX
            )
        );
        assert_eq!(
            validate_expiration_bounds(i64::MAX - 30, i64::MAX - 1, 604800, 30)
                .unwrap_err()
                .to_string(),
            "Expiration validation range overflow"
        );
    }
}
