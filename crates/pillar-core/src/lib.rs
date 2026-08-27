use async_trait::async_trait;
use futures::{stream, StreamExt, TryStreamExt};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, sync::Arc, time::Instant};

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
    pub numeric_response: Option<String>,
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
const MAX_CONCURRENT_WALLET_SIGNS: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub signature: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LegacyLzMessageId {
    pub src_chain_id: String,
    pub nonce: u64,
    pub dst_chain_id: String,
    pub src_ua_address: String,
    pub dst_ua_address: String,
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

/// The protocol's closed set of send versions. Upstream validates the field
/// against a native enum at the HTTP boundary
/// (TS: `apps/gasolina/src/bootstrap.ts:130-157`), so anything outside this set
/// is a malformed request rather than an unsupported deployment. Shared with
/// `pillar-api` so the boundary and the core cannot drift apart.
pub const KNOWN_ULN_SEND_VERSIONS: [&str; 4] = ["V2", "V301", "V302", "ReadV1002"];

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LzSentEvent {
    pub lz_message_id: LzMessageId,
    pub message: String,
    pub tx_hash: String,
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

    async fn validate_readiness(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError>;

    async fn validate_expiration(
        &self,
        dst_chain_name: &str,
        expiration: i64,
    ) -> Result<(), AppCoreError>;

    async fn validate_payload_signed(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError>;

    async fn validate_extra_context(&self, sent_event: &LzSentEvent) -> Result<(), AppCoreError>;
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
    #[error("{0}")]
    Internal(String),
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

impl PillarApp {
    pub async fn sign_request_v1(
        &self,
        request_input: PillarApiRequestV1,
    ) -> Result<PillarApiResponse, AppCoreError> {
        let lz_message_id = LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: self
                    .legacy_chain_name_resolver
                    .get_chain_name(&request_input.lz_message_id.src_chain_id)?,
                dst_chain_name: self
                    .legacy_chain_name_resolver
                    .get_chain_name(&request_input.lz_message_id.dst_chain_id)?,
                extra: IndexMap::from([
                    (
                        "srcEid".to_string(),
                        Value::from(
                            request_input
                                .lz_message_id
                                .src_chain_id
                                .parse::<i64>()
                                .map_err(|error| AppCoreError::Internal(error.to_string()))?,
                        ),
                    ),
                    (
                        "dstEid".to_string(),
                        Value::from(
                            request_input
                                .lz_message_id
                                .dst_chain_id
                                .parse::<i64>()
                                .map_err(|error| AppCoreError::Internal(error.to_string()))?,
                        ),
                    ),
                    (
                        "sender".to_string(),
                        Value::from(request_input.lz_message_id.src_ua_address.clone()),
                    ),
                    (
                        "receiver".to_string(),
                        Value::from(request_input.lz_message_id.dst_ua_address.clone()),
                    ),
                ]),
            },
            nonce: request_input.lz_message_id.nonce,
            uln_send_version: request_input.uln_version.clone(),
        };

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
    }

    pub async fn sign_request_v2(
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
            .unwrap_or("unknown");
        tracing::info!(
            src_chain = %src_chain_name,
            dst_chain = %dst_chain_name,
            nonce,
            uln_send_version,
            message_hash = %request.message_hash,
            "sign workflow started"
        );
        self.check_chain_name_availability(src_chain_name)?;
        self.check_chain_name_availability(dst_chain_name)?;

        if request.lz_message_id.uln_send_version == "ReadV1002"
            && !matches!(request.signing_context, SigningContext::Read { .. })
        {
            return Err(AppCoreError::BadRequest(format!(
                "Invalid protocol type for ReadV1002 on pathway {}",
                serde_json::to_string(&request.lz_message_id.pathway_id)
                    .expect("pathway serializes")
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

        // The send version alone picks the builder, exactly as upstream does
        // (TS: `apps/gasolina/src/app/app.ts:466-467`,
        // `hashCallDataBuilders[lzMessageId.ulnSendVersion]`; there is no
        // `builderVersion` override anywhere in that file). The destination's
        // receive ULN version is deliberately not consulted here, and upstream
        // reads it in exactly two places, neither of which is builder
        // selection:
        //
        // 1. `app.ts:620-632` looks up the real receive version from the
        //    destination endpoint and passes it to `hasPayloadSigned` -
        //    validation only. Pillar mirrors that in
        //    `validation_payload_receive_library`.
        // 2. `sdks/gasolinaSdk/evm/index.ts:137-145` maps a chain id to a ULN
        //    version to pick the target contract *inside* the already-selected
        //    V3 builder (`:194-211`), mirrored by
        //    `evm_receive_version_from_dst_eid`.
        //
        // So a packet sent on V2 keeps a V2 builder even if the destination has
        // since migrated. Two separate reviews have read this comment and
        // concluded the opposite, so it is spelled out: consulting the receive
        // version here would sign call data the upstream service would not
        // produce.
        //
        // The version is caller input on both routes - `sign_request_v1` copies
        // `PillarApiRequestV1.uln_version` straight into `uln_send_version` -
        // so a malformed or unrecognised value is a client error, never an
        // internal fault. Only a missing always-installed builder indicates our
        // own wiring is broken.
        let builder_key = request
            .lz_message_id
            .uln_send_version
            .as_str()
            .ok_or_else(|| {
                AppCoreError::BadRequest(format!(
                    "Invalid ulnSendVersion: expected one of {}, got {}",
                    KNOWN_ULN_SEND_VERSIONS.join(", "),
                    request.lz_message_id.uln_send_version
                ))
            })?;
        let builder = self
            .hash_call_data_builders
            .get(builder_key)
            .ok_or_else(|| {
                if !KNOWN_ULN_SEND_VERSIONS.contains(&builder_key) {
                    AppCoreError::BadRequest(format!(
                        "Invalid ulnSendVersion: expected one of {}, got {builder_key}",
                        KNOWN_ULN_SEND_VERSIONS.join(", ")
                    ))
                } else if matches!(builder_key, "V2" | "V301") {
                    AppCoreError::BadRequest(format!("Unsupported ulnSendVersion {builder_key}"))
                } else {
                    AppCoreError::Internal(format!(
                        "No hashCallDataBuilder for ulnSendVersion {builder_key}"
                    ))
                }
            })?;

        let resolver_started_at = Instant::now();
        let sent_event_result = self
            .sent_event_resolver
            .get_lz_sent_event(&request.src_tx_hash, &request.lz_message_id)
            .await
            .map_err(|error| {
                map_sent_event_error(error, &request.src_tx_hash, &request.lz_message_id)
            });
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
        let sent_event = sent_event_result?;
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
            // Readiness, expiration and payload-signed each cost at least one
            // round of provider RPCs, so they run concurrently rather than
            // adding up. Upstream does the same
            // (TS: `apps/gasolina/src/app/app.ts:495-510`,
            // `Promise.all([...])`), and like upstream, extra-context runs only
            // after everything else has passed.
            //
            // The results are unwrapped in the original sequential order, so
            // which error a request sees is unchanged: a request that used to
            // fail on its message hash still reports the message hash. What
            // changes is that the later checks have already been issued by
            // then, which is exactly upstream's trade.
            let (message_hash, readiness, expiration, payload_signed) = tokio::join!(
                self.validator.validate_message_hash(&request, &sent_event),
                self.validator
                    .validate_readiness(&sent_event, &request.signing_context),
                self.validator
                    .validate_expiration(dst_chain_name, request.signing_context.expiration()),
                async {
                    match request.signing_context.dvn_address() {
                        Some(dvn_address) => {
                            self.validator
                                .validate_payload_signed(&sent_event, dvn_address, dst_chain_name)
                                .await
                        }
                        None => Ok(()),
                    }
                },
            );
            message_hash?;
            validate_destination_prerequisites(dst_chain_name, &request.signing_context)?;
            readiness?;
            expiration?;
            payload_signed?;
            self.validator.validate_extra_context(&sent_event).await
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
        validation_result?;
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
        let sign_result = async {
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
                let signature = self
                    .signer_getter
                    .pillar_sign(dst_chain_name, &wallet_name, hash_call_data_ref)
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
        }
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

        let payload = details
            .pointer("/proof/resolvedPayload")
            .or_else(|| details.pointer("/proof/payload"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

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
    if message.contains("NotFoundError")
        || message.contains("Transaction receipt not found")
        || message.contains("Transaction not found")
    {
        AppCoreError::BadRequest(format!(
            "srcTxHash {src_tx_hash} not found on pathway {}",
            pathway_json(&lz_message_id.pathway_id)
        ))
    } else if message.contains("cannot find packet event")
        || message.contains("LZMessage not found")
        || message.contains("Packet does not match lzMessageId")
    {
        AppCoreError::BadRequest(format!(
            "cannot find packet event for srcTxHash {src_tx_hash} on pathway {}",
            pathway_json(&lz_message_id.pathway_id)
        ))
    } else {
        error
    }
}

fn validate_destination_prerequisites(
    dst_chain_name: &str,
    signing_context: &SigningContext,
) -> Result<(), AppCoreError> {
    if dst_chain_name == "solana"
        && matches!(
            signing_context,
            SigningContext::Message {
                dvn_address: None,
                ..
            }
        )
    {
        return Err(AppCoreError::Internal(
            "Solana: DVN Address is required for verify payload".to_string(),
        ));
    }
    Ok(())
}

fn pathway_json(pathway_id: &PathwayId) -> String {
    if let (Some(src_eid), Some(dst_eid), Some(sender), Some(receiver)) = (
        pathway_id.extra.get("srcEid"),
        pathway_id.extra.get("dstEid"),
        pathway_id.extra.get("sender"),
        pathway_id.extra.get("receiver"),
    ) {
        return format!(
            r#"{{"srcEid":{},"dstEid":{},"sender":{},"receiver":{},"srcChainName":{},"dstChainName":{}}}"#,
            serde_json::to_string(src_eid).expect("pathway srcEid serializes"),
            serde_json::to_string(dst_eid).expect("pathway dstEid serializes"),
            serde_json::to_string(sender).expect("pathway sender serializes"),
            serde_json::to_string(receiver).expect("pathway receiver serializes"),
            serde_json::to_string(&pathway_id.src_chain_name).expect("src chain serializes"),
            serde_json::to_string(&pathway_id.dst_chain_name).expect("dst chain serializes")
        );
    }
    serde_json::to_string(pathway_id).expect("pathway serializes")
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
        ) -> Result<(), AppCoreError> {
            Ok(())
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
            _verifier_address: &str,
            _dst_chain_name: &str,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn validate_extra_context(
            &self,
            _sent_event: &LzSentEvent,
        ) -> Result<(), AppCoreError> {
            Ok(())
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
        ) -> Result<(), AppCoreError> {
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
            _verifier_address: &str,
            _dst_chain_name: &str,
        ) -> Result<(), AppCoreError> {
            Ok(())
        }

        async fn validate_extra_context(
            &self,
            _sent_event: &LzSentEvent,
        ) -> Result<(), AppCoreError> {
            Ok(())
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

    /// `PillarApiRequestV1.uln_version` is copied straight into
    /// `uln_send_version` (see `sign_request_v1`), so the v1 route can hand the
    /// core a non-string too. A caller's malformed version must never be
    /// reported as an internal fault, whichever route it arrived on.
    #[tokio::test]
    async fn rejects_non_string_uln_send_version_as_client_error() {
        let mut request = request_v2("V302");
        request.lz_message_id.uln_send_version = Value::from(302);

        let error = app().sign_request_v2(request).await.unwrap_err();

        assert!(
            matches!(error, AppCoreError::BadRequest(_)),
            "a malformed caller field must not be an internal fault: {error:?}"
        );
    }

    #[tokio::test]
    async fn rejects_unrecognised_uln_send_version_as_client_error() {
        let error = app().sign_request_v2(request_v2("V999")).await.unwrap_err();

        assert!(
            matches!(error, AppCoreError::BadRequest(_)),
            "an unrecognised version is caller input, not a wiring bug: {error:?}"
        );
    }

    fn app_with_resolver(sent_event_resolver: Arc<dyn SentEventResolver>) -> PillarApp {
        PillarApp {
            sent_event_resolver,
            ..app()
        }
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
        ) -> Result<(), AppCoreError> {
            self.observe().await;
            Ok(())
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
            _verifier_address: &str,
            _dst_chain_name: &str,
        ) -> Result<(), AppCoreError> {
            self.observe().await;
            Ok(())
        }

        async fn validate_extra_context(
            &self,
            _sent_event: &LzSentEvent,
        ) -> Result<(), AppCoreError> {
            // Upstream holds extra-context back until the rest have passed, so
            // it must never overlap with them.
            self.observe().await;
            Ok(())
        }
    }

    /// Each of these validations costs at least one provider round trip, so
    /// four of them running in sequence is four times the provider latency for
    /// every valid request. Upstream issues them together
    /// (`apps/gasolina/src/app/app.ts:495-510`).
    #[tokio::test]
    async fn sign_request_v2_runs_the_provider_validations_concurrently() {
        let validator = Arc::new(DelayedValidator {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        });
        let mut app = app();
        app.validator = validator.clone();

        // A dvn address is what brings the payload-signed check into play, so
        // without one only three of the four would run.
        let mut request = request_v2("V302");
        request.signing_context = SigningContext::Message {
            expiration: 123,
            skip_v_id: None,
            dvn_address: Some("0xdvn".to_string()),
            block_confirmation: 1,
        };

        let started_at = Instant::now();
        app.sign_request_v2(request).await.unwrap();
        let elapsed = started_at.elapsed();

        // Four concurrent checks plus extra-context afterwards: two waits, not
        // five. Serial execution would take at least 600ms.
        assert_eq!(
            validator.max_active.load(Ordering::SeqCst),
            4,
            "provider validations were serialized"
        );
        assert!(
            elapsed < Duration::from_millis(400),
            "validation did not overlap: elapsed={elapsed:?}"
        );
    }

    /// Concurrency must not change which error a caller sees: the checks are
    /// all issued, then reported in the original order.
    #[tokio::test]
    async fn sign_request_v2_reports_readiness_before_expiration() {
        struct BothFail;

        #[async_trait]
        impl AppValidator for BothFail {
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
            ) -> Result<(), AppCoreError> {
                Err(AppCoreError::BadRequest("readiness".to_string()))
            }

            async fn validate_expiration(
                &self,
                _dst_chain_name: &str,
                _expiration: i64,
            ) -> Result<(), AppCoreError> {
                Err(AppCoreError::BadRequest("expiration".to_string()))
            }

            async fn validate_payload_signed(
                &self,
                _sent_event: &LzSentEvent,
                _verifier_address: &str,
                _dst_chain_name: &str,
            ) -> Result<(), AppCoreError> {
                Err(AppCoreError::BadRequest("payload signed".to_string()))
            }

            async fn validate_extra_context(
                &self,
                _sent_event: &LzSentEvent,
            ) -> Result<(), AppCoreError> {
                Ok(())
            }
        }

        let mut app = app();
        app.validator = Arc::new(BothFail);

        let error = app.sign_request_v2(request_v2("V302")).await.unwrap_err();
        assert!(
            matches!(&error, AppCoreError::BadRequest(message) if message == "readiness"),
            "{error:?}"
        );
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

    #[tokio::test]
    async fn solana_destination_missing_dvn_address_matches_upstream_before_readiness() {
        let mut app = app();
        app.available_chain_names = Arc::new(vec![
            "ethereum".to_string(),
            "bsc".to_string(),
            "solana".to_string(),
        ]);
        app.wallets_by_chain_name.insert(
            "solana".to_string(),
            vec![WalletRef {
                wallet_name: "wallet-1".to_string(),
            }],
        );
        app.validator = Arc::new(ReadinessFailsValidator);

        let mut request = request_v2("V302");
        request.lz_message_id.pathway_id.dst_chain_name = "solana".to_string();

        let err = app.sign_request_v2(request).await.unwrap_err();
        assert_eq!(
            err,
            AppCoreError::Internal(
                "Solana: DVN Address is required for verify payload".to_string()
            )
        );
    }

    #[tokio::test]
    async fn sign_request_v1_converts_legacy_message_to_v2() {
        let response = app()
            .sign_request_v1(PillarApiRequestV1 {
                src_tx_hash: "0xtx".to_string(),
                lz_message_id: LegacyLzMessageId {
                    src_chain_id: "1".to_string(),
                    nonce: 9,
                    dst_chain_id: "56".to_string(),
                    src_ua_address: "0xsrc".to_string(),
                    dst_ua_address: "0xdst".to_string(),
                },
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

    #[test]
    fn validate_expiration_bounds_matches_ts_error_texts() {
        let expired = validate_expiration_bounds(100, 131, 604800, 30).unwrap_err();
        assert_eq!(
            expired.to_string(),
            "Expiration has already passed: expiration=100, currentTimestamp=131"
        );

        let too_far = validate_expiration_bounds(605000, 100, 604800, 30).unwrap_err();
        assert_eq!(
            too_far.to_string(),
            "expiration is too far in the future: expiration=605000, maxAllowed=604900"
        );

        validate_expiration_bounds(130, 160, 604800, 30).unwrap();
        validate_expiration_bounds(604900, 100, 604800, 30).unwrap();
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
