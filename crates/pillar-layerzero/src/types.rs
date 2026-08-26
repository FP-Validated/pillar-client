use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent, SigningContext};

pub const ULN_VERSION_V2: &str = "V2";
pub const ULN_VERSION_V301: &str = "V301";
pub const ULN_VERSION_V302: &str = "V302";
pub const ULN_VERSION_READ_V1002: &str = "ReadV1002";
pub const RECEIVE_ULN_301_ADDRESS: &str = "ReceiveUln301";
pub const RECEIVE_ULN_302_ADDRESS: &str = "ReceiveUln302";
pub const READ_LIB_1002_ADDRESS: &str = "ReadLib1002";
pub const ULN_V2_ADDRESS: &str = "UlnV2";
pub const APTOS_V1_ORACLE_ADDRESS: &str = "AptosV1Oracle";
pub const APTOS_V1_ULN_301_ADDRESS: &str = "AptosV1Uln301";
pub const APTOS_ULN_302_ADDRESS: &str = "AptosUln302";
pub const LEGACY_ULN_V2_PACKET_TOPIC: &str =
    "0xe9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82";
pub const ENDPOINT_V2_PACKET_SENT_TOPIC: &str =
    "0x1ab700d4ced0c005b164c0f789fd09fcbb0156d4c2041b8a3bfbcd961cd1567f";
pub const ULN_301_PACKET_SENT_TOPIC: &str =
    "0x3dc6f2ede34d1db05729bbb76e5efd17ec1bc83f98f665e7fba0596dca438b96";
pub(crate) const RECEIVE_ULN_302_VERIFY_SELECTOR: [u8; 4] = [0x02, 0x23, 0x53, 0x6e];
pub(crate) const READ_LIB_1002_VERIFY_SELECTOR: [u8; 4] = [0xab, 0x75, 0x0e, 0x75];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvmHashLookupResult {
    Message { submitted: bool, confirmations: u64 },
    Read { payload_hash: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmVerificationState {
    Verifying,
    Verifiable,
    Verified,
    NotInitializable,
    VerifiableButCapExceeded,
    Reorged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadTimeMarker {
    Timestamp { timestamp: u64 },
    BlockNumber { block_number: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResolvedTimeMarker {
    pub target_eid: u32,
    pub marker: ReadTimeMarker,
    pub block_confirmation: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmReadRequest {
    pub request: String,
    pub target_eid: u32,
    pub marker: ReadTimeMarker,
    pub block_confirmation: u16,
    pub to: String,
    pub calldata: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmReadComputeSetting {
    OnlyMap,
    OnlyReduce,
    MapReduce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmReadCompute {
    pub target_eid: u32,
    pub marker: ReadTimeMarker,
    pub block_confirmation: u16,
    pub to: String,
    pub setting: EvmReadComputeSetting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmReadCommand {
    pub global_version: u16,
    pub app_command_label: String,
    pub requests: Vec<EvmReadRequest>,
    pub compute: Option<EvmReadCompute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlnV2HashInfo {
    pub lookup_hash: String,
    pub block_data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmUlnV2AppConfig {
    pub inbound_proof_library_version: u64,
    pub inbound_block_confirmations: u64,
    pub relayer: String,
    pub outbound_proof_type: u64,
    pub outbound_block_confirmations: u64,
    pub oracle: String,
}

#[async_trait]
pub trait UlnV2PayloadBuilder: Send + Sync + 'static {
    async fn build_uln_v2_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError>;
}

#[async_trait]
pub trait UlnV3PayloadBuilder: Send + Sync + 'static {
    async fn build_uln_v3_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError>;
}

#[async_trait]
pub trait UlnReadV1PayloadBuilder: Send + Sync + 'static {
    async fn build_uln_read_v1_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        resolved_payload: String,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError>;
}

#[async_trait]
pub trait ReadPayloadResolver: Send + Sync + 'static {
    async fn resolve_payload(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<String, AppCoreError>;
}
