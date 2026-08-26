use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};

use crate::types::{UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder};

mod address;
mod builders;
mod cell;
mod cl_declare;
mod dict;
mod options;
mod payload;
mod payload_signed;
mod proxy;

pub use address::{
    address_to_be32 as ton_address_to_be32, derive_uln_addresses, DerivedAddresses,
    TonContractCodeCells, TonPathway,
};
pub use cell::{boc_from_base64, boc_to_base64 as ton_boc_to_base64};

/// A parsed TON contract storage cell, as handed to the pure decoders.
pub type TonStorageCell = ton_core::cell::TonCell;
pub use options::decode_ton_relayer_options;
pub use payload::{build_ton_dvn_verify, TonDvnVerifyOutput, TonDvnVerifyRequest};
pub use payload_signed::{
    committable_view_is_signed, dvn_attestation, ton_payload_signed_targets,
    uln_default_receive_config, DvnAttestation, TonPayloadSignedRequest, TonPayloadSignedTargets,
    LIVE_TON_PACKET_BOC,
};
pub use proxy::decode_proxy_admin_target;

/// TON destination builder for the router's V2 / read slots.
///
/// TON supports only EndpointV2 DVN verify, and that path requires an on-chain
/// (quorum-agreed) `dvnAddressImplementation` lookup, so the V3 build lives in
/// the runtime crate (`RuntimeTonUlnPayloadBuilder`) which owns transport and
/// quorum. This stateless type fills the V2 / read slots with the same
/// "unsupported" behavior as the Starknet/Stellar builders, and its V3 arm
/// reports that the runtime builder must be used.
#[derive(Debug, Clone)]
pub struct TonUlnPayloadBuilder;

#[async_trait]
impl UlnV2PayloadBuilder for TonUlnPayloadBuilder {
    async fn build_uln_v2_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _block_confirmation: i64,
        _expiration: i64,
        _v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "Method not implemented.".to_string(),
        ))
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for TonUlnPayloadBuilder {
    async fn build_uln_v3_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _block_confirmation: i64,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "TON DVN verify requires the runtime on-chain quorum builder".to_string(),
        ))
    }
}

#[async_trait]
impl UlnReadV1PayloadBuilder for TonUlnPayloadBuilder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _resolved_payload: String,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "FIXME TON-READ: Method not implemented.".to_string(),
        ))
    }
}
