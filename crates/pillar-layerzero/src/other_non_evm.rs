mod starknet;
mod stellar;
mod ton;

pub use starknet::StarknetUlnPayloadBuilder;
pub use stellar::{stellar_contract_id_from_strkey, StellarUlnPayloadBuilder};
pub use ton::{
    boc_from_base64, build_ton_dvn_verify, committable_view_is_signed, decode_proxy_admin_target,
    decode_ton_relayer_options, derive_uln_addresses, dvn_attestation, ton_address_to_be32,
    ton_boc_to_base64, ton_payload_signed_targets, uln_default_receive_config, DerivedAddresses,
    DvnAttestation, TonContractCodeCells, TonDvnVerifyOutput, TonDvnVerifyRequest, TonPathway,
    TonPayloadSignedRequest, TonPayloadSignedTargets, TonStorageCell, TonUlnPayloadBuilder,
    LIVE_TON_PACKET_BOC,
};

use sha3::{Digest, Keccak256};

fn keccak0x(data: &[u8]) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(data)))
}
