//! End-to-end assembly of the EVM -> TON DVN verify payload, ported from
//! the upstream TypeScript `buildULNV3VerifyPayload` +
//! `lz-ton-contracts` `buildULNCallData` / `buildDvnVerifyCallData`.
//!
//! Pure: the on-chain-resolved `target` (dvnAddressImplementation) is supplied
//! by the caller (the runtime quorum wrapper). Everything else is deterministic.

use super::address::{address_to_be32, derive_uln_addresses, TonContractCodeCells, TonPathway};
use super::builders::{
    build_execute_params, build_lz_packet, build_lz_path, build_uln_call_data, OP_ULN_VERIFY,
};
use super::cell::{boc_to_hex, repr_hash_hex};
use pillar_core::AppCoreError;

/// Inputs for one EVM -> TON DVN verify signature.
pub struct TonDvnVerifyRequest<'a> {
    pub src_eid: u32,
    pub dst_eid: u32,
    /// EVM sender (source OApp) address string.
    pub sender: &'a str,
    /// TON receiver (destination OApp) address string.
    pub receiver: &'a str,
    /// Message guid (`0x`-prefixed, 32 bytes).
    pub guid: &'a str,
    pub nonce: u64,
    /// Message payload hex (`0x`-prefixed).
    pub message: &'a str,
    pub block_confirmation: i64,
    pub expiration: i64,
    /// UlnManager deployment address (per environment).
    pub uln_manager_address: &'a str,
    /// dvnAddressImplementation, resolved on-chain (quorum) by the caller.
    pub target: &'a str,
    pub code: &'a TonContractCodeCells,
}

/// Byte-exact outputs of the DVN verify payload build.
pub struct TonDvnVerifyOutput {
    /// Signed hash: `0x` + representation hash of the `md::ExecuteParams` cell.
    pub hash_call_data: String,
    /// `md::ExecuteParams` BOC hex.
    pub dvn_call_data_boc: String,
    /// `md::MdAddress` (uln call data) BOC hex.
    pub uln_call_data_boc: String,
    /// `addressToHex(uln.address)`.
    pub target_contract: String,
    /// `lz::Packet` representation hash (no `0x`).
    pub packet_hash: String,
}

pub(super) fn hex_to_be32(hex: &str) -> Result<[u8; 32], AppCoreError> {
    let body = hex.trim_start_matches("0x");
    let bytes = hex::decode(body)
        .map_err(|e| AppCoreError::Internal(format!("TON hex32 decode {hex}: {e}")))?;
    if bytes.len() > 32 {
        return Err(AppCoreError::Internal(format!(
            "value exceeds 32 bytes: {hex}"
        )));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// Assemble the DVN verify payload for an EVM -> TON pathway.
pub fn build_ton_dvn_verify(
    req: &TonDvnVerifyRequest<'_>,
) -> Result<TonDvnVerifyOutput, AppCoreError> {
    let pathway = TonPathway {
        src_eid: req.src_eid,
        dst_eid: req.dst_eid,
        sender: req.sender,
        receiver: req.receiver,
        uln_manager_address: req.uln_manager_address,
    };
    let derived = derive_uln_addresses(&pathway, req.code)?;
    let uln_addr_be: [u8; 32] = derived
        .uln
        .hash
        .as_slice()
        .try_into()
        .expect("32-byte hash");
    let uln_conn_addr_be: [u8; 32] = derived
        .uln_connection
        .hash
        .as_slice()
        .try_into()
        .expect("32-byte hash");

    // lz::Packet uses the original (unswapped) pathway.
    let sender_be = address_to_be32(req.sender)?;
    let receiver_be = address_to_be32(req.receiver)?;
    let path = build_lz_path(req.src_eid, &sender_be, req.dst_eid, &receiver_be)?;
    let packet = build_lz_packet(path, req.message, req.nonce, &hex_to_be32(req.guid)?)?;
    let packet_hash = repr_hash_hex(&packet)?;

    let uln_call_data = build_uln_call_data(
        &uln_conn_addr_be,
        req.nonce,
        req.block_confirmation,
        &hex_to_be32(&packet_hash)?,
    )?;
    let uln_call_data_boc = boc_to_hex(&uln_call_data)?;

    let target_be = address_to_be32(req.target)?;
    let dvn_call_data = build_execute_params(
        &target_be,
        uln_call_data,
        req.expiration,
        OP_ULN_VERIFY,
        &uln_addr_be,
    )?;

    Ok(TonDvnVerifyOutput {
        hash_call_data: format!("0x{}", repr_hash_hex(&dvn_call_data)?),
        dvn_call_data_boc: boc_to_hex(&dvn_call_data)?,
        uln_call_data_boc,
        target_contract: format!("0x{}", hex::encode(uln_addr_be)),
        packet_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_config::ton_code_cell;

    fn code() -> TonContractCodeCells {
        TonContractCodeCells {
            uln: ton_code_cell("Uln").unwrap().to_string(),
            uln_connection: ton_code_cell("UlnConnection").unwrap().to_string(),
        }
    }

    #[test]
    fn build_matches_oracle_vec_a() {
        let code = code();
        let out = build_ton_dvn_verify(&TonDvnVerifyRequest {
            src_eid: 30101,
            dst_eid: 30343,
            sender: "0x1111111111111111111111111111111111111111",
            receiver: "0:2222222222222222222222222222222222222222222222222222222222222222",
            guid: "0x3333333333333333333333333333333333333333333333333333333333333333",
            nonce: 42,
            message: "0xcafebabe",
            block_confirmation: 15,
            expiration: 1234567890,
            uln_manager_address: "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH",
            target: "0:4444444444444444444444444444444444444444444444444444444444444444",
            code: &code,
        })
        .unwrap();
        assert_eq!(
            out.packet_hash,
            "89d2af9622b30f26deeb8af84a30559d55a0ac6e7cdf77ca6e1b48f125062469"
        );
        assert_eq!(
            out.hash_call_data,
            "0x5e098fe4a9092360a48d98507c75e2e4808170d27ef37fe380d95c8fdddd07b6"
        );
        assert_eq!(out.uln_call_data_boc, "b5ee9c724101030100dc000197000000004d644164647293ff2057bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd806e41da72dfea3810968100343c9e6885a828d334d76475f1d1a12677fa48fe01016700556c6e566572696679615ee4ffcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000aa0200a700000000417474657374815ed897bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe274abe588acc3c9b7bae2be128c156755682b1b9f37ddf29b86d23c4941891a4000000000000003eee35d5a2");
        assert_eq!(out.dvn_call_data_boc, "b5ee9c72410204010001570001ef65786563506172616d73815ee4ffc625ed4a7b82befffffffffffffffffffffffffffffffffffffffffffffd11111111111111111111111111111111111111111111111111111111111111100000000126580b4a652abd385d1313776775216ef61bb53bd51b863623f633635f429e54ebd5baebb7daaf72010197000000004d644164647293ff2057bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd806e41da72dfea3810968100343c9e6885a828d334d76475f1d1a12677fa48fe02016700556c6e566572696679615ee4ffcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000aa0300a700000000417474657374815ed897bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe274abe588acc3c9b7bae2be128c156755682b1b9f37ddf29b86d23c4941891a4000000000000003e7d0b6586");
        assert_eq!(
            out.target_contract,
            "0x1744c4ddd9dd485bbd86ed4ef546e18d88fd8cd8d7d0a7953af56ebaedf6abdc"
        );
    }

    #[test]
    fn build_matches_oracle_vec_b_empty_message() {
        let code = code();
        let out = build_ton_dvn_verify(&TonDvnVerifyRequest {
            src_eid: 30101,
            dst_eid: 30343,
            sender: "0x00000000000000000000000000000000deadbeef",
            receiver: "0:2222222222222222222222222222222222222222222222222222222222222222",
            guid: "0x1111111111111111111111111111111111111111111111111111111111111111",
            nonce: 1,
            message: "0x",
            block_confirmation: 1,
            expiration: 2000000000,
            uln_manager_address: "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH",
            target: "0:4444444444444444444444444444444444444444444444444444444444444444",
            code: &code,
        })
        .unwrap();
        assert_eq!(
            out.packet_hash,
            "f9b4a8491dd87066fd8e5b12dffb34538cb7021e18e0d6cc75cec950ccdfa545"
        );
        assert_eq!(
            out.hash_call_data,
            "0x8821c83eca090defb0ef1dda1728a474a1a23442e8021d11119c618963c59b5b"
        );
        assert_eq!(out.dvn_call_data_boc, "b5ee9c72410204010001570001ef65786563506172616d73815ee4ffc625ed4a7b82befffffffffffffffffffffffffffffffffffffffffffffd111111111111111111111111111111111111111111111111111111111111111000000001dcd65002652abd385d1313776775216ef61bb53bd51b863623f633635f429e54ebd5baebb7daaf72010197000000004d644164647293ff2057bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc0a340fcc8f0896efee58a8073ff83b1f552424483648896ab841cf2b09fb10da02016700556c6e566572696679615ee4ffcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000060300a700000000417474657374815ed897bfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe6d2a1247761c19bf6396c4b7fecd14e32dc087863835b31d73b2543337e95140000000000000006635a9c2d");
    }

    #[test]
    fn build_matches_oracle_vec_c_large_multicell_message() {
        // 200-byte message -> multi-cell hex_to_cells chain (non-byte-aligned
        // 1023-bit split), the load-bearing path feeding packet_hash.
        let code = code();
        let message = format!("0x{}", "0123456789abcdef".repeat(25));
        let out = build_ton_dvn_verify(&TonDvnVerifyRequest {
            src_eid: 30101,
            dst_eid: 30343,
            sender: "0x1111111111111111111111111111111111111111",
            receiver: "0:2222222222222222222222222222222222222222222222222222222222222222",
            guid: "0x5555555555555555555555555555555555555555555555555555555555555555",
            nonce: 7,
            message: &message,
            block_confirmation: 20,
            expiration: 1_700_000_000,
            uln_manager_address: "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH",
            target: "0:4444444444444444444444444444444444444444444444444444444444444444",
            code: &code,
        })
        .unwrap();
        assert_eq!(
            out.packet_hash,
            "b12317bfeb0de4d97f9c7a24da3de08bbab61c22c5fcc99972e2cd2741ae091a"
        );
        assert_eq!(
            out.hash_call_data,
            "0x6a77fe5945a0c8d3550f8d6b9a19d0603e27374036abb7e1e6c96507f3e7fca6"
        );
        assert_eq!(out.dvn_call_data_boc, "b5ee9c72410204010001570001ef65786563506172616d73815ee4ffc625ed4a7b82befffffffffffffffffffffffffffffffffffffffffffffd111111111111111111111111111111111111111111111111111111111111111000000001954fc402652abd385d1313776775216ef61bb53bd51b863623f633635f429e54ebd5baebb7daaf72010197000000004d644164647293ff2057bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd806e41da72dfea3810968100343c9e6885a828d334d76475f1d1a12677fa48fe02016700556c6e566572696679615ee4ffcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000001e0300a700000000417474657374815ed897bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec48c5effac379365fe71e89368f7822eead8708b17f32665cb8b349d06b824680000000000000052faf64559");
    }
}
