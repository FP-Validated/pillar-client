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
    use serde_json::Value;

    fn gasolina_parity_json(name: &str) -> String {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        path.push("gasolina_parity");
        path.push(name);
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "missing Gasolina parity fixture {}: {error}",
                path.display()
            )
        })
    }

    /// These BOCs are upstream's output, not values this port recorded from
    /// itself. The fixture was produced by running `buildDvnVerifyCallData`,
    /// `buildULNCallData` and the two address constructors from
    /// `@monorepo/lz-ton-contracts` over the same inputs; its `_provenance`
    /// block carries the entrypoints and the argument that the reproduction
    /// touches no node. Before that reproduction existed these values could
    /// only be described as codec regression locks.
    ///
    /// The three vectors are the cases where the cell encoding can go wrong
    /// without the others noticing: a normal single-cell message, an empty
    /// message, and a 200-byte message that forces `hexToCells` to split on a
    /// non byte-aligned 1023-bit boundary.
    #[test]
    fn build_matches_gasolina_for_every_ton_vector() {
        let fixture: Value =
            serde_json::from_str(&gasolina_parity_json("ton_dvn_verify.json")).expect("parses");
        let code = TonContractCodeCells {
            uln: ton_code_cell("Uln").unwrap().to_string(),
            uln_connection: ton_code_cell("UlnConnection").unwrap().to_string(),
        };

        let vectors = fixture["vectors"].as_array().expect("vectors");
        assert_eq!(vectors.len(), 3, "every recorded vector must be compared");

        for vector in vectors {
            let id = vector["id"].as_str().unwrap();
            let input = &vector["input"];
            let out = build_ton_dvn_verify(&TonDvnVerifyRequest {
                src_eid: u32::try_from(input["srcEid"].as_u64().unwrap()).unwrap(),
                dst_eid: u32::try_from(input["dstEid"].as_u64().unwrap()).unwrap(),
                sender: input["sender"].as_str().unwrap(),
                receiver: input["receiver"].as_str().unwrap(),
                guid: input["guid"].as_str().unwrap(),
                nonce: input["nonce"].as_u64().unwrap(),
                message: input["message"].as_str().unwrap(),
                block_confirmation: input["blockConfirmation"].as_i64().unwrap(),
                expiration: input["expiration"].as_i64().unwrap(),
                uln_manager_address: vector["ulnManagerAddress"].as_str().unwrap(),
                target: input["dvnImplementation"].as_str().unwrap(),
                code: &code,
            })
            .unwrap_or_else(|error| panic!("{id}: build failed: {error:?}"));

            assert_eq!(
                out.packet_hash,
                vector["packetHash"].as_str().unwrap(),
                "{id}: lz::Packet representation hash"
            );
            assert_eq!(
                out.target_contract,
                vector["targetContract"].as_str().unwrap(),
                "{id}: addressToHex(uln.address)"
            );
            assert_eq!(
                out.uln_call_data_boc,
                vector["ulnCallDataBoc"].as_str().unwrap(),
                "{id}: md::MdAddress BOC"
            );
            assert_eq!(
                out.dvn_call_data_boc,
                vector["dvnCallDataBoc"].as_str().unwrap(),
                "{id}: md::ExecuteParams BOC"
            );
            assert_eq!(
                out.hash_call_data,
                format!("0x{}", vector["hashCallData"].as_str().unwrap()),
                "{id}: signed hash"
            );
        }
    }
}
