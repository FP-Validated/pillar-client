//! Deterministic ULN / UlnConnection contract address derivation for TON,
//! ported from the upstream LayerZero TypeScript implementation
//! (`getUlnContractFromConstructor` / `getUlnConnectionContractFromConstructor`).
//!
//! An address is `contractAddress(workchain=0, { code, data })` where `code` is
//! the compiled FunC artifact (supplied from generated static data) and `data`
//! is the class's initial storage encoded via [`cl_declare`].

use ton_core::cell::TonCell;
use ton_core::types::TonAddress;

use super::cell::{boc_from_hex, build, builder, state_init_address};
use super::cl_declare::{cl_declare, ClField, T_UINT16, T_UINT256, T_UINT32, T_UINT64, T_UINT8};
use num_bigint::BigUint;
use pillar_core::AppCoreError;

/// The compiled code cells (BOC hex) needed for address derivation, injected by
/// the runtime from `pillar_config` generated static data.
#[derive(Debug, Clone)]
pub struct TonContractCodeCells {
    pub uln: String,
    pub uln_connection: String,
}

fn empty_cell() -> Result<TonCell, AppCoreError> {
    build(builder())
}

/// `bigintToAddress`/`parseTonAddress` + `numberTypeLikeToAbsBigInt` for an
/// address-typed value: returns the 256-bit account id as big-endian bytes.
pub fn address_to_be32(value: &str) -> Result<[u8; 32], AppCoreError> {
    let trimmed = value.trim();
    let bytes = if let Some(hex_part) = trimmed.strip_prefix("0x") {
        // EVM / raw hex address: the integer value, right-aligned in 32 bytes.
        BigUint::parse_bytes(hex_part.as_bytes(), 16)
            .ok_or_else(|| AppCoreError::Internal(format!("invalid hex address: {value}")))?
    } else {
        // TON address: raw `wc:hash` or friendly base64 (handled by FromStr).
        let addr: TonAddress = trimmed
            .parse()
            .map_err(|e| AppCoreError::Internal(format!("invalid TON address {value}: {e}")))?;
        BigUint::from_bytes_be(addr.hash.as_slice())
    };
    let raw = bytes.to_bytes_be();
    if raw.len() > 32 {
        return Err(AppCoreError::Internal(format!(
            "address exceeds 256 bits: {value}"
        )));
    }
    let mut out = [0u8; 32];
    out[32 - raw.len()..].copy_from_slice(&raw);
    Ok(out)
}

/// `initBaseStorage(owner)` = `BaseStorage { owner, authenticated:false,
/// initialized:false, initialStorage:emptyCell }`.
fn build_base_storage(owner_be: &[u8; 32]) -> Result<TonCell, AppCoreError> {
    cl_declare(
        "baseStore",
        vec![
            ClField::u256_be(T_UINT256, owner_be),
            ClField::uint(0, 0u32),      // authenticated (bool)
            ClField::uint(0, 0u32),      // initialized (bool)
            ClField::Ref(empty_cell()?), // initialStorage
        ],
    )
}

/// `getUlnReceiveConfigDefault()`.
fn build_uln_receive_config_default() -> Result<TonCell, AppCoreError> {
    cl_declare(
        "UlnRecvCfg",
        vec![
            ClField::uint(0, 1u32),        // minCommitPacketGasNull = true
            ClField::uint(T_UINT32, 0u32), // minCommitPacketGas
            ClField::uint(0, 1u32),        // confirmationsNull = true
            ClField::uint(T_UINT64, 0u32), // confirmations
            ClField::uint(0, 1u32),        // requiredDVNsNull = true
            ClField::Ref(empty_cell()?),   // requiredDVNs (addressList, empty cell)
            ClField::uint(0, 1u32),        // optionalDVNsNull = true
            ClField::Ref(empty_cell()?),   // optionalDVNs
            ClField::uint(T_UINT8, 0u32),  // optionalDVNThreshold
        ],
    )
}

/// `getUlnSendConfigDefault()`.
fn build_uln_send_config_default() -> Result<TonCell, AppCoreError> {
    cl_declare(
        "UlnSendCfg",
        vec![
            ClField::uint(T_UINT32, 0u32),           // workerQuoteGasLimit
            ClField::uint(T_UINT32, 0u32),           // maxMessageBytes
            ClField::uint(0, 1u32),                  // executorNull = true
            ClField::u256_be(T_UINT256, &[0u8; 32]), // executor = 0
            ClField::uint(0, 1u32),                  // requiredDVNsNull = true
            ClField::Ref(empty_cell()?),             // requiredDVNs
            ClField::uint(0, 1u32),                  // optionalDVNsNull = true
            ClField::Ref(empty_cell()?),             // optionalDVNs
            ClField::uint(0, 1u32),                  // confirmationsNull = true
            ClField::uint(T_UINT64, 0u32),           // confirmations
        ],
    )
}

/// `Uln` initial storage cell for a pathway (already EID-swapped so that the
/// TON endpoint is the source, per `getContractPathObjectEidOnly`).
fn build_uln_data(
    uln_manager_be: &[u8; 32],
    contract_src_eid: u32,
    contract_dst_eid: u32,
) -> Result<TonCell, AppCoreError> {
    cl_declare(
        "uln",
        vec![
            ClField::Ref(build_base_storage(uln_manager_be)?),
            ClField::uint(T_UINT32, contract_src_eid),
            ClField::uint(T_UINT32, contract_dst_eid),
            ClField::Ref(build_uln_receive_config_default()?),
            ClField::Ref(build_uln_send_config_default()?),
            ClField::Ref(empty_cell()?),   // connectionCode
            ClField::Ref(empty_cell()?),   // workerFeelibInfos (dict256, empty)
            ClField::uint(T_UINT16, 0u32), // treasuryFeeBps
            ClField::uint(T_UINT16, 0u32), // remainingWorkerSlots
            ClField::uint(T_UINT16, 0u32), // remainingAdminWorkerSlots
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn build_uln_connection_data(
    uln_manager_be: &[u8; 32],
    path_src_eid: u32,
    path_src_oapp_be: &[u8; 32],
    path_dst_eid: u32,
    path_dst_oapp_be: &[u8; 32],
    uln_address_be: &[u8; 32],
) -> Result<TonCell, AppCoreError> {
    let path = cl_declare(
        "path",
        vec![
            ClField::uint(T_UINT32, path_src_eid),
            ClField::u256_be(T_UINT256, path_src_oapp_be),
            ClField::uint(T_UINT32, path_dst_eid),
            ClField::u256_be(T_UINT256, path_dst_oapp_be),
        ],
    )?;
    cl_declare(
        "connection",
        vec![
            ClField::Ref(build_base_storage(uln_manager_be)?),
            ClField::Ref(path),
            ClField::u256_be(T_UINT256, &[0u8; 32]), // endpointAddress = 0
            ClField::u256_be(T_UINT256, &[0u8; 32]), // channelAddress = 0
            ClField::uint(T_UINT64, 1u32),           // firstUnexecutedNonce = 1
            ClField::u256_be(T_UINT256, uln_address_be),
            ClField::Ref(build_uln_send_config_default()?),
            ClField::Ref(build_uln_receive_config_default()?),
            ClField::Ref(empty_cell()?), // hashLookups (dict256, empty)
            ClField::Ref(empty_cell()?), // commitPOOO (initial storage = empty cell)
        ],
    )
}

/// A resolved pathway for a EVM -> TON message.
pub struct TonPathway<'a> {
    pub src_eid: u32,
    pub dst_eid: u32,
    /// Source OApp (EVM sender) as an address string.
    pub sender: &'a str,
    /// Destination OApp (TON receiver) as an address string.
    pub receiver: &'a str,
    pub uln_manager_address: &'a str,
}

/// Derived ULN + UlnConnection addresses for a pathway.
pub struct DerivedAddresses {
    pub uln: TonAddress,
    pub uln_connection: TonAddress,
}

/// Compute the deterministic ULN and UlnConnection addresses for an EVM -> TON
/// pathway. The EID/OApp path is swapped so the TON endpoint is the source,
/// matching `getContractPathObjectEidOnly` for a non-TON source chain.
pub fn derive_uln_addresses(
    pathway: &TonPathway<'_>,
    code: &TonContractCodeCells,
) -> Result<DerivedAddresses, AppCoreError> {
    let uln_manager_be = address_to_be32(pathway.uln_manager_address)?;
    let sender_be = address_to_be32(pathway.sender)?;
    let receiver_be = address_to_be32(pathway.receiver)?;

    // EVM -> TON: source chain is not TON, so send/receive are swapped for the
    // TON contract's own path.
    let (c_src_eid, c_dst_eid) = (pathway.dst_eid, pathway.src_eid);
    let (c_src_oapp, c_dst_oapp) = (&receiver_be, &sender_be);

    let uln_code = boc_from_hex(&code.uln)?;
    let uln_conn_code = boc_from_hex(&code.uln_connection)?;

    let uln_data = build_uln_data(&uln_manager_be, c_src_eid, c_dst_eid)?;
    let uln = state_init_address(0, &uln_code, &uln_data)?;

    let uln_addr_be: [u8; 32] = uln.hash.as_slice().try_into().expect("32-byte hash");
    let uln_conn_data = build_uln_connection_data(
        &uln_manager_be,
        c_src_eid,
        c_src_oapp,
        c_dst_eid,
        c_dst_oapp,
        &uln_addr_be,
    )?;
    let uln_connection = state_init_address(0, &uln_conn_code, &uln_conn_data)?;

    Ok(DerivedAddresses {
        uln,
        uln_connection,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference addresses produced by the real compiled LayerZero TON encoders
    // and `contractAddress` from `@ton/core`. The reproducible form of this is
    // `scripts/gasolina-parity/emit-ton-dvn-verify.ts`, whose committed output
    // (`tests/gasolina_parity/ton_dvn_verify.json`) drives the parity tests.
    fn code_cells() -> TonContractCodeCells {
        TonContractCodeCells {
            uln: pillar_config::ton_code_cell("Uln").unwrap().to_string(),
            uln_connection: pillar_config::ton_code_cell("UlnConnection")
                .unwrap()
                .to_string(),
        }
    }

    const ULN_MANAGER: &str = "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH";
    const RECEIVER: &str = "0:2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn derives_uln_addresses_matching_oracle_vec_a() {
        let pathway = TonPathway {
            src_eid: 30101,
            dst_eid: 30343,
            sender: "0x1111111111111111111111111111111111111111",
            receiver: RECEIVER,
            uln_manager_address: ULN_MANAGER,
        };
        let derived = derive_uln_addresses(&pathway, &code_cells()).unwrap();
        assert_eq!(
            derived.uln.to_hex(),
            "0:1744c4ddd9dd485bbd86ed4ef546e18d88fd8cd8d7d0a7953af56ebaedf6abdc"
        );
        assert_eq!(
            derived.uln_connection.to_hex(),
            "0:601b90769cb7fa8e0425a0400d0f279a216a0a34cd35d91d7c7468499dfe923f"
        );
    }

    #[test]
    fn derives_uln_connection_depends_on_sender_vec_b() {
        let pathway = TonPathway {
            src_eid: 30101,
            dst_eid: 30343,
            sender: "0x00000000000000000000000000000000deadbeef",
            receiver: RECEIVER,
            uln_manager_address: ULN_MANAGER,
        };
        let derived = derive_uln_addresses(&pathway, &code_cells()).unwrap();
        // Uln address depends only on {eids, ulnManager}.
        assert_eq!(
            derived.uln.to_hex(),
            "0:1744c4ddd9dd485bbd86ed4ef546e18d88fd8cd8d7d0a7953af56ebaedf6abdc"
        );
        assert_eq!(
            derived.uln_connection.to_hex(),
            "0:028d03f323c225bbfb962a01cffe0ec7d54909120d92225aae1073cac27ec436"
        );
    }
}
