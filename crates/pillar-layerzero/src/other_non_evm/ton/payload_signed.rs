//! Pure decoding for the TON payload-signed check, ported from the upstream
//! LayerZero TypeScript implementation.
//!
//! `UlnTonSdk.hasPayloadSigned`
//! (TS: `packages/sdks/lz-v2-sdk/src/uln/ton/index.ts:228-249`) is
//! `verificationState ∈ {VERIFIABLE, VERIFIED} || hasDvnVerified`. This module
//! owns everything that is a pure function of contract storage — the DVN
//! attestation lookup, the receive-config DVN set and the `committableView`
//! state mapping — while the runtime crate owns transport and provider quorum.
//!
//! Class field indices come from the pinned
//! `@layerzerolabs/lz-ton-sdk-v2@3.0.167` generated schema and match the
//! initial-storage encoders in [`super::address`], which are locked by golden
//! address vectors:
//!
//! * `UlnConnection`: `0 baseStorage, 1 path, 2 endpointAddress,
//!   3 channelAddress, 4 firstUnexecutedNonce, 5 ulnAddress,
//!   6 UlnSendConfigOApp, 7 UlnReceiveConfigOApp, 8 hashLookups, 9 commitPOOO`
//! * `Uln`: `0 baseStorage, 1 eid, 2 dstEid, 3 defaultUlnReceiveConfig,
//!   4 defaultUlnSendConfig, ...`
//! * `lz::Attestation`: `0 hash (uint256), 1 confirmations (uint64)`

use pillar_core::AppCoreError;
use ton_core::cell::TonCell;

use super::address::{address_to_be32, derive_uln_addresses, TonContractCodeCells, TonPathway};
use super::builders::{build_lz_packet, build_lz_path};
use super::cell::{boc_to_base64, map_err, repr_hash_hex};
use super::cl_declare::{cl_get_ref, cl_get_uint_be};
use super::dict::dict256_get_ref;
use super::payload::hex_to_be32;

/// `UlnConnection.hashLookups` (`dict256`).
const ULN_CONNECTION_HASH_LOOKUPS: usize = 8;
/// `UlnConnection.UlnReceiveConfigOApp` (`objRef`).
const ULN_CONNECTION_RECEIVE_CONFIG: usize = 7;
/// `Uln.defaultUlnReceiveConfig` (`objRef`).
const ULN_DEFAULT_RECEIVE_CONFIG: usize = 3;
/// `lz::Attestation.hash` (`uint256`).
const ATTESTATION_HASH: usize = 0;

/// `UlnReceiveConfig.requiredDVNsNull` / `.requiredDVNs`.
const RECEIVE_CONFIG_REQUIRED_DVNS_NULL: usize = 4;
const RECEIVE_CONFIG_REQUIRED_DVNS: usize = 5;
/// `UlnReceiveConfig.optionalDVNsNull` / `.optionalDVNs`.
const RECEIVE_CONFIG_OPTIONAL_DVNS_NULL: usize = 6;
const RECEIVE_CONFIG_OPTIONAL_DVNS: usize = 7;

/// The `lz::Packet` BOC carried by the live mainnet `UlnConnection`'s own
/// inbound `MdObj` message at nonce 2095, exported so the runtime crate's
/// end-to-end test can assert that this exact packet reaches the wire.
/// `tests::rebuilds_the_live_mainnet_inbound_packet_byte_for_byte` proves the
/// builders reproduce it from the event fields.
pub const LIVE_TON_PACKET_BOC: &str = "te6cckECAwEAAQIAAqcAAAAAUGFja2V0k/8k/9YV7gZ7/////////////////////////////////AAAAAAAACC+wF+gw+I94oCV5eVzBiOtBeGC+YH6RkkAD9WyGdOQI/oBAgDnAAAAAAAAcGF0aFFe4F+1J+4Ke/////////////////////////////////wAAdZUAAAAAAAAAAAAAAAAfdIx23kaOnRG9NA+p1cut8xXfsAAAdocd31gAUhdO0d0NZsNb/cGl/Maa9PSuNhVLE9z8bBSjX4AZAADAAAAAAAAAAAAAAAAAAAAAAAAABZUK6RjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVPDPWw==";

/// Pathway inputs for one TON payload-signed check.
pub struct TonPayloadSignedRequest<'a> {
    pub src_eid: u32,
    pub dst_eid: u32,
    /// Source OApp (the sender on the non-TON chain).
    pub sender: &'a str,
    /// Destination OApp (the TON receiver).
    pub receiver: &'a str,
    /// Message guid (`0x`-prefixed, 32 bytes).
    pub guid: &'a str,
    pub nonce: u64,
    /// Message payload hex (`0x`-prefixed).
    pub message: &'a str,
    /// UlnManager deployment address for the selected (current or deprecated)
    /// ULN.
    pub uln_manager_address: &'a str,
    pub code: &'a TonContractCodeCells,
}

/// Everything the payload-signed check needs before touching a provider: the
/// two contract addresses to read, and the `lz::Packet` in both of the forms
/// the check consumes.
pub struct TonPayloadSignedTargets {
    /// `Uln` address, friendly bounceable form (`Address.toString()`).
    pub uln_address: String,
    /// `UlnConnection` address, friendly bounceable form.
    pub uln_connection_address: String,
    /// `lz::Packet` BOC base64, the second `committableView` argument.
    pub packet_boc_base64: String,
    /// `lz::Packet` representation hash, compared against the DVN attestation.
    pub packet_hash_be: [u8; 32],
}

/// Derive the contract addresses and packet for a payload-signed check.
///
/// TS: `packages/sdks/lz-v2-sdk/src/uln/ton/index.ts:137-160` and `:262-300`
/// derive the `Uln` / `UlnConnection` contracts from the pathway, and
/// `:204-222` / `:277-292` build the `lz::Packet` from the *unswapped* pathway.
pub fn ton_payload_signed_targets(
    request: &TonPayloadSignedRequest<'_>,
) -> Result<TonPayloadSignedTargets, AppCoreError> {
    let derived = derive_uln_addresses(
        &TonPathway {
            src_eid: request.src_eid,
            dst_eid: request.dst_eid,
            sender: request.sender,
            receiver: request.receiver,
            uln_manager_address: request.uln_manager_address,
        },
        request.code,
    )?;

    let path = build_lz_path(
        request.src_eid,
        &address_to_be32(request.sender)?,
        request.dst_eid,
        &address_to_be32(request.receiver)?,
    )?;
    let packet = build_lz_packet(
        path,
        request.message,
        request.nonce,
        &hex_to_be32(request.guid)?,
    )?;

    Ok(TonPayloadSignedTargets {
        uln_address: derived.uln.to_string(),
        uln_connection_address: derived.uln_connection.to_string(),
        packet_boc_base64: boc_to_base64(&packet)?,
        packet_hash_be: hex_to_be32(&repr_hash_hex(&packet)?)?,
    })
}

/// `VerificationState` as far as the payload-signed check is concerned.
///
/// TS: `packages/sdks/lz-v2-sdk/src/uln/ton/index.ts:315-326` maps the
/// `committableView` number to `0 VERIFYING, 1 VERIFIABLE, 2 VERIFIED,
/// 3 VERIFIED (executed), 4 VERIFYING (config error)`, defaulting to
/// `VERIFYING`; `hasPayloadSigned` then treats `VERIFIABLE` and `VERIFIED` as
/// signed.
pub fn committable_view_is_signed(state: u64) -> bool {
    matches!(state, 1..=3)
}

/// `deserializeAddressList`: 256-bit account ids packed into a cell chain, each
/// cell holding as many as fit and chaining the rest through its last
/// reference.
///
/// TS: `packages/common-ton/src/class/helpers.ts:114-137`
pub fn deserialize_address_list(cell: &TonCell) -> Result<Vec<[u8; 32]>, AppCoreError> {
    let mut addresses = Vec::new();
    let mut current = Some(cell.clone());
    while let Some(node) = current {
        let mut parser = node.parser();
        while parser.data_bits_left().map_err(map_err)? >= 256 {
            let mut address = [0u8; 32];
            parser.read_bits_to(256, &mut address).map_err(map_err)?;
            addresses.push(address);
        }
        current = if parser.refs_left() > 0 {
            Some(parser.read_next_ref().map_err(map_err)?.clone())
        } else {
            None
        };
    }
    Ok(addresses)
}

/// The DVN sets of a `UlnReceiveConfig` storage cell, with the `*Null` flags
/// that drive the custom-over-default merge.
struct ReceiveConfigDvns {
    required_is_null: bool,
    required: Vec<[u8; 32]>,
    optional_is_null: bool,
    optional: Vec<[u8; 32]>,
}

fn read_bool(cell: &TonCell, field_index: usize) -> Result<bool, AppCoreError> {
    Ok(cl_get_uint_be(cell, field_index, 1)?.first() == Some(&1))
}

fn receive_config_dvns(config: &TonCell) -> Result<ReceiveConfigDvns, AppCoreError> {
    Ok(ReceiveConfigDvns {
        required_is_null: read_bool(config, RECEIVE_CONFIG_REQUIRED_DVNS_NULL)?,
        required: deserialize_address_list(&cl_get_ref(config, RECEIVE_CONFIG_REQUIRED_DVNS)?)?,
        optional_is_null: read_bool(config, RECEIVE_CONFIG_OPTIONAL_DVNS_NULL)?,
        optional: deserialize_address_list(&cl_get_ref(config, RECEIVE_CONFIG_OPTIONAL_DVNS)?)?,
    })
}

/// The effective inbound DVN set for a pathway: the OApp's own
/// `UlnReceiveConfigOApp`, with each null half falling back to the ULN's
/// `defaultUlnReceiveConfig`.
///
/// TS: `packages/contracts/lz-ton-contracts/src/uln.ts:153-188`
/// (`getUlnVerifyConfig`) and `:483-534` (`fetchUlnConfig` returning
/// `requiredDVNs`/`optionalDVNs`). A null half on both sides is an invalid
/// config upstream (`throw new Error('ULN Config is invalid: ...')`).
pub fn effective_receive_dvns(
    custom_config: &TonCell,
    default_config: &TonCell,
) -> Result<Vec<[u8; 32]>, AppCoreError> {
    let custom = receive_config_dvns(custom_config)?;
    let default = receive_config_dvns(default_config)?;

    let required = if custom.required_is_null {
        if default.required_is_null {
            return Err(AppCoreError::Internal(
                "ULN Config is invalid: requiredDVNs missing".to_string(),
            ));
        }
        default.required
    } else {
        custom.required
    };
    let optional = if custom.optional_is_null {
        if default.optional_is_null {
            return Err(AppCoreError::Internal(
                "ULN Config is invalid: optionalDVNs missing".to_string(),
            ));
        }
        default.optional
    } else {
        custom.optional
    };

    let mut dvns = optional;
    dvns.extend(required);
    Ok(dvns)
}

/// `Uln.defaultUlnReceiveConfig` raw cell — also the third `committableView`
/// argument.
pub fn uln_default_receive_config(uln_storage: &TonCell) -> Result<TonCell, AppCoreError> {
    cl_get_ref(uln_storage, ULN_DEFAULT_RECEIVE_CONFIG)
}

/// `UlnConnection.UlnReceiveConfigOApp` raw cell.
pub fn uln_connection_receive_config(
    connection_storage: &TonCell,
) -> Result<TonCell, AppCoreError> {
    cl_get_ref(connection_storage, ULN_CONNECTION_RECEIVE_CONFIG)
}

/// Outcome of the DVN attestation half of the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DvnAttestation {
    /// This DVN has an attestation for the packet.
    Matches,
    /// No attestation for this nonce/DVN, or a different packet hash.
    Absent,
    /// The DVN is not in the destination receive config, so TON could never
    /// accept its proof. Upstream short-circuits to "already signed" so the
    /// signing request becomes a no-op instead of a failing verify workflow.
    ///
    /// TS: `packages/sdks/lz-v2-sdk/src/uln/ton/index.ts:178-192`
    NotInReceiveConfig,
}

/// `hasDvnVerified`, minus the two storage reads.
///
/// TS: `packages/sdks/lz-v2-sdk/src/uln/ton/index.ts:132-223`
pub fn dvn_attestation(
    connection_storage: &TonCell,
    default_receive_config: &TonCell,
    nonce: u64,
    verifier_be: &[u8; 32],
    packet_hash_be: &[u8; 32],
) -> Result<DvnAttestation, AppCoreError> {
    let hash_lookups = cl_get_ref(connection_storage, ULN_CONNECTION_HASH_LOOKUPS)?;
    let mut nonce_key = [0u8; 32];
    nonce_key[24..].copy_from_slice(&nonce.to_be_bytes());
    // `!hashLookupsDictionary.has(nonce)` -> false, checked before the
    // receive-config short-circuit.
    let Some(per_verifier) = dict256_get_ref(&hash_lookups, &nonce_key)? else {
        return Ok(DvnAttestation::Absent);
    };

    let custom_receive_config = uln_connection_receive_config(connection_storage)?;
    let configured = effective_receive_dvns(&custom_receive_config, default_receive_config)?;
    if !configured.iter().any(|dvn| dvn == verifier_be) {
        return Ok(DvnAttestation::NotInReceiveConfig);
    }

    let Some(attestation) = dict256_get_ref(&per_verifier, verifier_be)? else {
        return Ok(DvnAttestation::Absent);
    };
    let attested_hash = cl_get_uint_be(&attestation, ATTESTATION_HASH, 256)?;
    if attested_hash.as_slice() == packet_hash_be.as_slice() {
        Ok(DvnAttestation::Matches)
    } else {
        Ok(DvnAttestation::Absent)
    }
}

#[cfg(test)]
mod tests {
    use super::super::cell::{build, builder};
    use super::super::cl_declare::{
        cl_declare, ClField, T_UINT16, T_UINT256, T_UINT32, T_UINT64, T_UINT8,
    };
    use super::*;
    use num_bigint::BigUint;

    /// `UlnConnection` storage with an attestation from DVN `0xaa..aa` for nonce 7,
    /// whose receive config lists that same DVN. Built by
    /// `payload_signed::tests::runtime_storage_fixtures_are_stable`.
    const FIXTURE_ATTESTED_CONNECTION: &str = "te6cckECCAEAAaEAA+djb25uZWN0aW9uk/8k/9gV7gl7Y17iADm/8m/9m/+m/////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgcHAQRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAgMHAnNVbG5SZWN2Q2ZnAV7UV/AX/YYDAcDk/8AcHk/9McL//////////////////gAAAAEAAAAAAAAAAAAgBAcBQ6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPAFAECqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgFDoBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVUAYApwAAAABBdHRlc3SBXtiXv//////////////////////////////////////93d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3dwAAAAAAAAABgAA42yTPA==";

    /// `UlnConnection` storage with an empty `hashLookups` dictionary.
    const FIXTURE_EMPTY_CONNECTION: &str = "te6cckECBQEAAQEAA+djb25uZWN0aW9uk/8k/9gV7gl7Y17iADm/8m/9m/+m/////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgQEAQRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAgQEAnNVbG5SZWN2Q2ZnAV7UV/AX/YYDAcDk/8AcHk/9McL//////////////////gAAAAEAAAAAAAAAAAAgAwQAQKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAACEskBt";

    /// `UlnConnection` storage that has an attestation for nonce 7 from DVN
    /// `0xaa..aa`, but whose receive config only lists `0xbb..bb`.
    const FIXTURE_FOREIGN_DVN_CONNECTION: &str = "te6cckECCAEAAaEAA+djb25uZWN0aW9uk/8k/9gV7gl7Y17iADm/8m/9m/+m/////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgcHAQRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAgMHAnNVbG5SZWN2Q2ZnAV7UV/AX/YYDAcDk/8AcHk/9McL//////////////////gAAAAEAAAAAAAAAAAAgBAcBQ6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPAFAEC7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uwFDoBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVUAYApwAAAABBdHRlc3SBXtiXv//////////////////////////////////////93d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3dwAAAAAAAAABgAAhwJfzA==";

    /// `Uln` storage whose `defaultUlnReceiveConfig` has empty, non-null DVN lists.
    const FIXTURE_ULN_STORAGE: &str = "te6cckEBBAEAhAADcwAAAAAAAAB1bG6T/xRXtRfuT/2b/yb/2b/5BntBrtBvv//////////////8AAAAAAAAAAAAAAAAAAIDAQICc1VsblJlY3ZDZmcBXtRX8Bf9hgMBwOT/wBweT/0xwv/////////////////+AAAAAQAAAAAAAAAAACADAwMAAwMDAACgWnrC";

    fn addr(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn address_list(addresses: &[[u8; 32]]) -> TonCell {
        let mut b = builder();
        for address in addresses {
            b.write_num(&BigUint::from_bytes_be(address), 256).unwrap();
        }
        build(b).unwrap()
    }

    /// `UlnReceiveConfig` in schema field order (see [`super::super::address`]).
    fn receive_config(required: Option<&[[u8; 32]]>, optional: Option<&[[u8; 32]]>) -> TonCell {
        cl_declare(
            "UlnRecvCfg",
            vec![
                ClField::uint(0, 1u32), // minCommitPacketGasNull
                ClField::uint(T_UINT32, 0u32),
                ClField::uint(0, 1u32), // confirmationsNull
                ClField::uint(T_UINT64, 0u32),
                ClField::uint(0, u32::from(required.is_none())),
                ClField::Ref(address_list(required.unwrap_or(&[]))),
                ClField::uint(0, u32::from(optional.is_none())),
                ClField::Ref(address_list(optional.unwrap_or(&[]))),
                ClField::uint(T_UINT8, 0u32),
            ],
        )
        .unwrap()
    }

    fn attestation(hash: &[u8; 32]) -> TonCell {
        cl_declare(
            "Attest",
            vec![
                ClField::u256_be(T_UINT256, hash),
                ClField::uint(T_UINT64, 1u32),
            ],
        )
        .unwrap()
    }

    /// One-key `dict256` whose value is `value`, matching
    /// `Dictionary.Values.Cell()` (value stored as a reference).
    fn single_key_dict(key_be: &[u8; 32], value: TonCell) -> TonCell {
        let mut b = builder();
        b.write_bit(true).unwrap(); // hml_long$10
        b.write_bit(false).unwrap();
        b.write_num(&BigUint::from(256u32), 9).unwrap();
        b.write_bits(key_be, 256).unwrap();
        b.write_ref(value).unwrap();
        build(b).unwrap()
    }

    fn nonce_key(nonce: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[24..].copy_from_slice(&nonce.to_be_bytes());
        key
    }

    fn connection_storage(hash_lookups: TonCell, custom_receive: TonCell) -> TonCell {
        cl_declare(
            "connection",
            vec![
                ClField::Ref(build(builder()).unwrap()), // baseStorage
                ClField::Ref(build(builder()).unwrap()), // path
                ClField::u256_be(T_UINT256, &[0u8; 32]), // endpointAddress
                ClField::u256_be(T_UINT256, &[0u8; 32]), // channelAddress
                ClField::uint(T_UINT64, 1u32),           // firstUnexecutedNonce
                ClField::u256_be(T_UINT256, &[0u8; 32]), // ulnAddress
                ClField::Ref(build(builder()).unwrap()), // UlnSendConfigOApp
                ClField::Ref(custom_receive),            // UlnReceiveConfigOApp
                ClField::Ref(hash_lookups),              // hashLookups
                ClField::Ref(build(builder()).unwrap()), // commitPOOO
            ],
        )
        .unwrap()
    }

    /// Real TON mainnet `UlnConnection` storage, read from toncenter
    /// `getAddressInformation` for
    /// `0:168B0D4BC86F5F148DDC86AEE8D8A9AF61D75C82E8C4509A14C8C0377DA8AD79`.
    /// That contract was found by walking the transactions of the `Uln` this
    /// crate derives for the Ethereum(30101) -> TON pathway, so it is a real
    /// deployment rather than a hand-built cell. It pins the class name, the
    /// `hashLookups` field index and the receive-config field index against
    /// production bytes.
    const LIVE_ULN_CONNECTION_STORAGE: &str = "te6cckECDwEABI0AA+djb25uZWN0aW9uk/8k/9gV7gl7Y17iADm/8m/9m/+m/////////////////CwxOfwU8SQuTZAt1lF9w2Ed3WNVioLZOKVx1h7NKIxwEQ7s5JtpYPL54PzJ1TO8v8CfCWaBK1dDlJwtpZFVUlgAAAAAAAAgvgEFAgGYAGJhc2VTdG9yZYFewJewJf5P/P////////////////////////////////wa1KxGrr2W/H/R8V+iQukrWp1pohZu+WlHB/EUZVMVMwMEQBdExN3Z3UhbvYbtTvVG4Y2I/YzY19CnlTr1brrt9qvcCQoNCwPnY29ubmVjdGlvbpP/JP/YFe4Je2Ne4gA5v/Jv/Zv/pv////////////////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYEBQYBmABiYXNlU3RvcmWBXsCXsCX+T/z////////////////////////////////8GtSsRq69lvx/0fFfokLpK1qdaaIWbvlpRwfxFGVTFTANAOcAAAAAAABwYXRoUV7gX7Un7gp7/////////////////////////////////AAB2hx3fWABSF07R3Q1mw1v9waX8xpr09K42FUsT3PxsFKNfAAB1lQAAAAAAAAAAAAAAAB90jHbeRo6dEb00D6nVy63zFd+wgRAF0TE3dndSFu9hu1O9UbhjYj9jNjX0KeVOvVuuu32q9wHCA0NArlVbG5TZW5kQ2ZnUV7UX7AZ7gZ/Ap/k/8AqDk/9AqHYqL///////////////AAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAACANDQJzVWxuUmVjdkNmZwFe1FfwF/2GAwHA5P/AHB5P/THC//////////////////4AAAABAAAAAAAAAADAIA0NArlVbG5TZW5kQ2ZnUV7UX7AZ7gZ/Ap/k/8AqDk/9AqHYqL///////////////AAHUwAAAAgqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKAMDQJzVWxuUmVjdkNmZwFe1FfwF/2GAwHA5P/AHB5P/THC//////////////////wABjnAAAAAAAAAAA8AIAwNAWcAAAAAAABQT09PYV7k/8///////////////////////////////////////AAAAAAAACDCDgCADRIt7E7IvWbGg0T68N1HHXJ6fVeiG2IFFwW74uTCcqcEufmDYATX9T5S4BYC2cB8FM3zi4qUa26BPP6o3hCSfQAAAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZPMnes=";

    #[test]
    fn decodes_live_mainnet_uln_connection_storage() {
        use super::super::cell::boc_from_base64;
        use super::super::cl_declare::cell_name;

        let storage = boc_from_base64(LIVE_ULN_CONNECTION_STORAGE).expect("parse live storage");
        assert_eq!(cell_name(&storage).unwrap(), "connection");

        // `hashLookups` (field 8) is an empty dict on this connection, so no
        // nonce resolves and the DVN half reports `Absent`.
        let attestation = dvn_attestation(
            &storage,
            &receive_config(Some(&[addr(0xaa)]), Some(&[])),
            1,
            &addr(0xaa),
            &addr(0x77),
        )
        .unwrap();
        assert_eq!(attestation, DvnAttestation::Absent);

        // The OApp receive config (field 7) decodes as a `UlnReceiveConfig`.
        let custom = uln_connection_receive_config(&storage).expect("receive config");
        assert_eq!(cell_name(&custom).unwrap(), "UlnRecvCfg");
    }

    /// The real mainnet `UlnConnection`
    /// `0:168B0D4BC86F5F148DDC86AEE8D8A9AF61D75C82E8C4509A14C8C0377DA8AD79`
    /// stores its own pathway, read out of its `path` field (index 1):
    /// Ethereum(30101) OApp `0x1f748c76de468e9d11bd340fa9d5cbadf315dfb0` ->
    /// TON(30343) OApp
    /// `0x1ddf580052174ed1dd0d66c35bfdc1a5fcc69af4f4ae36154b13dcfc6c14a35f`.
    /// Deriving from those real values must reproduce the deployed address, so
    /// this pins the whole derivation chain (base storage, path encoding, the
    /// EID swap, the pinned code cells and the StateInit hash) against a live
    /// deployment instead of a synthetic vector.
    #[test]
    fn derives_the_live_mainnet_uln_connection_address() {
        let code = TonContractCodeCells {
            uln: pillar_config::ton_code_cell("Uln").unwrap().to_string(),
            uln_connection: pillar_config::ton_code_cell("UlnConnection")
                .unwrap()
                .to_string(),
        };
        let targets = ton_payload_signed_targets(&TonPayloadSignedRequest {
            src_eid: 30_101,
            dst_eid: 30_343,
            sender: "0x1f748c76de468e9d11bd340fa9d5cbadf315dfb0",
            receiver: "0x1ddf580052174ed1dd0d66c35bfdc1a5fcc69af4f4ae36154b13dcfc6c14a35f",
            guid: "0x0000000000000000000000000000000000000000000000000000000000000000",
            nonce: 1,
            message: "0x",
            uln_manager_address: "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH",
            code: &code,
        })
        .unwrap();
        assert_eq!(
            targets.uln_connection_address,
            "EQAWiw1LyG9fFI3chq7o2KmvYddcgujEUJoUyMA3faiteWtV"
        );
        assert_eq!(
            targets.uln_address,
            "EQAXRMTd2d1IW72G7U71RuGNiP2M2NfQp5U69W667far3CYo"
        );
    }

    /// Every field below was decoded out of the real `lz::Packet` cell carried
    /// by the live mainnet `UlnConnection`'s own inbound `MdObj` message
    /// (opcode `0xf9d37b80`) at nonce 2095. Rebuilding the packet from those
    /// fields must reproduce that BOC byte for byte, which is what ties
    /// `build_lz_packet`'s path/message/nonce/guid layout to a real delivered
    /// LayerZero message rather than a vector we invented.
    pub(crate) const LIVE_PACKET_SRC_EID: u32 = 30_101;
    pub(crate) const LIVE_PACKET_SENDER: &str = "0x1f748c76de468e9d11bd340fa9d5cbadf315dfb0";
    pub(crate) const LIVE_PACKET_DST_EID: u32 = 30_343;
    pub(crate) const LIVE_PACKET_RECEIVER: &str =
        "0x1ddf580052174ed1dd0d66c35bfdc1a5fcc69af4f4ae36154b13dcfc6c14a35f";
    pub(crate) const LIVE_PACKET_NONCE: u64 = 2095;
    pub(crate) const LIVE_PACKET_GUID: &str =
        "0xb017e830f88f78a02579795cc188eb417860be607e91924003f56c8674e408fe";
    pub(crate) const LIVE_PACKET_MESSAGE: &str = "0x00030000000000000000000000000000000000000016542ba463000000000000000000000000000000000000000000000000";

    #[test]
    fn rebuilds_the_live_mainnet_inbound_packet_byte_for_byte() {
        let path = build_lz_path(
            LIVE_PACKET_SRC_EID,
            &hex_to_be32(LIVE_PACKET_SENDER).unwrap(),
            LIVE_PACKET_DST_EID,
            &hex_to_be32(LIVE_PACKET_RECEIVER).unwrap(),
        )
        .unwrap();
        let packet = build_lz_packet(
            path,
            LIVE_PACKET_MESSAGE,
            LIVE_PACKET_NONCE,
            &hex_to_be32(LIVE_PACKET_GUID).unwrap(),
        )
        .unwrap();
        assert_eq!(boc_to_base64(&packet).unwrap(), LIVE_TON_PACKET_BOC);
        assert_eq!(
            repr_hash_hex(&packet).unwrap(),
            "e4482d1fcf50c317e9a35c45470bfdd025e9f9ea4c9125094a6facf6b4d96617"
        );
    }

    #[test]
    fn committable_view_signed_states_match_ts_mapping() {
        // VERIFIABLE(1), VERIFIED(2), VERIFIED-executed(3) count as signed.
        assert!(!committable_view_is_signed(0));
        assert!(committable_view_is_signed(1));
        assert!(committable_view_is_signed(2));
        assert!(committable_view_is_signed(3));
        // Config error maps back to VERIFYING, as does anything unknown.
        assert!(!committable_view_is_signed(4));
        assert!(!committable_view_is_signed(9));
    }

    #[test]
    fn deserializes_chained_address_list() {
        // Three addresses fit in one 1023-bit cell only twice, so the third
        // must be reachable through the chained reference.
        let tail = address_list(&[addr(0x33)]);
        let mut b = builder();
        b.write_num(&BigUint::from_bytes_be(&addr(0x11)), 256)
            .unwrap();
        b.write_num(&BigUint::from_bytes_be(&addr(0x22)), 256)
            .unwrap();
        b.write_ref(tail).unwrap();
        let head = build(b).unwrap();

        assert_eq!(
            deserialize_address_list(&head).unwrap(),
            vec![addr(0x11), addr(0x22), addr(0x33)]
        );
    }

    #[test]
    fn effective_dvns_fall_back_to_the_default_config_per_half() {
        let custom = receive_config(None, Some(&[addr(0xaa)]));
        let default = receive_config(Some(&[addr(0xbb)]), Some(&[addr(0xcc)]));
        // required is null -> default's required; optional is set -> custom's.
        assert_eq!(
            effective_receive_dvns(&custom, &default).unwrap(),
            vec![addr(0xaa), addr(0xbb)]
        );
    }

    #[test]
    fn effective_dvns_reject_a_config_null_on_both_sides() {
        let custom = receive_config(None, Some(&[addr(0xaa)]));
        let default = receive_config(None, Some(&[addr(0xcc)]));
        let err = effective_receive_dvns(&custom, &default).unwrap_err();
        assert!(err.to_string().contains("requiredDVNs missing"));
    }

    #[test]
    fn dvn_attestation_matches_the_packet_hash() {
        let verifier = addr(0xaa);
        let packet_hash = addr(0x77);
        let inner = single_key_dict(&verifier, attestation(&packet_hash));
        let storage = connection_storage(
            single_key_dict(&nonce_key(7), inner),
            receive_config(Some(&[verifier]), Some(&[])),
        );
        let default = receive_config(Some(&[]), Some(&[]));

        assert_eq!(
            dvn_attestation(&storage, &default, 7, &verifier, &packet_hash).unwrap(),
            DvnAttestation::Matches
        );
        // A different packet for the same nonce/DVN is not an attestation.
        assert_eq!(
            dvn_attestation(&storage, &default, 7, &verifier, &addr(0x78)).unwrap(),
            DvnAttestation::Absent
        );
        // An unattested nonce short-circuits before the receive-config check.
        assert_eq!(
            dvn_attestation(&storage, &default, 8, &verifier, &packet_hash).unwrap(),
            DvnAttestation::Absent
        );
    }

    #[test]
    fn dvn_outside_the_receive_config_short_circuits() {
        let verifier = addr(0xaa);
        let packet_hash = addr(0x77);
        let inner = single_key_dict(&verifier, attestation(&packet_hash));
        let storage = connection_storage(
            single_key_dict(&nonce_key(7), inner),
            // Configured DVNs do not include the verifier.
            receive_config(Some(&[addr(0xbb)]), Some(&[])),
        );
        let default = receive_config(Some(&[]), Some(&[]));

        assert_eq!(
            dvn_attestation(&storage, &default, 7, &verifier, &packet_hash).unwrap(),
            DvnAttestation::NotInReceiveConfig
        );
    }

    /// The runtime crate's TON payload-signed tests drive a fake transport with
    /// storage BOCs, so they cannot call these private builders. They embed the
    /// base64 below instead; this test is the producer and keeps the two copies
    /// from drifting apart.
    #[test]
    fn runtime_storage_fixtures_are_stable() {
        use super::super::cell::boc_to_base64;
        let verifier = addr(0xaa);

        let attested = connection_storage(
            single_key_dict(
                &nonce_key(7),
                single_key_dict(&verifier, attestation(&addr(0x77))),
            ),
            receive_config(Some(&[verifier]), Some(&[])),
        );
        assert_eq!(
            boc_to_base64(&attested).unwrap(),
            FIXTURE_ATTESTED_CONNECTION
        );

        let empty = connection_storage(
            build(builder()).unwrap(),
            receive_config(Some(&[verifier]), Some(&[])),
        );
        assert_eq!(boc_to_base64(&empty).unwrap(), FIXTURE_EMPTY_CONNECTION);

        let foreign_dvn = connection_storage(
            single_key_dict(
                &nonce_key(7),
                single_key_dict(&verifier, attestation(&addr(0x77))),
            ),
            receive_config(Some(&[addr(0xbb)]), Some(&[])),
        );
        assert_eq!(
            boc_to_base64(&foreign_dvn).unwrap(),
            FIXTURE_FOREIGN_DVN_CONNECTION
        );

        let uln = cl_declare(
            "uln",
            vec![
                ClField::Ref(build(builder()).unwrap()), // baseStorage
                ClField::uint(T_UINT32, 0u32),           // eid
                ClField::uint(T_UINT32, 0u32),           // dstEid
                ClField::Ref(receive_config(Some(&[]), Some(&[]))), // defaultUlnReceiveConfig
                ClField::Ref(build(builder()).unwrap()), // defaultUlnSendConfig
                ClField::Ref(build(builder()).unwrap()), // connectionCode
                ClField::Ref(build(builder()).unwrap()), // workerFeelibInfos
                ClField::uint(T_UINT16, 0u32),           // treasuryFeeBps
                ClField::uint(T_UINT16, 0u32),           // remainingWorkerSlots
                ClField::uint(T_UINT16, 0u32),           // remainingAdminWorkerSlots
            ],
        )
        .unwrap();
        assert_eq!(boc_to_base64(&uln).unwrap(), FIXTURE_ULN_STORAGE);
    }

    #[test]
    fn empty_hash_lookups_dictionary_is_absent() {
        let storage = connection_storage(
            build(builder()).unwrap(),
            receive_config(Some(&[addr(0xaa)]), Some(&[])),
        );
        let default = receive_config(Some(&[]), Some(&[]));
        assert_eq!(
            dvn_attestation(&storage, &default, 7, &addr(0xaa), &addr(0x77)).unwrap(),
            DvnAttestation::Absent
        );
    }
}
