use crate::solana::solana_payload_signed_request;
use indexmap::IndexMap;
use pillar_core::{LzMessageId, LzSentEvent, PathwayId};
use serde_json::Value;

use crate::solana::{solana_payload_signed_accounts, SolanaPayloadSignedRequest};

fn synthetic_request() -> SolanaPayloadSignedRequest {
    let receiver_bytes = bs58::decode("6td1W4vFnQsKKunmKprARgpMEtYdVBnZ2FVcpqxKxaoA")
        .into_vec()
        .unwrap();
    let mut receiver = [0u8; 32];
    receiver.copy_from_slice(&receiver_bytes);

    let sender_raw = hex::decode("296216132c655e55a1281b2267e12a5b45b1bbb3").unwrap();
    let mut sender = [0u8; 32];
    sender[32 - sender_raw.len()..].copy_from_slice(&sender_raw);

    let dvn_bytes = bs58::decode("4gnov6q1KFcjtwBjepBmQtuf5R4ho4XVkrytY8hk4CTF")
        .into_vec()
        .unwrap();
    let mut dvn = [0u8; 32];
    dvn.copy_from_slice(&dvn_bytes);

    SolanaPayloadSignedRequest {
        receiver,
        sender,
        src_eid: 40231,
        nonce: 7,
        header_hash: [0x11u8; 32],
        payload_hash: [0x22u8; 32],
        dvn,
    }
}

/// Cross-checked against real `@solana/web3.js` `PublicKey.findProgramAddressSync`
/// with the exact same seeds as `@layerzerolabs/lz-solana-sdk-v2`'s
/// `EndpointPDA.nonce`/`pendingNonce` and `UlnPDA.confirmations`/`config`
/// (the upstream TypeScript service's vendored dependency), for
/// the real arbsep(40231)->solana receiver/dvn addresses used in the
/// 2026-07-14 live canary retest.
#[test]
fn solana_payload_signed_pdas_match_web3js_derivation() {
    let request = synthetic_request();
    let accounts = solana_payload_signed_accounts(&request).unwrap();

    assert_eq!(
        bs58::encode(accounts.nonce_pda).into_string(),
        "DDHyCLH3HNytVV4HseC2eex1Cpiv2LSQhZC7AkNh71Mn"
    );
    assert_eq!(
        bs58::encode(accounts.pending_nonce_pda).into_string(),
        "AEk1iFxUBjkm3uViMPUTyXm91z8xzn67uYcxkXxWuuZu"
    );
    assert_eq!(
        bs58::encode(accounts.receive_config_pda).into_string(),
        "37Yy4W7EhcWEC4yaj3uhkP5w8UY1VSj6D2QAbo4fSyuL"
    );
    assert_eq!(
        bs58::encode(accounts.default_receive_config_pda).into_string(),
        "BfYtqTpJSw5YztWdjgK8ED8L3dxMqFATApDMLk5YPrCe"
    );
    assert_eq!(
        bs58::encode(accounts.confirmations_pda).into_string(),
        "7PLaBbs4ctfBHP6V92XuKWvZNbB8pm5iLGade87YeKKv"
    );
}

use crate::solana::{solana_payload_is_signed, SolanaFetchedPayloadSignedAccounts};

const NONCE_DISCRIMINATOR: [u8; 8] = [143, 197, 147, 95, 106, 165, 50, 43];
const PENDING_INBOUND_NONCE_DISCRIMINATOR: [u8; 8] = [170, 176, 95, 240, 120, 231, 241, 218];
const RECEIVE_CONFIG_DISCRIMINATOR: [u8; 8] = [162, 159, 153, 188, 56, 65, 245, 58];
const CONFIRMATIONS_DISCRIMINATOR: [u8; 8] = [206, 57, 50, 8, 124, 133, 138, 112];

fn nonce_account_bytes(inbound_nonce: u64) -> Vec<u8> {
    let mut bytes = NONCE_DISCRIMINATOR.to_vec();
    bytes.push(0); // bump
    bytes.extend_from_slice(&0u64.to_le_bytes()); // outboundNonce (unused)
    bytes.extend_from_slice(&inbound_nonce.to_le_bytes());
    bytes
}

fn pending_inbound_nonce_account_bytes(nonces: &[u64]) -> Vec<u8> {
    let mut bytes = PENDING_INBOUND_NONCE_DISCRIMINATOR.to_vec();
    bytes.extend_from_slice(&(nonces.len() as u32).to_le_bytes());
    for nonce in nonces {
        bytes.extend_from_slice(&nonce.to_le_bytes());
    }
    bytes.push(0); // bump
    bytes
}

fn receive_config_account_bytes(confirmations: u64) -> Vec<u8> {
    let mut bytes = RECEIVE_CONFIG_DISCRIMINATOR.to_vec();
    bytes.push(0); // bump
    bytes.extend_from_slice(&confirmations.to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 0]); // requiredDvnCount, optionalDvnCount, optionalDvnThreshold
    bytes.extend_from_slice(&0u32.to_le_bytes()); // requiredDvns vec length
    bytes.extend_from_slice(&0u32.to_le_bytes()); // optionalDvns vec length
    bytes
}

fn confirmations_account_bytes(value: Option<u64>) -> Vec<u8> {
    let mut bytes = CONFIRMATIONS_DISCRIMINATOR.to_vec();
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    bytes.push(0); // bump
    bytes
}

#[test]
fn solana_payload_is_signed_true_when_already_delivered() {
    let request = synthetic_request();
    let nonce_data = nonce_account_bytes(request.nonce);
    let accounts = SolanaFetchedPayloadSignedAccounts {
        nonce: Some(&nonce_data),
        ..Default::default()
    };

    assert!(solana_payload_is_signed(&request, accounts).unwrap());
}

#[test]
fn solana_payload_is_signed_true_when_nonce_pending_commit() {
    let request = synthetic_request();
    let pending_data = pending_inbound_nonce_account_bytes(&[3, request.nonce, 9]);
    let accounts = SolanaFetchedPayloadSignedAccounts {
        pending_nonce: Some(&pending_data),
        ..Default::default()
    };

    assert!(solana_payload_is_signed(&request, accounts).unwrap());
}

#[test]
fn solana_payload_is_signed_true_when_dvn_confirmations_meet_threshold() {
    let request = synthetic_request();
    let default_config = receive_config_account_bytes(5);
    let confirmations = confirmations_account_bytes(Some(5));
    let accounts = SolanaFetchedPayloadSignedAccounts {
        default_receive_config: Some(&default_config),
        confirmations: Some(&confirmations),
        ..Default::default()
    };

    assert!(solana_payload_is_signed(&request, accounts).unwrap());
}

#[test]
fn solana_payload_is_signed_false_when_dvn_confirmations_below_threshold() {
    let request = synthetic_request();
    let default_config = receive_config_account_bytes(5);
    let confirmations = confirmations_account_bytes(Some(2));
    let accounts = SolanaFetchedPayloadSignedAccounts {
        default_receive_config: Some(&default_config),
        confirmations: Some(&confirmations),
        ..Default::default()
    };

    assert!(!solana_payload_is_signed(&request, accounts).unwrap());
}

#[test]
fn solana_payload_is_signed_false_when_confirmations_missing_or_zero() {
    let request = synthetic_request();
    let default_config = receive_config_account_bytes(5);

    let missing_accounts = SolanaFetchedPayloadSignedAccounts {
        default_receive_config: Some(&default_config),
        confirmations: None,
        ..Default::default()
    };
    assert!(!solana_payload_is_signed(&request, missing_accounts).unwrap());

    let zero = confirmations_account_bytes(Some(0));
    let zero_accounts = SolanaFetchedPayloadSignedAccounts {
        default_receive_config: Some(&default_config),
        confirmations: Some(&zero),
        ..Default::default()
    };
    assert!(!solana_payload_is_signed(&request, zero_accounts).unwrap());

    let none_value = confirmations_account_bytes(None);
    let none_accounts = SolanaFetchedPayloadSignedAccounts {
        default_receive_config: Some(&default_config),
        confirmations: Some(&none_value),
        ..Default::default()
    };
    assert!(!solana_payload_is_signed(&request, none_accounts).unwrap());
}

#[test]
fn solana_payload_is_signed_uses_custom_receive_config_over_default() {
    let request = synthetic_request();
    let default_config = receive_config_account_bytes(5);
    let custom_config = receive_config_account_bytes(1);
    let confirmations = confirmations_account_bytes(Some(1));
    let accounts = SolanaFetchedPayloadSignedAccounts {
        receive_config: Some(&custom_config),
        default_receive_config: Some(&default_config),
        confirmations: Some(&confirmations),
        ..Default::default()
    };

    // Custom config's lower threshold (1) is used instead of the default's
    // higher threshold (5); a confirmation value of 1 clears the custom bar.
    assert!(solana_payload_is_signed(&request, accounts).unwrap());
}

#[test]
fn solana_payload_is_signed_falls_back_to_default_when_custom_confirmations_unset() {
    let request = synthetic_request();
    let default_config = receive_config_account_bytes(5);
    let custom_config = receive_config_account_bytes(0); // unset -> fall back to default
    let confirmations = confirmations_account_bytes(Some(2));
    let accounts = SolanaFetchedPayloadSignedAccounts {
        receive_config: Some(&custom_config),
        default_receive_config: Some(&default_config),
        confirmations: Some(&confirmations),
        ..Default::default()
    };

    // Default threshold (5) applies since custom is unset (0); 2 < 5.
    assert!(!solana_payload_is_signed(&request, accounts).unwrap());
}

#[test]
fn solana_payload_is_signed_errors_without_default_receive_config() {
    let request = synthetic_request();
    let accounts = SolanaFetchedPayloadSignedAccounts::default();

    let error = solana_payload_is_signed(&request, accounts).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Default Solana ULN receive config not found"),
        "{error}"
    );
}

/// `EvmPacketSentResolver::decode_lz_packet_v1` always stores `receiver` as
/// a raw 32-byte `0x`-hex string decoded straight out of the on-chain
/// packet log (`format!("0x{}", hex::encode(&bytes[49..81]))`), even when
/// the destination is Solana — it never re-encodes into the destination
/// chain's native base58 format. `solana_payload_signed_request` must accept
/// that hex form directly (not just a base58 receiver a caller might supply
/// natively), since a raw 32-byte value decodes identically either way.
/// Regression for a 2026-07-14 live retest failure: `solana_payload_signed_request`
/// previously bs58-decoded `receiver` unconditionally and errored with
/// "invalid character '0' at byte 0" on this exact real resolver shape.
#[test]
fn solana_payload_signed_request_accepts_hex_receiver_from_real_resolver() {
    let receiver_bytes = bs58::decode("6td1W4vFnQsKKunmKprARgpMEtYdVBnZ2FVcpqxKxaoA")
        .into_vec()
        .unwrap();
    let sent_event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "arbsep".to_string(),
                dst_chain_name: "solana".to_string(),
                extra: IndexMap::from([
                    ("srcEid".to_string(), Value::from(40_231)),
                    ("dstEid".to_string(), Value::from(40_168)),
                    (
                        "sender".to_string(),
                        Value::from(format!(
                            "0x{}",
                            hex::encode(
                                [
                                    [0u8; 12].as_slice(),
                                    &hex::decode("296216132c655e55a1281b2267e12a5b45b1bbb3")
                                        .unwrap()
                                ]
                                .concat()
                            )
                        )),
                    ),
                    (
                        "receiver".to_string(),
                        // Real resolver shape: raw 32-byte hex, not base58.
                        Value::from(format!("0x{}", hex::encode(&receiver_bytes))),
                    ),
                ]),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: IndexMap::from([(
            "guid".to_string(),
            Value::from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        )]),
    };

    let request =
        solana_payload_signed_request(&sent_event, "4gnov6q1KFcjtwBjepBmQtuf5R4ho4XVkrytY8hk4CTF")
            .unwrap();

    assert_eq!(hex::encode(request.receiver), hex::encode(&receiver_bytes));
}
