use crate::solana::{
    solana_payload_signed_accounts, solana_uln_is_valid_receive_library, SolanaPayloadSignedRequest,
};

/// Anchor's `ReceiveLibraryConfig` discriminator, `sha256("account:ReceiveLibraryConfig")[..8]`.
const DISCRIMINATOR: &str = "8ee2fb8a01ce5bc1";
/// The message-library PDA of the pinned ULN program (`2XgGZG4oP29U3w5h4nTk1V2LFHL23zKDPJjs3psGzLKQ`).
const ULN_LIB: &str = "16b7830c3f8a44c810ca87de56e032889c358ec75d4732bf7361862658acb2af";
const OTHER_LIB: &str = "2515806648630228f165e86b6a6e0469117511850390dcf03f5bb7dd2f9b92f6";
const ZERO_LIB: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Accounts as the endpoint program holds them on mainnet (read 2026-11-02), 82 bytes each:
/// the default config for srcEid 30101, and three per-receiver configs.
fn padded(prefix_hex: &str) -> Vec<u8> {
    let mut bytes = hex::decode(prefix_hex).unwrap();
    bytes.resize(82, 0);
    bytes
}

fn mainnet_default_30101() -> Vec<u8> {
    padded(&format!("{DISCRIMINATOR}{ULN_LIB}00fd"))
}

/// `13QUNXwjeAd7wHgoSEx36ZAfbCSon1BveXkZ6VrefFvo`: the receiver follows the default.
fn mainnet_receiver_on_default() -> Vec<u8> {
    padded(&format!("{DISCRIMINATOR}{ZERO_LIB}00ff"))
}

/// `1rCHYQ3FomhLqE95o2Lge1mrsqa9HqJUXsmTc7dB1to`: the receiver names the ULN itself.
fn mainnet_receiver_on_uln() -> Vec<u8> {
    padded(&format!("{DISCRIMINATOR}{ULN_LIB}00fc"))
}

/// `i4JEGjvJ992JyWTNZHkJXnKcG6HLXTRhioe8SdrjmZq`: the receiver names another library.
fn mainnet_receiver_on_other_library() -> Vec<u8> {
    padded(&format!("{DISCRIMINATOR}{OTHER_LIB}00fd"))
}

/// The layout with a grace period, from the endpoint source (`state/message_lib.rs`):
/// message_lib, `Option<ReceiveLibraryTimeout { message_lib, expiry }>`, bump.
fn config_with_timeout(message_lib: &str, timeout: (&str, u64)) -> Vec<u8> {
    let mut bytes = hex::decode(format!("{DISCRIMINATOR}{message_lib}01{}", timeout.0)).unwrap();
    bytes.extend_from_slice(&timeout.1.to_le_bytes());
    bytes.push(254);
    bytes
}

fn config(message_lib: &str) -> Vec<u8> {
    padded(&format!("{DISCRIMINATOR}{message_lib}00fe"))
}

fn valid(receiver: Option<&[u8]>, default: Option<&[u8]>, slot: u64) -> bool {
    solana_uln_is_valid_receive_library(receiver, default, slot).unwrap()
}

#[test]
fn a_receiver_following_the_default_or_naming_the_uln_receives_on_the_uln() {
    let default = mainnet_default_30101();
    assert!(valid(
        Some(&mainnet_receiver_on_default()),
        Some(&default),
        1
    ));
    assert!(valid(Some(&mainnet_receiver_on_uln()), Some(&default), 1));
}

#[test]
fn a_receiver_on_another_library_does_not_receive_on_the_uln() {
    let default = mainnet_default_30101();
    assert!(!valid(
        Some(&mainnet_receiver_on_other_library()),
        Some(&default),
        1
    ));
}

#[test]
fn a_receiver_following_a_default_that_is_not_the_uln_does_not_receive_on_the_uln() {
    assert!(!valid(
        Some(&mainnet_receiver_on_default()),
        Some(&config(OTHER_LIB)),
        1
    ));
}

#[test]
fn the_replaced_library_is_valid_until_its_grace_period_ends() {
    let receiver = config_with_timeout(OTHER_LIB, (ULN_LIB, 100));
    let default = mainnet_default_30101();
    assert!(valid(Some(&receiver), Some(&default), 99));
    assert!(!valid(Some(&receiver), Some(&default), 100));
    assert!(!valid(Some(&receiver), Some(&default), 101));
}

#[test]
fn a_grace_period_only_covers_the_library_it_names() {
    let receiver = config_with_timeout(OTHER_LIB, (ZERO_LIB, 100));
    assert!(!valid(Some(&receiver), Some(&mainnet_default_30101()), 1));
}

#[test]
fn the_default_grace_period_applies_to_a_receiver_on_the_default_only() {
    let default = config_with_timeout(OTHER_LIB, (ULN_LIB, 100));
    assert!(valid(
        Some(&mainnet_receiver_on_default()),
        Some(&default),
        99
    ));
    assert!(!valid(
        Some(&mainnet_receiver_on_default()),
        Some(&default),
        100
    ));
    assert!(!valid(
        Some(&mainnet_receiver_on_other_library()),
        Some(&default),
        99
    ));
}

#[test]
fn the_endpoint_cannot_verify_without_both_configs() {
    let default = mainnet_default_30101();
    assert!(!valid(None, Some(&default), 1));
    assert!(!valid(Some(&mainnet_receiver_on_uln()), None, 1));
}

#[test]
fn a_config_that_is_not_a_receive_library_config_is_an_error() {
    let default = mainnet_default_30101();
    let mut wrong_discriminator = mainnet_receiver_on_uln();
    wrong_discriminator[0] ^= 1;
    let mut bad_option_tag = mainnet_receiver_on_uln();
    bad_option_tag[40] = 2;
    for bad in [
        wrong_discriminator,
        bad_option_tag,
        mainnet_receiver_on_uln()[..39].to_vec(),
    ] {
        assert!(solana_uln_is_valid_receive_library(Some(&bad), Some(&default), 1).is_err());
    }
}

#[test]
fn library_config_pdas_match_the_endpoint_derivation() {
    let receiver = bs58::decode("6td1W4vFnQsKKunmKprARgpMEtYdVBnZ2FVcpqxKxaoA")
        .into_vec()
        .unwrap();
    let request = SolanaPayloadSignedRequest {
        receiver: receiver.try_into().unwrap(),
        sender: [1; 32],
        src_eid: 40231,
        nonce: 7,
        header_hash: [0x11; 32],
        payload_hash: [0x22; 32],
        dvn: [3; 32],
    };
    let accounts = solana_payload_signed_accounts(&request).unwrap();
    assert_eq!(
        bs58::encode(accounts.library_config_pda).into_string(),
        "G5XxdUJr14FGEPcb8dKYdRinw8hfmxMUZmUN73piyWza"
    );
    assert_eq!(
        bs58::encode(accounts.default_library_config_pda).into_string(),
        "HjDEd9BGQnuJFkmhFyWyrcVWwV84cqU8RCST27STjs7H"
    );
    let on_mainnet = SolanaPayloadSignedRequest {
        src_eid: 30101,
        ..request
    };
    assert_eq!(
        bs58::encode(
            solana_payload_signed_accounts(&on_mainnet)
                .unwrap()
                .default_library_config_pda
        )
        .into_string(),
        "CWLmnfujBmXmp24oGc7yhNUFnuYm6x6DZc4fJ5tumDVu",
        "the address the mainnet default config for srcEid 30101 was read from"
    );
}
