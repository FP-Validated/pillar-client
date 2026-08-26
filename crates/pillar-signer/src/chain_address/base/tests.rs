use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::*;
use crate::chain_address::{evm_address_from_public_key, EvmChain, PlainChain, SolanaChain};
use crate::types::{ChainType, PublicKeyRequest, RawSignerAdapter, SignRequest, SignerError};

#[derive(Default)]
struct MockRawSigner {
    public_key_requests: Mutex<Vec<PublicKeyRequest>>,
    public_key: Option<Vec<u8>>,
}

#[async_trait]
impl RawSignerAdapter for MockRawSigner {
    async fn sign(&self, _request: SignRequest) -> Result<Vec<u8>, SignerError> {
        Ok(vec![0xab, 0xcd])
    }

    async fn get_public_key(&self, request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        self.public_key_requests.lock().await.push(request);
        Ok(self
            .public_key
            .clone()
            .unwrap_or_else(|| (1u8..=33).collect()))
    }
}

fn rust_azure_uncompressed_prefixed_public_key() -> Vec<u8> {
    let mut public_key = vec![0x04, 0xca, 0x11, 0xe4];
    public_key.extend(0x01..=0x3e);
    public_key
}

fn uncompressed_public_key() -> Vec<u8> {
    let mut public_key = vec![0x04, 0x11, 0xe4];
    public_key.extend(0x01..=0x3e);
    public_key
}

fn raw_public_key() -> Vec<u8> {
    let mut public_key = vec![0x11, 0xe4];
    public_key.extend(0x01..=0x3e);
    public_key
}

fn non_exact_66_byte_public_key(first: u8, second: u8) -> Vec<u8> {
    let mut public_key = vec![first, second, 0x11, 0xe4];
    public_key.extend(0x01..=0x3e);
    public_key
}

fn upstream_public_key_hex() -> &'static str {
    "0x11e40102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e"
}

#[tokio::test]
async fn pillar_sign_prefixes_signature_and_caches_address() {
    let raw = Arc::new(MockRawSigner::default());
    let signer = PillarSignerAdapter::new(raw.clone(), PlainChain(ChainType::Aptos), false);
    let first = signer.pillar_sign(&[1, 2, 3]).await.unwrap();
    let second = signer.pillar_sign(&[4, 5, 6]).await.unwrap();
    assert_eq!(first.signature, "0xabcd");
    assert_eq!(first.address, second.address);
    assert_eq!(raw.public_key_requests.lock().await.len(), 1);
}

#[tokio::test]
async fn signer_info_strips_public_key_prefix_like_typescript() {
    let raw = Arc::new(MockRawSigner::default());
    let signer = PillarSignerAdapter::new(raw, PlainChain(ChainType::Aptos), false);
    let info = signer.get_signer_info().await.unwrap();
    assert_eq!(
        info.public_key,
        "0x02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"
    );
}

#[tokio::test]
async fn signer_info_strips_rust_azure_uncompressed_prefix_like_upstream() {
    let raw = Arc::new(MockRawSigner {
        public_key_requests: Mutex::default(),
        public_key: Some(rust_azure_uncompressed_prefixed_public_key()),
    });
    let signer = PillarSignerAdapter::new(raw, EvmChain, true);
    let info = signer.get_signer_info().await.unwrap();

    assert_eq!(info.public_key, upstream_public_key_hex());
}

#[tokio::test]
async fn signer_info_derives_evm_address_from_rust_azure_uncompressed_prefix_like_upstream() {
    let public_key = rust_azure_uncompressed_prefixed_public_key();
    let expected_address = evm_address_from_public_key(&public_key[2..]).unwrap();
    let raw = Arc::new(MockRawSigner {
        public_key_requests: Mutex::default(),
        public_key: Some(public_key),
    });
    let signer = PillarSignerAdapter::new(raw, EvmChain, true);
    let info = signer.get_signer_info().await.unwrap();

    assert_eq!(info.address, expected_address);
    assert_eq!(info.address.len(), 42);
    assert_eq!(info.public_key, upstream_public_key_hex());
}

#[tokio::test]
async fn signer_info_preserves_kms_uncompressed_public_key_body() {
    let raw = Arc::new(MockRawSigner {
        public_key_requests: Mutex::default(),
        public_key: Some(uncompressed_public_key()),
    });
    let signer = PillarSignerAdapter::new(raw, EvmChain, true);
    let info = signer.get_signer_info().await.unwrap();

    assert_eq!(info.public_key, upstream_public_key_hex());
}

#[tokio::test]
async fn signer_info_strips_only_solana_azure_sec1_prefix() {
    let mut public_key = vec![0x04, 0xca];
    public_key.extend(0x11u8..=0x4f);
    let raw = Arc::new(MockRawSigner {
        public_key_requests: Mutex::default(),
        public_key: Some(public_key),
    });
    let signer = PillarSignerAdapter::new(raw, SolanaChain, true);
    let info = signer.get_signer_info().await.unwrap();

    assert_eq!(
        info.public_key,
        "0xca1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    );
}

#[test]
fn evm_address_accepts_raw_uncompressed_and_live_azure_public_key_shapes() {
    let raw_key = raw_public_key();
    let uncompressed_key = uncompressed_public_key();
    let live_key = rust_azure_uncompressed_prefixed_public_key();

    let expected = evm_address_from_public_key(&raw_key).unwrap();
    assert_eq!(
        evm_address_from_public_key(&uncompressed_key).unwrap(),
        expected
    );
    assert_eq!(evm_address_from_public_key(&live_key).unwrap(), expected);
}

#[tokio::test]
async fn signer_info_rejects_non_exact_66_byte_evm_public_key_vectors() {
    let expected_error = SignerError::Message(
        "ECDSA public key must be 64 raw bytes or 65 uncompressed bytes, got 66".to_string(),
    );

    for (label, public_key) in [
        (
            "uncompressed_with_wrong_second_byte",
            non_exact_66_byte_public_key(0x04, 0xcb),
        ),
        (
            "wrong_uncompressed_prefix_with_second_byte",
            non_exact_66_byte_public_key(0x05, 0xca),
        ),
    ] {
        assert_eq!(public_key.len(), 66);
        let raw = Arc::new(MockRawSigner {
            public_key_requests: Mutex::default(),
            public_key: Some(public_key),
        });
        let signer = PillarSignerAdapter::new(raw, EvmChain, true);
        let error = signer.get_signer_info().await.unwrap_err();

        assert_eq!(error, expected_error);
        println!("qa_malformed_public_key {label} rejected_error={error}");
    }
}
