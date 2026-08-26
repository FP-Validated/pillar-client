use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::*;
use crate::types::{
    PublicKeyRequest, RawSignerAdapter, SeedKind, SignRequest, SignatureType, SignerError,
};

#[derive(Default)]
struct MockRawSigner {
    sign_requests: Mutex<Vec<SignRequest>>,
}

#[async_trait]
impl RawSignerAdapter for MockRawSigner {
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        self.sign_requests.lock().await.push(request);
        Ok(vec![0xab, 0xcd])
    }

    async fn get_public_key(&self, _request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        Ok((1u8..=33).collect())
    }
}

struct EvmPublicKeySigner {
    sign_requests: Mutex<Vec<SignRequest>>,
    public_key: Vec<u8>,
}

#[async_trait]
impl RawSignerAdapter for EvmPublicKeySigner {
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        self.sign_requests.lock().await.push(request);
        Ok(vec![0xab, 0xcd])
    }

    async fn get_public_key(&self, _request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        Ok(self.public_key.clone())
    }
}

struct RequestAwarePublicKeySigner {
    sign_requests: Mutex<Vec<SignRequest>>,
    public_key_requests: Mutex<Vec<PublicKeyRequest>>,
    ecdsa_public_key: Vec<u8>,
}

#[async_trait]
impl RawSignerAdapter for RequestAwarePublicKeySigner {
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        self.sign_requests.lock().await.push(request);
        Ok(vec![0xab, 0xcd])
    }

    async fn get_public_key(&self, request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        self.public_key_requests.lock().await.push(request);
        Ok(self.ecdsa_public_key.clone())
    }
}

fn ecdsa_public_key_a() -> Vec<u8> {
    hex::decode(concat!(
        "04",
        "8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
        "3547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
    ))
    .unwrap()
}

fn ecdsa_public_key_b() -> Vec<u8> {
    hex::decode(concat!(
        "04",
        "9d8a62f656a8d1615c1294fd71e9cfb3e4855fb85e459356b9c0e60fa8dc226c",
        "eaedcd6f06036bfd25e4a4d14fc02ddfe4e7b67713d4ba302247c6e0f34a8085"
    ))
    .unwrap()
}

#[tokio::test]
async fn solana_uses_ed25519_for_non_kms_and_ecdsa_for_kms() {
    let raw = Arc::new(MockRawSigner::default());
    let signer = PillarSignerAdapter::new(raw.clone(), SolanaChain, false);
    signer.pillar_sign(&[1]).await.unwrap();
    assert_eq!(
        raw.sign_requests.lock().await[0].private_key_signature_type,
        SignatureType::Ed25519
    );

    let raw = Arc::new(MockRawSigner::default());
    let signer = PillarSignerAdapter::new(raw.clone(), SolanaChain, true);
    signer.pillar_sign(&[1]).await.unwrap();
    assert_eq!(
        raw.sign_requests.lock().await[0].private_key_signature_type,
        SignatureType::Ecdsa
    );
}

#[tokio::test]
async fn aptos_uses_ed25519_private_key_for_local_signing_but_ecdsa_for_address() {
    let raw = Arc::new(RequestAwarePublicKeySigner {
        sign_requests: Mutex::new(Vec::new()),
        public_key_requests: Mutex::new(Vec::new()),
        ecdsa_public_key: ecdsa_public_key_a(),
    });
    let signer = PillarSignerAdapter::new(raw.clone(), AptosChain, false);
    let signature = signer.pillar_sign(&[1]).await.unwrap();

    assert_eq!(
        signature.address,
        "0xb459a8bef24fe3598be8b968c8e632b7992babdecfb026a80399104c8c3cd739"
    );
    assert_eq!(
        raw.sign_requests.lock().await[0].private_key_signature_type,
        SignatureType::Ed25519
    );
    assert_eq!(
        raw.public_key_requests.lock().await[0].private_key_signature_type,
        SignatureType::Ecdsa
    );
}

#[tokio::test]
async fn sui_uses_ed25519_private_key_for_local_signing_but_ecdsa_for_address() {
    let raw = Arc::new(RequestAwarePublicKeySigner {
        sign_requests: Mutex::new(Vec::new()),
        public_key_requests: Mutex::new(Vec::new()),
        ecdsa_public_key: ecdsa_public_key_a(),
    });
    let signer = PillarSignerAdapter::new(raw.clone(), SuiChain, false);
    let signature = signer.pillar_sign(&[1]).await.unwrap();

    assert_eq!(
        signature.address,
        "0x548572c05b35e9db5effdc688f3eae066d71297983c269299a30bd22357eef6d"
    );
    assert_eq!(
        raw.sign_requests.lock().await[0].private_key_signature_type,
        SignatureType::Ed25519
    );
    assert_eq!(
        raw.public_key_requests.lock().await[0].private_key_signature_type,
        SignatureType::Ecdsa
    );
}

#[tokio::test]
async fn ton_uses_ton_seed_and_ed25519_private_key_for_local_signing() {
    let raw = Arc::new(RequestAwarePublicKeySigner {
        sign_requests: Mutex::new(Vec::new()),
        public_key_requests: Mutex::new(Vec::new()),
        ecdsa_public_key: hex::decode(concat!(
            "04",
            "82b8ed2f423ff8aa6fba75cbd4cc272e2abd2dd9fea53705d383706730bd7d75",
            "7271129607204ff3f52b72567d5be8e760bd89be920bda0bf5228d2c6b737b3d"
        ))
        .unwrap(),
    });
    let signer = PillarSignerAdapter::new(raw.clone(), TonChain, false);
    let signature = signer.pillar_sign(&[1]).await.unwrap();

    assert_eq!(
        signature.address,
        "0xc0fa29d67e6f5734c6be1da067fe00c898fe6aa8f5e01eaa73ca589fd41442a5"
    );
    assert_eq!(
        raw.sign_requests.lock().await[0].private_key_signature_type,
        SignatureType::Ed25519
    );
    assert_eq!(raw.sign_requests.lock().await[0].seed_kind, SeedKind::Ton);
    assert_eq!(
        raw.public_key_requests.lock().await[0].seed_kind,
        SeedKind::Ton
    );
}

#[test]
fn evm_prepare_data_matches_ethers_hash_message_vector() {
    assert_eq!(
        bytes_to_hex(&ethers_hash_message(b"hello")),
        "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750"
    );
    assert_eq!(
        bytes_to_hex(&EvmChain.prepare_data(&[1, 2, 3])),
        "bcf83051a4d206c6e43d7eaa4c75429737ac0d5ee08ee68430443bd815e6ac05"
    );
}

#[test]
fn evm_address_from_public_key_matches_ethereum_vector() {
    let public_key = ecdsa_public_key_b();
    assert_eq!(
        evm_address_from_public_key(&public_key).unwrap(),
        "0x7BB33FfA20aD26F1e60F96dC2C9d27C12d864c41"
    );
    assert_eq!(
        evm_address_from_public_key(&public_key[1..]).unwrap(),
        "0x7BB33FfA20aD26F1e60F96dC2C9d27C12d864c41"
    );
}

#[test]
fn evm_signer_info_public_key_matches_upstream_for_azure_uncompressed_key() {
    let public_key = ecdsa_public_key_a();
    assert_eq!(
        format!(
            "0x{}",
            bytes_to_hex(evm_signer_info_public_key(&public_key, true))
        ),
        "0x8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
    );
}

#[test]
fn evm_address_chain_matches_starknet_and_stellar_ts_address_rule() {
    assert_eq!(
        EvmAddressChain
            .signer_address(&ecdsa_public_key_b())
            .unwrap(),
        "0x7BB33FfA20aD26F1e60F96dC2C9d27C12d864c41"
    );
}

#[test]
fn aptos_address_from_ecdsa_public_key_matches_typescript_vector() {
    assert_eq!(
        AptosChain.signer_address(&ecdsa_public_key_a()).unwrap(),
        "0xb459a8bef24fe3598be8b968c8e632b7992babdecfb026a80399104c8c3cd739"
    );
}

#[test]
fn sui_address_from_ecdsa_public_key_matches_typescript_vector() {
    let public_key = ecdsa_public_key_a();
    assert_eq!(
        SuiChain.signer_address(&public_key).unwrap(),
        "0x548572c05b35e9db5effdc688f3eae066d71297983c269299a30bd22357eef6d"
    );
    assert_eq!(
        bytes_to_hex(&compress_ecdsa_public_key(&public_key).unwrap()),
        "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75"
    );
}

#[test]
fn initia_address_from_ecdsa_public_key_matches_typescript_vector() {
    let public_key = ecdsa_public_key_a();
    assert_eq!(
        InitiaChain.signer_address(&public_key).unwrap(),
        "init15428vq2uzwhm3taey9sr9x5vm6tk78ewhz4v9m"
    );
    assert_eq!(
        bytes_to_hex(&compress_ecdsa_public_key(&public_key).unwrap()),
        "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75"
    );
}

#[test]
fn ton_address_from_ecdsa_public_key_matches_typescript_vector() {
    let public_key = hex::decode(concat!(
        "04",
        "82b8ed2f423ff8aa6fba75cbd4cc272e2abd2dd9fea53705d383706730bd7d75",
        "7271129607204ff3f52b72567d5be8e760bd89be920bda0bf5228d2c6b737b3d"
    ))
    .unwrap();

    assert_eq!(
        TonChain.signer_address(&public_key).unwrap(),
        "0xc0fa29d67e6f5734c6be1da067fe00c898fe6aa8f5e01eaa73ca589fd41442a5"
    );
    assert_eq!(
        bytes_to_hex(&ton_public_key_cell_hash(&public_key[1..]).unwrap()),
        "c0fa29d67e6f5734c6be1da067fe00c898fe6aa8f5e01eaa73ca589fd41442a5"
    );
}

#[tokio::test]
async fn evm_address_only_chains_do_not_hash_or_transform_signatures() {
    let raw = Arc::new(EvmPublicKeySigner {
        sign_requests: Mutex::new(Vec::new()),
        public_key: ecdsa_public_key_b(),
    });
    let signer = PillarSignerAdapter::new(raw.clone(), EvmAddressChain, false);
    signer.pillar_sign(&[1, 2, 3]).await.unwrap();
    let requests = raw.sign_requests.lock().await;
    assert_eq!(requests[0].data, vec![1, 2, 3]);
    assert_eq!(requests[0].signature_type, SignatureType::Ecdsa);
    assert_eq!(requests[0].private_key_signature_type, SignatureType::Ecdsa);
    assert!(!requests[0].transform_recovery_id);
}

#[test]
fn solana_address_is_base58_first_32_public_key_bytes() {
    let public_key = (1u8..=33).collect::<Vec<_>>();
    assert_eq!(
        SolanaChain.signer_address(&public_key).unwrap(),
        "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw"
    );
}

#[test]
fn solana_address_matches_upstream_for_azure_uncompressed_key() {
    assert_eq!(
        SolanaChain.signer_address(&ecdsa_public_key_a()).unwrap(),
        "9pjvUx5h2dQUrj76Gqmwe24PXPHW3eWFGBuUgVW5BVPS"
    );
}

#[test]
fn solana_signer_info_preserves_first_coordinate_byte_for_azure_uncompressed_key() {
    let mut public_key = vec![0x04, 0xca];
    public_key.extend(0x11u8..=0x4f);

    assert_eq!(
        SolanaChain.signer_info_public_key(&public_key, true),
        &public_key[1..]
    );
}

#[tokio::test]
async fn solana_signer_info_preserves_raw_coordinate_bytes_without_sec1_prefix() {
    let upstream_public_key = hex::decode(concat!(
        "11e4b7d37870aca2ace4d5dee1dd296e6d76c7ff757c648d41f1e65d495d7408",
        "97f8edc07fea309c99494ab3f2115c27f1f8aca0d0843ce485e6266ed351f1"
    ))
    .unwrap();
    let mut live_azure_public_key = Vec::with_capacity(65);
    live_azure_public_key.push(0xca);
    live_azure_public_key.extend_from_slice(&upstream_public_key);
    let raw = Arc::new(EvmPublicKeySigner {
        sign_requests: Mutex::new(Vec::new()),
        public_key: live_azure_public_key,
    });
    let signer = PillarSignerAdapter::new(raw, SolanaChain, true);

    let signer_info = signer.get_signer_info().await.unwrap();

    assert_eq!(
        signer_info.address,
        "EboBSUoobiqt7JYcH46ro7TGBjtE2vczKnUmsiWy6Ffy"
    );
    assert_eq!(
        signer_info.public_key,
        format!("0xca{}", bytes_to_hex(&upstream_public_key))
    );
}

#[tokio::test]
async fn solana_signer_info_preserves_all_64_azure_coordinate_bytes() {
    let upstream_public_key = hex::decode(concat!(
        "ca11e4b7d37870aca2ace4d5dee1dd296e6d76c7ff757c648d41f1e65d495d",
        "740897f8edc07fea309c99494ab3f2115c27f1f8aca0d0843ce485e6266ed351f1"
    ))
    .unwrap();
    let mut live_azure_public_key = Vec::with_capacity(65);
    live_azure_public_key.push(0x04);
    live_azure_public_key.extend_from_slice(&upstream_public_key);
    let raw = Arc::new(EvmPublicKeySigner {
        sign_requests: Mutex::new(Vec::new()),
        public_key: live_azure_public_key,
    });
    let signer = PillarSignerAdapter::new(raw, SolanaChain, true);

    let signer_info = signer.get_signer_info().await.unwrap();

    assert_eq!(
        signer_info.address,
        "EboBSUoobiqt7JYcH46ro7TGBjtE2vczKnUmsiWy6Ffy"
    );
    assert_eq!(
        signer_info.public_key,
        format!("0x{}", bytes_to_hex(&upstream_public_key))
    );
}
