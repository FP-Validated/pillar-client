use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureType {
    Ecdsa,
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedKind {
    Bip39,
    Ton,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainType {
    Aptos,
    Evm,
    Tron,
    Initia,
    Solana,
    IotaMove,
    Sui,
    Ton,
    Starknet,
    Stellar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub data: Vec<u8>,
    pub signature_type: SignatureType,
    pub private_key_signature_type: SignatureType,
    pub transform_recovery_id: bool,
    pub seed_kind: SeedKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyRequest {
    pub signature_type: SignatureType,
    pub private_key_signature_type: SignatureType,
    pub seed_kind: SeedKind,
}

#[async_trait]
pub trait RawSignerAdapter: Send + Sync + 'static {
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError>;
    async fn get_public_key(&self, request: PublicKeyRequest) -> Result<Vec<u8>, SignerError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMnemonic {
    pub mnemonic: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmsProvider {
    Aws,
    Gcp,
    Azure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletSignerKind {
    Mnemonic,
    Kms { provider: KmsProvider },
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTypeWalletDefinition {
    pub secret_name: String,
    pub signer_kind: Option<WalletSignerKind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletDefinition {
    pub name: String,
    pub by_chain_type: HashMap<ChainType, ChainTypeWalletDefinition>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignerError {
    #[error("{0}")]
    Message(String),
    #[error("Unsupported chain type: {0:?}")]
    UnsupportedChainType(ChainType),
    #[error("SignerAdapter: Duplicate wallet definition found for {0}")]
    DuplicateWalletDefinition(String),
    #[error("Wallet definition not found for {0}")]
    WalletDefinitionNotFound(String),
    #[error("Chain type wallet definition not found for {0:?}")]
    ChainTypeWalletDefinitionNotFound(ChainType),
    #[error("GCP credentials are not set")]
    GcpCredentialsNotSet,
    #[error("Azure credentials are not set")]
    AzureCredentialsNotSet,
    #[error("Unsupported KMS provider: {0:?}")]
    UnsupportedKmsProvider(KmsProvider),
    #[error("Unsupported signer type for {0}")]
    UnsupportedSignerType(String),
}

pub(crate) fn chain_type_ts_name(chain_type: ChainType) -> &'static str {
    match chain_type {
        ChainType::Aptos => "APTOS",
        ChainType::Evm => "EVM",
        ChainType::Tron => "TRON",
        ChainType::Initia => "INITIA",
        ChainType::Solana => "SOLANA",
        ChainType::IotaMove => "IOTAMOVE",
        ChainType::Sui => "SUI",
        ChainType::Ton => "TON",
        ChainType::Starknet => "STARKNET",
        ChainType::Stellar => "STELLAR",
    }
}

#[async_trait]
impl<T> RawSignerAdapter for Arc<T>
where
    T: RawSignerAdapter + ?Sized,
{
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        (**self).sign(request).await
    }

    async fn get_public_key(&self, request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        (**self).get_public_key(request).await
    }
}
