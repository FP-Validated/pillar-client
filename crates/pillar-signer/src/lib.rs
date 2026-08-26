mod aws;
mod azure;
mod chain_address;
mod factory;
mod gcp;
mod kms_signature;
mod local_mnemonic;
mod types;

pub use aws::{
    AwsKmsClient, AwsKmsRawSignerAdapter, AwsKmsRawSignerAdapterFactory, AwsSdkKmsClient,
};
pub use azure::{
    parse_azure_kms_key_id, AzureKeyVaultKmsClient, AzureKmsClient, AzureKmsKeyId,
    AzureKmsRawSignerAdapter, AzureKmsRawSignerAdapterFactory,
};
pub use chain_address::{
    AptosChain, ChainAddress, EvmAddressChain, EvmChain, InitiaChain, PillarSignerAdapter,
    PillarSignerAdapterKind, PlainChain, SignerInfo, SolanaChain, SuiChain, TonChain,
};
pub use factory::{RawSignerAdapterFactory, SignerAdapterFactory};
pub use gcp::{
    GcpKmsClient, GcpKmsOptions, GcpKmsRawSignerAdapter, GcpKmsRawSignerAdapterFactory,
    GoogleCloudKmsClient,
};
pub use kms_signature::{kms_ecdsa_signature_to_recoverable, KmsEcdsaSignatureEncoding};
pub use local_mnemonic::{LocalMnemonicRawSignerAdapter, LocalMnemonicRawSignerAdapterFactory};
pub use types::{
    ChainType, ChainTypeWalletDefinition, KmsProvider, LocalMnemonic, PublicKeyRequest,
    RawSignerAdapter, SeedKind, SignRequest, SignatureType, SignerError, WalletDefinition,
    WalletSignerKind,
};

#[cfg(test)]
include!("unsupported_signature_type_tests.rs");
