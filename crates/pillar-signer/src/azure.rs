mod adapter;
mod client;
mod factory;
mod key_id;

pub use adapter::AzureKmsRawSignerAdapter;
pub use client::{AzureKeyVaultKmsClient, AzureKmsClient};
pub use factory::AzureKmsRawSignerAdapterFactory;
pub use key_id::{parse_azure_kms_key_id, AzureKmsKeyId};

#[cfg(test)]
mod hedge_tests;
#[cfg(test)]
mod tests;
