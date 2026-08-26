mod base;
mod chains;
mod hash;
mod kind;

pub use base::{ChainAddress, PillarSignerAdapter, SignerInfo};
pub use chains::{
    AptosChain, EvmAddressChain, EvmChain, InitiaChain, PlainChain, SolanaChain, SuiChain, TonChain,
};
pub use kind::PillarSignerAdapterKind;

pub(crate) use hash::{
    bytes_to_hex, compress_ecdsa_public_key, ethers_hash_message, evm_address_from_public_key,
    evm_signer_info_public_key, strip_public_key_prefix, ton_public_key_cell_hash,
};

#[cfg(test)]
mod tests;
