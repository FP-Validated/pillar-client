use super::*;

use pillar_metrics::PillarMetrics;
use tokio::sync::Mutex;

pub struct LocalMnemonicSignerGetter {
    pub(super) chain_type_by_chain_name: HashMap<String, ChainType>,
    pub(super) signer_factory: SignerAdapterFactory<LocalMnemonicRawSignerAdapterFactory>,
    pub(super) metrics: Arc<Mutex<PillarMetrics>>,
}

pub struct LocalMnemonicSignerAssembly {
    pub signer_getter: Arc<dyn SignerGetter>,
    pub signer_info: BTreeMap<String, Vec<SignerInfo>>,
}

pub struct KmsSignerAssembly {
    pub signer_getter: Arc<dyn SignerGetter>,
    pub signer_info: BTreeMap<String, Vec<SignerInfo>>,
}

pub struct RuntimeSignerAssembly {
    pub signer_getter: Arc<dyn SignerGetter>,
    pub signer_info: BTreeMap<String, Vec<SignerInfo>>,
}
