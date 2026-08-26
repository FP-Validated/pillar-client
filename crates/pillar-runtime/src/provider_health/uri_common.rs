use super::*;

pub(crate) fn provider_uri_parts(uri: &ProviderUri) -> (String, HashMap<String, String>) {
    match uri {
        ProviderUri::Uri(uri) => (uri.clone(), HashMap::new()),
        ProviderUri::UriWithHeaders { uri, headers } => (uri.clone(), headers.clone()),
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AptosIndexerHealthKind {
    NoCode,
    Movement,
}

pub(crate) struct AptosIndexerProviderHealthRequest {
    pub(crate) report_url: String,
    pub(crate) request_url: String,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Value,
    pub(crate) kind: AptosIndexerHealthKind,
}
