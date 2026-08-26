use async_trait::async_trait;
use pillar_api::{router, AppError, ServerApp, SignerInfo, StaticApp};
use pillar_core::{
    PillarApiRequestV1, PillarApiRequestV2, PillarApiResponse, ProviderHealthSnapshot, Signature,
};
use serde_json::Value;

struct QaApp(StaticApp);

#[async_trait]
impl ServerApp for QaApp {
    async fn sign_request_v1(
        &self,
        _input: PillarApiRequestV1,
    ) -> Result<PillarApiResponse, AppError> {
        Ok(qa_signature_response())
    }

    async fn sign_request_v2(
        &self,
        _input: PillarApiRequestV2,
    ) -> Result<PillarApiResponse, AppError> {
        Ok(qa_signature_response())
    }

    async fn get_signer_info(&self, chain_name: String) -> Result<Vec<SignerInfo>, AppError> {
        self.0.get_signer_info(chain_name).await
    }

    fn get_available_chain_names(&self) -> Vec<String> {
        self.0.get_available_chain_names()
    }

    fn get_environment(&self) -> String {
        self.0.get_environment()
    }

    async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, AppError> {
        self.0.get_provider_health().await
    }

    async fn get_provider_health_report(&self) -> Result<Value, AppError> {
        self.0.get_provider_health_report().await
    }
}

fn qa_signature_response() -> PillarApiResponse {
    PillarApiResponse {
        signatures: vec![Signature {
            signature: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            address: "0x06bb41FE76F41429f55aC8C355ac8669769A1ba1".to_string(),
        }],
        payload: "0x0223536e".to_string(),
        debug_info: None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("PILLAR_QA_PORT")
        .unwrap_or_else(|_| "18080".to_string())
        .parse::<u16>()?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let auth_tokens = std::env::var("PILLAR_API_AUTH_TOKENS")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    axum::serve(
        listener,
        router(
            QaApp(StaticApp::observed_mainnet().with_auth_tokens(auth_tokens)),
            "qa-version",
        ),
    )
    .await?;
    Ok(())
}
