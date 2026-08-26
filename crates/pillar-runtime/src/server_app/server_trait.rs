use super::*;

#[async_trait]
impl<T> ServerApp for RuntimeServerApp<T>
where
    T: JsonRpcTransport,
{
    async fn sign_request_v1(
        &self,
        input: PillarApiRequestV1,
    ) -> Result<PillarApiResponse, AppError> {
        if let Some(signing_app) = &self.signing_app {
            // Pins one provider generation for the whole request, so no two
            // consumers of it can straddle a refresh.
            return self
                .providers
                .pin_for_request(signing_app.sign_request_v1(input))
                .await;
        }
        Err(AppError::Internal(
            "signRequestV1 is not wired in the Rust runtime yet".to_string(),
        ))
    }

    async fn sign_request_v2(
        &self,
        input: PillarApiRequestV2,
    ) -> Result<PillarApiResponse, AppError> {
        if let Some(signing_app) = &self.signing_app {
            // Pins one provider generation for the whole request, so no two
            // consumers of it can straddle a refresh.
            return self
                .providers
                .pin_for_request(signing_app.sign_request_v2(input))
                .await;
        }
        Err(AppError::Internal(
            "signRequestV2 is not wired in the Rust runtime yet".to_string(),
        ))
    }

    async fn get_signer_info(&self, chain_name: String) -> Result<Vec<SignerInfo>, AppError> {
        if let Some(signing_app) = &self.signing_app {
            return signing_app.get_signer_info(chain_name).await;
        }
        if self
            .providers
            .load()
            .available_chain_names()
            .iter()
            .any(|available| available == &chain_name)
        {
            Err(AppError::Internal(
                "signer-info is not wired in the Rust runtime yet".to_string(),
            ))
        } else {
            Err(AppError::BadRequest(format!(
                "Chain {chain_name} is not supported"
            )))
        }
    }

    fn get_available_chain_names(&self) -> Vec<String> {
        self.providers.load().available_chain_names().to_vec()
    }

    fn get_environment(&self) -> String {
        self.runtime_config
            .environment
            .clone()
            .expect("LAYERZERO_ENVIRONMENT must be present in RuntimeServerApp")
    }

    async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, AppError> {
        self.provider_health_cache
            .read()
            .await
            .map_err(AppError::Internal)
    }

    async fn get_provider_health_report(&self) -> Result<Value, AppError> {
        serde_json::to_value(
            self.provider_health_source
                .get_provider_health_report()
                .await,
        )
        .map_err(|error| AppError::Internal(error.to_string()))
    }
    fn auth_tokens(&self) -> Vec<String> {
        self.runtime_config.api_auth_tokens.clone()
    }

    async fn readiness(&self) -> pillar_api::ReadinessStatus {
        // Readiness combines two reads of provider state - is any advertised
        // chain healthy - so it has to pin a generation like a sign request
        // does. Without the pin a refresh landing between the health read and
        // the roster read would answer from one generation's health and
        // another's chain set, and report on a combination that never served.
        let ready = self
            .providers
            .pin_for_request(async {
                self.provider_health_cache
                    .read()
                    .await
                    .map(|health| {
                        self.providers
                            .load()
                            .available_chain_names()
                            .iter()
                            .any(|chain| health.get(chain).copied().unwrap_or(false))
                    })
                    .unwrap_or(false)
            })
            .await;
        if ready {
            pillar_api::ReadinessStatus::Ready
        } else {
            pillar_api::ReadinessStatus::NotReady
        }
    }
    fn metrics(&self) -> Option<Arc<Mutex<PillarMetrics>>> {
        self.signing_app
            .as_ref()
            .and_then(|signing_app| signing_app.metrics())
    }
}
