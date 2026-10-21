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
                .pin_for_request(async {
                    self.controls
                        .scope(
                            self.providers.generation(),
                            signing_app.sign_request_v1(input),
                        )
                        .await
                })
                .await;
        }
        Err(AppError::Internal(
            "signRequestV1 is unavailable: this app was built without a signing core".to_string(),
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
                .pin_for_request(async {
                    self.controls
                        .scope(
                            self.providers.generation(),
                            signing_app.sign_request_v2(input),
                        )
                        .await
                })
                .await;
        }
        Err(AppError::Internal(
            "signRequestV2 is unavailable: this app was built without a signing core".to_string(),
        ))
    }

    async fn get_signer_info(&self, chain_name: String) -> Result<Vec<SignerInfo>, AppError> {
        if let Some(signing_app) = &self.signing_app {
            return self
                .controls
                .scope(
                    self.providers.generation(),
                    signing_app.get_signer_info(chain_name),
                )
                .await;
        }
        if self
            .providers
            .load()
            .available_chain_names()
            .iter()
            .any(|available| available == &chain_name)
        {
            Err(AppError::Internal(
                "signer-info is unavailable: this app was built without a signing core".to_string(),
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
        self.controls
            .scope(
                self.providers.generation(),
                self.provider_health_cache.read(),
            )
            .await
            .map_err(AppError::Internal)
    }

    async fn get_provider_health_report(&self) -> Result<Value, AppError> {
        let generation = self.providers.generation();
        self.controls
            .scope(generation, self.provider_health_cache.read())
            .await
            .map_err(AppError::Internal)?;
        let report = self
            .provider_health_source
            .retained_report(generation, (self.provider_health_source.now_unix_ms())())
            .await
            .ok_or_else(|| {
                AppError::Internal(
                    "provider health report is unavailable for the current provider generation"
                        .to_string(),
                )
            })?;
        serde_json::to_value(&*report).map_err(|error| AppError::Internal(error.to_string()))
    }
    fn auth_tokens(&self) -> &[String] {
        &self.runtime_config.api_auth_tokens
    }

    fn auth_token_matches(&self, token: &[u8]) -> bool {
        self.runtime_config
            .api_auth_tokens
            .iter()
            .any(|expected| pillar_api::constant_time_token_match(token, expected.as_bytes()))
    }
    fn public_sign_routes(&self) -> bool {
        self.runtime_config.public_sign_routes
    }

    fn api_auth_enabled(&self) -> bool {
        self.runtime_config.api_auth_enabled
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
                self.controls
                    .scope(
                        self.providers.generation(),
                        self.provider_health_cache.read(),
                    )
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
        if ready && self.controls.healthy().await {
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
    fn execution_resources(&self) -> Option<Arc<pillar_core::execution::ExecutionResources>> {
        Some(self.controls.resources.clone())
    }
}
