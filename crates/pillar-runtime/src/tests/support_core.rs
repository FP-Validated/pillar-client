use super::*;

pub(super) struct FixedResolver;

#[async_trait]
impl pillar_core::SentEventResolver for FixedResolver {
    async fn get_lz_sent_event(
        &self,
        src_tx_hash: &str,
        lz_message_id: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError> {
        Ok(LzSentEvent {
            lz_message_id: lz_message_id.clone(),
            message: "0xabc".to_string(),
            tx_hash: src_tx_hash.to_string(),
            extra: IndexMap::new(),
        })
    }
}

pub(super) struct FixedBuilder;

#[async_trait]
impl HashCallDataBuilder for FixedBuilder {
    async fn build_dvn_hash_call_data(
        &self,
        _sent_event: &LzSentEvent,
        _signing_context: &SigningContext,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Ok(HashCallDataResult {
            hash_call_data: "0xfeed".to_string(),
            details: json!({
                "proof": {
                    "payload": "0xpayload",
                    "resolvedPayload": "0xresolved"
                }
            }),
        })
    }
}

pub(super) struct NoopValidator;

#[async_trait]
impl AppValidator for NoopValidator {
    async fn validate_message_hash(
        &self,
        _request: &PillarApiRequestV2,
        _sent_event: &LzSentEvent,
    ) -> Result<(), AppCoreError> {
        Ok(())
    }

    async fn validate_readiness(
        &self,
        _sent_event: &LzSentEvent,
        _signing_context: &SigningContext,
    ) -> Result<(), AppCoreError> {
        Ok(())
    }

    async fn validate_expiration(
        &self,
        _dst_chain_name: &str,
        _expiration: i64,
    ) -> Result<(), AppCoreError> {
        Ok(())
    }

    async fn validate_payload_signed(
        &self,
        _sent_event: &LzSentEvent,
        _verifier_address: &str,
        _dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        Ok(())
    }

    async fn validate_extra_context(&self, _sent_event: &LzSentEvent) -> Result<(), AppCoreError> {
        Ok(())
    }
}

pub(super) struct FixedSigner;

#[async_trait]
impl SignerGetter for FixedSigner {
    async fn pillar_sign(
        &self,
        dst_chain_name: &str,
        wallet_name: &str,
        data_hex: &str,
    ) -> Result<Signature, AppCoreError> {
        Ok(Signature {
            signature: format!("sig:{dst_chain_name}:{wallet_name}:{data_hex}"),
            address: "0xsigner".to_string(),
        })
    }
}

pub(super) struct FixedRawKmsSigner {
    pub(super) public_key: Vec<u8>,
    pub(super) signature: Vec<u8>,
    pub(super) sign_requests: Arc<Mutex<Vec<SignRequest>>>,
}

#[async_trait]
impl RawSignerAdapter for FixedRawKmsSigner {
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        self.sign_requests.lock().unwrap().push(request);
        Ok(self.signature.clone())
    }

    async fn get_public_key(&self, request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        assert_eq!(request.signature_type, SignatureType::Ecdsa);
        Ok(self.public_key.clone())
    }
}

pub(super) struct FixedRawKmsFactory {
    pub(super) provider: KmsProvider,
    pub(super) expected_secret_name: String,
    pub(super) public_key: Vec<u8>,
    pub(super) signature: Vec<u8>,
    pub(super) sign_requests: Arc<Mutex<Vec<SignRequest>>>,
    pub(super) kms_calls: Arc<Mutex<Vec<(KmsProvider, String)>>>,
}

#[async_trait]
impl RawSignerAdapterFactory for FixedRawKmsFactory {
    async fn mnemonic(
        &self,
        _wallet_name: &str,
        _chain_type: ChainType,
        _definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        Err(SignerError::UnsupportedSignerType("MNEMONIC".to_string()))
    }

    async fn kms(
        &self,
        provider: KmsProvider,
        definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        assert_eq!(provider, self.provider);
        assert_eq!(definition.secret_name, self.expected_secret_name);
        self.kms_calls
            .lock()
            .unwrap()
            .push((provider, definition.secret_name.clone()));
        Ok(Arc::new(FixedRawKmsSigner {
            public_key: self.public_key.clone(),
            signature: self.signature.clone(),
            sign_requests: self.sign_requests.clone(),
        }))
    }
}
