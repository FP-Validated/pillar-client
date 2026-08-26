use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;

use crate::abi::{address_to_bytes32, decode_hex_32, decode_hex_bytes, u64_from_i64};
use crate::evm::evm_receive_version_from_dst_eid;
use crate::packet::{
    extra_u64, pathway_extra_string, proof_from_event, uln_send_version_string, EvmUlnProof,
};
use crate::types::{
    UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder, ULN_VERSION_V302,
};

pub(crate) const SOLANA_ULN_PROGRAM_ID: &str = "7a4WjyR8VZ7yZz5XJAKm39BUGn5iT9CKcv2pmG9tdXVH";
pub(crate) const VERIFY_DISCRIMINATOR: [u8; 8] = [133, 161, 141, 48, 120, 198, 88, 150];
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

pub struct SolanaUlnPayloadBuilder;

impl SolanaUlnPayloadBuilder {
    pub fn build_uln_v3_verify_payload_from_proof(
        &self,
        sent_event: &LzSentEvent,
        proof: EvmUlnProof,
        block_confirmation: i64,
        expiration: i64,
        v_id: &str,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let dvn_address = dvn_address.ok_or_else(|| {
            AppCoreError::Internal("Solana: DVN Address is required for verify payload".to_string())
        })?;
        let dst_eid = extra_u64(sent_event, "dstEid")?;
        let uln_send_version = uln_send_version_string(&sent_event.lz_message_id.uln_send_version)?;
        if evm_receive_version_from_dst_eid(dst_eid, &uln_send_version) != ULN_VERSION_V302 {
            return Err(AppCoreError::Internal(
                "Solana only supports EndpointV2".to_string(),
            ));
        }

        let vid = v_id
            .parse::<u32>()
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let block_confirmation = u64_from_i64(block_confirmation, "blockConfirmation")?;
        let program_id = public_key_bytes(SOLANA_ULN_PROGRAM_ID)?;
        let dvn = public_key_bytes(dvn_address)?;
        let uln_call_data = solana_verify_instruction_data(&proof, block_confirmation)?;
        let accounts = solana_verify_accounts(&proof, &dvn, &program_id)?;
        let digest_bytes = execute_transaction_digest_bytes(
            vid,
            &program_id,
            &accounts,
            &uln_call_data,
            expiration,
        );
        let hash_call_data = hex::encode(Keccak256::digest(&digest_bytes));

        Ok(HashCallDataResult {
            hash_call_data,
            details: serde_json::json!({
                "dvnHashCallData": {
                    "dvnCallData": hex::encode(&digest_bytes),
                },
                "dvnCallData": {
                    "expiration": expiration,
                    "vid": v_id,
                    "targetContract": SOLANA_ULN_PROGRAM_ID,
                    "ulnCallData": hex::encode(&uln_call_data),
                },
                "ulnCallData": {
                    "methodName": "verify",
                    "proof": {
                        "packetHeader": proof.packet_header,
                        "payloadHash": proof.payload_hash,
                    },
                    "blockConfirmation": block_confirmation,
                },
                "proof": {
                    "payload": sent_event.message,
                    "lzMessageId": sent_event.lz_message_id,
                },
            }),
        })
    }
}

#[async_trait]
impl UlnV2PayloadBuilder for SolanaUlnPayloadBuilder {
    async fn build_uln_v2_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _block_confirmation: i64,
        _expiration: i64,
        _v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "Not implemented: Solana only supports EndpointV2".to_string(),
        ))
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for SolanaUlnPayloadBuilder {
    async fn build_uln_v3_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.build_uln_v3_verify_payload_from_proof(
            sent_event,
            proof_from_event(sent_event)?,
            block_confirmation,
            expiration,
            &v_id,
            dvn_address,
        )
    }
}

#[async_trait]
impl UlnReadV1PayloadBuilder for SolanaUlnPayloadBuilder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _resolved_payload: String,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal("Not implemented".to_string()))
    }
}

pub(crate) fn solana_verify_instruction_data(
    proof: &EvmUlnProof,
    block_confirmation: u64,
) -> Result<Vec<u8>, AppCoreError> {
    let packet_header = decode_hex_bytes(&proof.packet_header)?;
    if packet_header.len() != 81 {
        return Err(AppCoreError::Internal(format!(
            "invalid Solana packet header length: {}",
            packet_header.len()
        )));
    }
    let payload_hash = decode_hex_32(&proof.payload_hash)?;
    let mut out = Vec::with_capacity(129);
    out.extend_from_slice(&VERIFY_DISCRIMINATOR);
    out.extend_from_slice(&packet_header);
    out.extend_from_slice(&payload_hash);
    out.extend_from_slice(&block_confirmation.to_le_bytes());
    Ok(out)
}

pub(crate) fn execute_transaction_digest_bytes(
    vid: u32,
    program_id: &[u8; 32],
    accounts: &[TransactionAccount],
    data: &[u8],
    expiration: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 4 + accounts.len() * 34 + 4 + data.len() + 8);
    out.extend_from_slice(&vid.to_le_bytes());
    out.extend_from_slice(program_id);
    out.extend_from_slice(&(accounts.len() as u32).to_le_bytes());
    for account in accounts {
        out.extend_from_slice(&account.pubkey);
        out.push(u8::from(account.is_signer));
        out.push(u8::from(account.is_writable));
    }
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&expiration.to_le_bytes());
    out
}

pub fn solana_header_and_payload_hash(
    proof: &EvmUlnProof,
) -> Result<([u8; 32], [u8; 32]), AppCoreError> {
    let packet_header = decode_hex_bytes(&proof.packet_header)?;
    let header_hash: [u8; 32] = Keccak256::digest(&packet_header).into();
    let payload_hash = decode_hex_32(&proof.payload_hash)?;
    Ok((header_hash, payload_hash))
}

fn solana_verify_accounts(
    proof: &EvmUlnProof,
    dvn: &[u8; 32],
    program_id: &[u8; 32],
) -> Result<Vec<TransactionAccount>, AppCoreError> {
    let (header_hash, payload_hash) = solana_header_and_payload_hash(proof)?;
    Ok(vec![
        TransactionAccount {
            pubkey: *dvn,
            is_signer: true,
            is_writable: false,
        },
        TransactionAccount {
            pubkey: find_program_address(
                &[
                    b"Confirmations".as_slice(),
                    &header_hash,
                    &payload_hash,
                    dvn,
                ],
                program_id,
            )?,
            is_signer: false,
            is_writable: true,
        },
        TransactionAccount {
            pubkey: find_program_address(&[b"__event_authority".as_slice()], program_id)?,
            is_signer: false,
            is_writable: false,
        },
        TransactionAccount {
            pubkey: *program_id,
            is_signer: false,
            is_writable: false,
        },
    ])
}

pub(crate) fn find_program_address(
    seeds: &[&[u8]],
    program_id: &[u8; 32],
) -> Result<[u8; 32], AppCoreError> {
    for bump in (0..=255_u8).rev() {
        let bump_seed = [bump];
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update(bump_seed);
        hasher.update(program_id);
        hasher.update(PDA_MARKER);
        let digest = hasher.finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&digest);
        if VerifyingKey::from_bytes(&candidate).is_err() {
            return Ok(candidate);
        }
    }
    Err(AppCoreError::Internal(
        "unable to find Solana program address".to_string(),
    ))
}

pub fn solana_message_library_address(program_id: &str) -> Result<String, AppCoreError> {
    let program_id = public_key_bytes(program_id)?;
    let address = find_program_address(&[b"MessageLib".as_slice()], &program_id)?;
    Ok(bs58::encode(address).into_string())
}

pub(crate) fn public_key_bytes(value: &str) -> Result<[u8; 32], AppCoreError> {
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    if bytes.len() != 32 {
        return Err(AppCoreError::Internal(format!(
            "invalid Solana public key length: {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) struct TransactionAccount {
    pub(crate) pubkey: [u8; 32],
    pub(crate) is_signer: bool,
    pub(crate) is_writable: bool,
}

pub(crate) const SOLANA_ENDPOINT_PROGRAM_ID: &str = "76y77prsiCMvXMjuoZ5VRrhG5qYBrUMYTE5WgHqgjEn6";

const NONCE_ACCOUNT_DISCRIMINATOR: [u8; 8] = [143, 197, 147, 95, 106, 165, 50, 43];
const PENDING_INBOUND_NONCE_ACCOUNT_DISCRIMINATOR: [u8; 8] =
    [170, 176, 95, 240, 120, 231, 241, 218];
const RECEIVE_CONFIG_ACCOUNT_DISCRIMINATOR: [u8; 8] = [162, 159, 153, 188, 56, 65, 245, 58];
const CONFIRMATIONS_ACCOUNT_DISCRIMINATOR: [u8; 8] = [206, 57, 50, 8, 124, 133, 138, 112];
/// Sentinel `u64` value the on-chain ULN program uses to mean "explicitly
/// override to zero confirmations required", distinct from "unset" (which is
/// the ordinary `0` default). Mirrors TypeScript `NIL_CONFIRMATIONS`.
const NIL_CONFIRMATIONS: u64 = u64::MAX;

/// Inputs needed to derive and evaluate the Solana on-chain accounts that
/// prove whether `dvn` has already recorded a sufficient confirmation for
/// this exact packet, mirroring TypeScript `UlnSolanaSdk.isVerified`
/// (`packages/sdks/lz-v2-sdk/src/uln/solana/index.ts`).
#[derive(Clone, Copy)]
pub struct SolanaPayloadSignedRequest {
    pub receiver: [u8; 32],
    pub sender: [u8; 32],
    pub src_eid: u32,
    pub nonce: u64,
    pub header_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub dvn: [u8; 32],
}

/// The Solana account addresses (PDAs) that must be fetched via
/// `getMultipleAccounts` before `solana_payload_is_signed` can evaluate
/// whether `dvn` already verified this packet.
pub struct SolanaPayloadSignedAccounts {
    pub nonce_pda: [u8; 32],
    pub pending_nonce_pda: [u8; 32],
    pub receive_config_pda: [u8; 32],
    pub default_receive_config_pda: [u8; 32],
    pub confirmations_pda: [u8; 32],
}

/// Raw, possibly-missing account bytes fetched for the PDAs from
/// [`SolanaPayloadSignedAccounts`]. `None` means the RPC returned a null
/// account (not yet initialized on-chain), which TypeScript treats the same
/// as "this check does not apply yet" for `nonce`/`pending_nonce`, and as
/// "not yet confirmed" for `confirmations`.
#[derive(Default)]
pub struct SolanaFetchedPayloadSignedAccounts<'a> {
    pub nonce: Option<&'a [u8]>,
    pub pending_nonce: Option<&'a [u8]>,
    pub receive_config: Option<&'a [u8]>,
    pub default_receive_config: Option<&'a [u8]>,
    pub confirmations: Option<&'a [u8]>,
}

/// Builds a [`SolanaPayloadSignedRequest`] from a resolved sent event and the
/// signing DVN's own wallet address, decoding `receiver` (Solana base58) and
/// `sender` (the source chain's native address format, hex for the
/// currently-supported EVM source chains) into the raw 32-byte values the
/// on-chain PDAs are keyed by.
pub fn solana_payload_signed_request(
    sent_event: &LzSentEvent,
    dvn_address: &str,
) -> Result<SolanaPayloadSignedRequest, AppCoreError> {
    let receiver_raw = pathway_extra_string(sent_event, "receiver")?;
    let receiver =
        address_to_bytes32(&receiver_raw).or_else(|_| public_key_bytes(&receiver_raw))?;
    let sender_raw = pathway_extra_string(sent_event, "sender")?;
    let sender = address_to_bytes32(&sender_raw).or_else(|_| public_key_bytes(&sender_raw))?;
    let src_eid = u32::try_from(extra_u64(sent_event, "srcEid")?)
        .map_err(|_| AppCoreError::Internal("srcEid exceeds u32".to_string()))?;
    let dvn = public_key_bytes(dvn_address)?;
    let proof = proof_from_event(sent_event)?;
    let (header_hash, payload_hash) = solana_header_and_payload_hash(&proof)?;
    Ok(SolanaPayloadSignedRequest {
        receiver,
        sender,
        src_eid,
        nonce: sent_event.lz_message_id.nonce,
        header_hash,
        payload_hash,
        dvn,
    })
}

pub fn solana_payload_signed_accounts(
    request: &SolanaPayloadSignedRequest,
) -> Result<SolanaPayloadSignedAccounts, AppCoreError> {
    let endpoint_program_id = public_key_bytes(SOLANA_ENDPOINT_PROGRAM_ID)?;
    let uln_program_id = public_key_bytes(SOLANA_ULN_PROGRAM_ID)?;
    let src_eid_be = request.src_eid.to_be_bytes();
    let nonce_pda = find_program_address(
        &[
            b"Nonce".as_slice(),
            &request.receiver,
            &src_eid_be,
            &request.sender,
        ],
        &endpoint_program_id,
    )?;
    let pending_nonce_pda = find_program_address(
        &[
            b"PendingNonce".as_slice(),
            &request.receiver,
            &src_eid_be,
            &request.sender,
        ],
        &endpoint_program_id,
    )?;
    let receive_config_pda = find_program_address(
        &[b"ReceiveConfig".as_slice(), &src_eid_be, &request.receiver],
        &uln_program_id,
    )?;
    let default_receive_config_pda =
        find_program_address(&[b"ReceiveConfig".as_slice(), &src_eid_be], &uln_program_id)?;
    let confirmations_pda = find_program_address(
        &[
            b"Confirmations".as_slice(),
            &request.header_hash,
            &request.payload_hash,
            &request.dvn,
        ],
        &uln_program_id,
    )?;
    Ok(SolanaPayloadSignedAccounts {
        nonce_pda,
        pending_nonce_pda,
        receive_config_pda,
        default_receive_config_pda,
        confirmations_pda,
    })
}

/// Evaluates whether `dvn` has already verified this packet, mirroring
/// TypeScript `UlnSolanaSdk.isVerified`:
/// - already delivered (`Nonce.inboundNonce >= nonce`);
/// - already committed but not yet delivered (`nonce` is in `PendingInboundNonce`);
/// - the DVN's `Confirmations` record meets the configured threshold.
///
/// Does not port the additional `getVerificationState` on-chain
/// transaction-simulation path (multi-DVN threshold combinations checked via
/// the DVN program's view instruction) — that is a separate, larger port. As
/// a result this is a conservative subset of the TypeScript check: it can
/// only under-report "already signed" relative to TypeScript in scenarios
/// `isVerified` alone does not cover, never over-report it, so it is safe
/// against duplicate on-chain submissions from this DVN's own confirmation
/// record without risking a false "already signed" that would silently skip
/// a signature that was actually still needed.
pub fn solana_payload_is_signed(
    request: &SolanaPayloadSignedRequest,
    accounts: SolanaFetchedPayloadSignedAccounts<'_>,
) -> Result<bool, AppCoreError> {
    if let Some(data) = accounts.nonce {
        if decode_solana_nonce_account(data)?.inbound_nonce >= request.nonce {
            return Ok(true);
        }
    }
    if let Some(data) = accounts.pending_nonce {
        if decode_solana_pending_inbound_nonce_account(data)?.contains(&request.nonce) {
            return Ok(true);
        }
    }

    let default_config = accounts
        .default_receive_config
        .ok_or_else(|| {
            AppCoreError::Internal("Default Solana ULN receive config not found".to_string())
        })
        .and_then(decode_solana_receive_config_account)?;
    let custom_config = accounts
        .receive_config
        .map(decode_solana_receive_config_account)
        .transpose()?;
    let required_confirmations = match custom_config {
        None => default_config.confirmations,
        Some(custom) if custom.confirmations == 0 => default_config.confirmations,
        Some(custom) if custom.confirmations == NIL_CONFIRMATIONS => 0,
        Some(custom) => custom.confirmations,
    };

    let Some(data) = accounts.confirmations else {
        return Ok(false);
    };
    let Some(confirmation_value) = decode_solana_confirmations_account(data)? else {
        return Ok(false);
    };
    if confirmation_value == 0 {
        return Ok(false);
    }
    Ok(confirmation_value >= required_confirmations)
}

struct SolanaNonceAccount {
    inbound_nonce: u64,
}

fn decode_solana_nonce_account(data: &[u8]) -> Result<SolanaNonceAccount, AppCoreError> {
    check_account_discriminator(data, &NONCE_ACCOUNT_DISCRIMINATOR, "Nonce")?;
    // layout: 8-byte discriminator, 1-byte bump, u64 outboundNonce, u64 inboundNonce
    Ok(SolanaNonceAccount {
        inbound_nonce: read_u64_le(data, 17, "Nonce.inboundNonce")?,
    })
}

fn decode_solana_pending_inbound_nonce_account(data: &[u8]) -> Result<Vec<u64>, AppCoreError> {
    check_account_discriminator(
        data,
        &PENDING_INBOUND_NONCE_ACCOUNT_DISCRIMINATOR,
        "PendingInboundNonce",
    )?;
    // layout: 8-byte discriminator, u32 vec length, N * u64 nonce, 1-byte bump
    let len = read_u32_le(data, 8, "PendingInboundNonce.nonces.len")? as usize;
    (0..len)
        .map(|index| read_u64_le(data, 12 + index * 8, "PendingInboundNonce.nonces[i]"))
        .collect()
}

struct SolanaUlnConfig {
    confirmations: u64,
}

fn decode_solana_receive_config_account(data: &[u8]) -> Result<SolanaUlnConfig, AppCoreError> {
    check_account_discriminator(data, &RECEIVE_CONFIG_ACCOUNT_DISCRIMINATOR, "ReceiveConfig")?;
    // layout: 8-byte discriminator, 1-byte bump, UlnConfig{u64 confirmations, ...}
    Ok(SolanaUlnConfig {
        confirmations: read_u64_le(data, 9, "ReceiveConfig.uln.confirmations")?,
    })
}

fn decode_solana_confirmations_account(data: &[u8]) -> Result<Option<u64>, AppCoreError> {
    check_account_discriminator(data, &CONFIRMATIONS_ACCOUNT_DISCRIMINATOR, "Confirmations")?;
    // layout: 8-byte discriminator, 1-byte Option tag, [u64 value if Some], 1-byte bump
    let tag = *data.get(8).ok_or_else(|| {
        AppCoreError::Internal("Confirmations account data too short".to_string())
    })?;
    if tag == 0 {
        return Ok(None);
    }
    Ok(Some(read_u64_le(data, 9, "Confirmations.value")?))
}

fn check_account_discriminator(
    data: &[u8],
    expected: &[u8; 8],
    account_name: &str,
) -> Result<(), AppCoreError> {
    let actual = data
        .get(..8)
        .ok_or_else(|| AppCoreError::Internal(format!("{account_name} account data too short")))?;
    if actual != expected {
        return Err(AppCoreError::Internal(format!(
            "{account_name} account discriminator mismatch"
        )));
    }
    Ok(())
}

fn read_u64_le(data: &[u8], offset: usize, field: &str) -> Result<u64, AppCoreError> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| AppCoreError::Internal(format!("{field}: account data too short")))?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_u32_le(data: &[u8], offset: usize, field: &str) -> Result<u32, AppCoreError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| AppCoreError::Internal(format!("{field}: account data too short")))?;
    Ok(u32::from_le_bytes(bytes))
}
