use k256::ecdsa::{
    RecoveryId as EcdsaRecoveryId, Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{pkcs8::DecodePublicKey, PublicKey as EcdsaPublicKey};
use spki::SubjectPublicKeyInfoRef;

use crate::types::SignerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmsEcdsaSignatureEncoding {
    Der,
    Raw,
}

pub fn kms_ecdsa_signature_to_recoverable(
    signature: &[u8],
    encoding: KmsEcdsaSignatureEncoding,
    digest: &[u8],
    expected_public_key: &[u8],
    transform_recovery_id: bool,
) -> Result<Vec<u8>, SignerError> {
    let signature = match encoding {
        KmsEcdsaSignatureEncoding::Der => EcdsaSignature::from_der(signature),
        KmsEcdsaSignatureEncoding::Raw => EcdsaSignature::from_slice(signature),
    }
    .map_err(|error| SignerError::Message(error.to_string()))?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let recovery_id = recover_ecdsa_recovery_id(&signature, digest, expected_public_key)?;
    let mut result = signature.to_bytes().to_vec();
    result.push(if transform_recovery_id {
        recovery_id + 27
    } else {
        recovery_id
    });
    Ok(result)
}

fn recover_ecdsa_recovery_id(
    signature: &EcdsaSignature,
    digest: &[u8],
    expected_public_key: &[u8],
) -> Result<u8, SignerError> {
    let expected_public_key = raw_ecdsa_public_key(expected_public_key)?;
    for recovery_id in 0..=3 {
        let recovery_id = EcdsaRecoveryId::try_from(recovery_id)
            .map_err(|error| SignerError::Message(error.to_string()))?;
        // Ids 2 and 3 require r + n < p and are unrecoverable for essentially
        // every signature. Propagating that failure ended the search on the
        // first such candidate and reported a k256 signature-error string,
        // making the "Could not find recoveryId" arm below unreachable and
        // hiding the real cause: a KMS public key that matches no candidate.
        let Ok(recovered) = EcdsaVerifyingKey::recover_from_prehash(digest, signature, recovery_id)
        else {
            continue;
        };
        let recovered = recovered.to_encoded_point(false);
        if &recovered.as_bytes()[1..] == expected_public_key {
            return Ok(recovery_id.to_byte());
        }
    }
    Err(SignerError::Message(
        "Could not find recoveryId".to_string(),
    ))
}

pub(crate) fn ecdsa_public_key_from_spki_der(der: &[u8]) -> Result<Vec<u8>, SignerError> {
    let public_key = EcdsaPublicKey::from_public_key_der(der)
        .map_err(|error| SignerError::Message(error.to_string()))?;
    Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
}

pub(crate) fn ecdsa_public_key_from_pem(pem: &str) -> Result<Vec<u8>, SignerError> {
    let (label, der) = pem_rfc7468::decode_vec(pem.as_bytes())
        .map_err(|error| SignerError::Message(error.to_string()))?;
    if label != "PUBLIC KEY" {
        return Err(SignerError::Message(format!(
            "Expected PUBLIC KEY PEM, got {label}"
        )));
    }
    ecdsa_public_key_from_spki_der(&der)
}

pub(crate) fn ed25519_public_key_from_spki_der(der: &[u8]) -> Result<Vec<u8>, SignerError> {
    let spki = SubjectPublicKeyInfoRef::try_from(der)
        .map_err(|error| SignerError::Message(error.to_string()))?;
    let public_key = spki.subject_public_key.raw_bytes();
    if public_key.len() != 32 {
        return Err(SignerError::Message(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }
    Ok(public_key.to_vec())
}

pub(crate) fn raw_ecdsa_public_key(public_key: &[u8]) -> Result<&[u8], SignerError> {
    match public_key.len() {
        65 if public_key[0] == 0x04 => Ok(&public_key[1..]),
        64 => Ok(public_key),
        other => Err(SignerError::Message(format!(
            "ECDSA public key must be 64 raw bytes or 65 uncompressed bytes, got {other}"
        ))),
    }
}

#[cfg(test)]
mod tests;
