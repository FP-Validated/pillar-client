use super::*;
use k256::ecdsa::SigningKey as EcdsaSigningKey;

#[test]
fn kms_ecdsa_signature_to_recoverable_matches_typescript_der_and_raw_paths() {
    let signing_key = EcdsaSigningKey::from_slice(&[7u8; 32]).unwrap();
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let digest = [9u8; 32];
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
    let compact = signature.to_bytes().to_vec();

    let der_recoverable = kms_ecdsa_signature_to_recoverable(
        signature.to_der().as_bytes(),
        KmsEcdsaSignatureEncoding::Der,
        &digest,
        &public_key[1..],
        false,
    )
    .unwrap();
    assert_eq!(&der_recoverable[..64], compact);
    assert_eq!(der_recoverable[64], recovery_id.to_byte());

    let raw_recoverable = kms_ecdsa_signature_to_recoverable(
        &compact,
        KmsEcdsaSignatureEncoding::Raw,
        &digest,
        &public_key,
        true,
    )
    .unwrap();
    assert_eq!(&raw_recoverable[..64], compact);
    assert_eq!(raw_recoverable[64], recovery_id.to_byte() + 27);
}

#[test]
fn kms_ecdsa_signature_to_recoverable_rejects_bad_raw_signature_length() {
    let err = kms_ecdsa_signature_to_recoverable(
        &[1, 2, 3],
        KmsEcdsaSignatureEncoding::Raw,
        &[9u8; 32],
        &[4u8; 64],
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("signature error"));
}
