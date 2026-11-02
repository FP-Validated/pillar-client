use super::*;
use k256::ecdsa::SigningKey as EcdsaSigningKey;

#[test]
fn kms_ecdsa_signature_to_recoverable_matches_typescript_der_and_raw_paths() {
    let signing_key = EcdsaSigningKey::from_slice(&[7u8; 32]).unwrap();
    let public_key = signing_key
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    let digest = [9u8; 32];
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest);
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
fn ethereum_recovery_transform_rejects_rare_recovery_ids_but_raw_mode_preserves_them() {
    let digest = [0u8; 32];
    for wanted_id in [2u8, 3u8] {
        let (signature, public_key) = (1u16..=u8::MAX as u16)
            .find_map(|r| {
                let mut compact = [0u8; 64];
                compact[30..32].copy_from_slice(&r.to_be_bytes());
                compact[63] = 1;
                let signature = EcdsaSignature::from_slice(&compact).ok()?;
                let recovery_id = EcdsaRecoveryId::try_from(wanted_id).ok()?;
                let recovered =
                    EcdsaVerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
                        .ok()?;
                Some((compact, recovered.to_sec1_point(false).as_bytes().to_vec()))
            })
            .expect("small deterministic r range contains a valid recovery-id 2/3 point");
        let raw = kms_ecdsa_signature_to_recoverable(
            &signature,
            KmsEcdsaSignatureEncoding::Raw,
            &digest,
            &public_key,
            false,
        )
        .unwrap();
        assert_eq!(raw[64], wanted_id);
        assert!(kms_ecdsa_signature_to_recoverable(
            &signature,
            KmsEcdsaSignatureEncoding::Raw,
            &digest,
            &public_key,
            true,
        )
        .is_err());
    }
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

/// A DER signature of 29-byte `r` and `s` is exactly 64 bytes, the length of raw `r || s`.
#[test]
fn a_64_byte_der_signature_is_recovered_as_der_not_misread_as_raw() {
    let digest = [9u8; 32];
    let (der, public_key, r) = (1u8..=0x7f)
        .find_map(|first| {
            let mut r = [1u8; 29];
            r[0] = first;
            let mut der = vec![0x30, 0x3e, 0x02, 0x1d];
            der.extend_from_slice(&r);
            der.extend_from_slice(&[0x02, 0x1d]);
            der.extend_from_slice(&[2u8; 29]);
            let signature = EcdsaSignature::from_der(&der).ok()?;
            [0u8, 1].into_iter().find_map(|id| {
                let id = EcdsaRecoveryId::try_from(id).ok()?;
                let key = EcdsaVerifyingKey::recover_from_prehash(&digest, &signature, id).ok()?;
                Some((der.clone(), key.to_sec1_point(false).as_bytes().to_vec(), r))
            })
        })
        .expect("some r is a curve x-coordinate");
    assert_eq!(der.len(), 64);
    assert!(kms_ecdsa_signature_to_recoverable(
        &der,
        KmsEcdsaSignatureEncoding::Raw,
        &digest,
        &public_key,
        false
    )
    .is_err());

    let recovered =
        kms_ecdsa_signature_of_either_encoding_to_recoverable(&der, &digest, &public_key, false)
            .unwrap();
    assert_eq!(&recovered[3..32], &r[..]);
}
