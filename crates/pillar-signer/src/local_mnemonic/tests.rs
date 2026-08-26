use super::*;
use crate::chain_address::bytes_to_hex;
use crate::{PublicKeyRequest, RawSignerAdapter, SeedKind, SignRequest, SignatureType};

#[tokio::test]
async fn local_mnemonic_ecdsa_public_key_matches_typescript_vector() {
    let signer = LocalMnemonicRawSignerAdapter::new(LocalMnemonic {
        mnemonic: "test test test test test test test test test test test junk".to_string(),
        path: "m/44'/60'/0'/0/0".to_string(),
    });

    let public_key = signer
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    assert_eq!(
        bytes_to_hex(&public_key),
        concat!(
            "04",
            "8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "3547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
        )
    );
}

#[tokio::test]
async fn local_mnemonic_ecdsa_signature_matches_typescript_vector() {
    let signer = LocalMnemonicRawSignerAdapter::new(LocalMnemonic {
        mnemonic: "test test test test test test test test test test test junk".to_string(),
        path: "m/44'/60'/0'/0/0".to_string(),
    });
    let data =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();

    let signature = signer
        .sign(SignRequest {
            data,
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            transform_recovery_id: false,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    assert_eq!(
        bytes_to_hex(&signature),
        concat!(
            "f42a8f0d81999bb1ebfa5ab96208ca5f4b2890db087c15371f7b840c5a70853c",
            "46ae076d8999c080cda491c75eca1133ae94dc0282b778971b393d898f07b06e",
            "00"
        )
    );
}

#[tokio::test]
async fn local_mnemonic_ecdsa_can_apply_recovery_id_transform() {
    let signer = LocalMnemonicRawSignerAdapter::new(LocalMnemonic {
        mnemonic: "test test test test test test test test test test test junk".to_string(),
        path: "m/44'/60'/0'/0/0".to_string(),
    });
    let data =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();

    let signature = signer
        .sign(SignRequest {
            data,
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            transform_recovery_id: true,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    assert_eq!(signature.last(), Some(&27));
}

#[tokio::test]
async fn local_mnemonic_ed25519_public_key_matches_typescript_vector() {
    let signer = LocalMnemonicRawSignerAdapter::new(LocalMnemonic {
        mnemonic: "test test test test test test test test test test test junk".to_string(),
        path: "m/44'/501'/0'/0'".to_string(),
    });

    let public_key = signer
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ed25519,
            private_key_signature_type: SignatureType::Ed25519,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    assert_eq!(
        bytes_to_hex(&public_key),
        "0bf32b9f0db09672038fea36139b18f98a5f0149ef4ce0332e44b9a77e83c22d"
    );
}

#[tokio::test]
async fn local_mnemonic_ed25519_signature_matches_typescript_vector() {
    let signer = LocalMnemonicRawSignerAdapter::new(LocalMnemonic {
        mnemonic: "test test test test test test test test test test test junk".to_string(),
        path: "m/44'/501'/0'/0'".to_string(),
    });
    let data =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();

    let signature = signer
        .sign(SignRequest {
            data,
            signature_type: SignatureType::Ed25519,
            private_key_signature_type: SignatureType::Ed25519,
            transform_recovery_id: false,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    assert_eq!(
        bytes_to_hex(&signature),
        concat!(
            "3a0e4eb2c2a7a6d0be6797af3c934ee0daad5d2ea6aa2aaea10f1f8a0caf887",
            "758e5dcc90443f2328a65e2d7534dac8a70993511f27bb8799a895443fd79920d"
        )
    );
}

#[tokio::test]
async fn local_mnemonic_ed25519_private_key_can_feed_legacy_ecdsa_mode() {
    let signer = LocalMnemonicRawSignerAdapter::new(LocalMnemonic {
        mnemonic: "test test test test test test test test test test test junk".to_string(),
        path: "m/44'/501'/0'/0'".to_string(),
    });
    let public_key = signer
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ed25519,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    assert_eq!(
        bytes_to_hex(&public_key),
        concat!(
            "04",
            "62453fa45272e0d59ffa2bb74d98fd0261b52cc10512095eedae17c8f58dc17e",
            "08fd59e78d446c7635a1e3d854089d96a6d877e43eba56a59439ee85a90622b8"
        )
    );

    let data =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let signature = signer
        .sign(SignRequest {
            data,
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ed25519,
            transform_recovery_id: false,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    assert_eq!(
        bytes_to_hex(&signature),
        concat!(
            "407774d099b6e66a3f2d2f395fcb2907e218c099bf107ad854abef74ea93850f",
            "262be13bd8ce36e914e8da6b8a1d9490a5d737f1df5fc6b7b76b696c71171c7c",
            "00"
        )
    );
}

#[tokio::test]
async fn local_mnemonic_ton_seed_public_key_matches_typescript_vector() {
    let signer = LocalMnemonicRawSignerAdapter::new(LocalMnemonic {
        mnemonic: "test test test test test test test test test test test junk".to_string(),
        path: "m/44'/607'/0'".to_string(),
    });

    assert_eq!(
        bytes_to_hex(&ton_hd_seed(&signer.mnemonic.mnemonic, "").unwrap()),
        concat!(
            "8c7d8863fc52b287b1399a2a77ecc8e71b21e578e9f33245d368b131db6ff3c",
            "d92b2f2854d573d7339aca5b71a71d578943721670013e01bbe6434ff6a308186"
        )
    );

    let public_key = signer
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ed25519,
            seed_kind: SeedKind::Ton,
        })
        .await
        .unwrap();

    assert_eq!(
        bytes_to_hex(&public_key),
        concat!(
            "04",
            "82b8ed2f423ff8aa6fba75cbd4cc272e2abd2dd9fea53705d383706730bd7d75",
            "7271129607204ff3f52b72567d5be8e760bd89be920bda0bf5228d2c6b737b3d"
        )
    );
}

#[tokio::test]
async fn local_mnemonic_rejects_ecdsa_private_key_for_ed25519_signature_like_typescript() {
    let signer = LocalMnemonicRawSignerAdapter::new(LocalMnemonic {
        mnemonic: "test test test test test test test test test test test junk".to_string(),
        path: "m/44'/60'/0'/0/0".to_string(),
    });

    let err = signer
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ed25519,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "Bad keypair generation: only mismatch allowed is Ed25519 pk -> ECDSA key pair"
    );
}
