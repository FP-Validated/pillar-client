use crate::packet::EvmUlnProof;
use crate::solana::{
    execute_transaction_digest_bytes, find_program_address, public_key_bytes,
    solana_message_library_address, solana_verify_instruction_data, TransactionAccount,
    SOLANA_ULN_PROGRAM_ID, VERIFY_DISCRIMINATOR,
};

#[test]
fn solana_verify_data_uses_kinobi_layout() {
    let proof = EvmUlnProof {
        packet_header: format!("0x{}", "11".repeat(81)),
        payload_hash: format!("0x{}", "22".repeat(32)),
    };

    let data = solana_verify_instruction_data(&proof, 64).unwrap();

    assert_eq!(&data[..8], VERIFY_DISCRIMINATOR);
    assert_eq!(&data[8..89], vec![0x11; 81]);
    assert_eq!(&data[89..121], vec![0x22; 32]);
    assert_eq!(&data[121..], 64_u64.to_le_bytes());
}

#[test]
fn execute_digest_uses_kinobi_field_order() {
    let account = TransactionAccount {
        pubkey: [0x33; 32],
        is_signer: true,
        is_writable: false,
    };

    let data = execute_transaction_digest_bytes(7, &[0x11; 32], &[account], &[0xaa, 0xbb], 9);

    assert_eq!(&data[..4], 7_u32.to_le_bytes());
    assert_eq!(&data[4..36], &[0x11; 32]);
    assert_eq!(&data[36..40], 1_u32.to_le_bytes());
    assert_eq!(&data[40..72], &[0x33; 32]);
    assert_eq!(&data[72..74], &[1, 0]);
    assert_eq!(&data[74..78], 2_u32.to_le_bytes());
    assert_eq!(&data[78..80], &[0xaa, 0xbb]);
    assert_eq!(&data[80..], 9_i64.to_le_bytes());
}

#[test]
fn solana_public_key_decodes_base58_like_sdk() {
    assert_eq!(
        hex::encode(public_key_bytes(SOLANA_ULN_PROGRAM_ID).unwrap()),
        "619e429a1de67854bd455ee6643f568d6236cde8e9442a3abf029f016faae630"
    );
}

#[test]
fn solana_message_library_pda_matches_pinned_sdk() {
    assert_eq!(
        solana_message_library_address(SOLANA_ULN_PROGRAM_ID).unwrap(),
        "2XgGZG4oP29U3w5h4nTk1V2LFHL23zKDPJjs3psGzLKQ"
    );
}

#[test]
fn solana_pda_matches_sdk_event_authority() {
    let program_id = public_key_bytes(SOLANA_ULN_PROGRAM_ID).unwrap();
    let pda = find_program_address(&[b"__event_authority".as_slice()], &program_id).unwrap();

    assert_eq!(
        bs58::encode(pda).into_string(),
        "7n1YeBMVEUCJ4DscKAcpVQd6KXU7VpcEcc15ZuMcL4U3"
    );
}
