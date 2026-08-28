use super::*;

/// How each destination family answers "was this payload already signed?".
///
/// Upstream reaches one `hasPayloadSigned` per family from
/// `App.validatePayloadSigned` (`apps/gasolina/src/app/app.ts:615-640`); this
/// port dispatches the same way in `validation_payload.rs`
/// `validate_payload_not_signed_with_quorum`. The rows below are the observable
/// consequence of that dispatch: the wire shape of the first on-chain read.
///
/// The table exists for exhaustiveness rather than for decoding. Every family's
/// decode rule already has its own tests; what none of them can catch is a new
/// destination family being added without deciding what its already-signed read
/// does. The dispatch ends in an EVM branch, so a forgotten family does not
/// fail - it quietly reads an EVM ULN contract on a chain that has none, and a
/// read that cannot find an attestation reports "not signed". That is the
/// failure this defends against: a missing row means a request signs twice.
struct FamilyRead {
    /// The name the dispatch matches on.
    chain_name: &'static str,
    /// Endpoint id, so the event resolves to a real configured destination.
    dst_eid: u64,
    /// Receiver encoding the family's own parser accepts.
    receiver: &'static str,
    /// DVN identifier in the family's own address encoding.
    verifier: &'static str,
    /// Upstream's entry point for this family, cited so a reader can check the
    /// row without a TypeScript checkout.
    upstream: &'static str,
    /// A substring of `"{url} {body}"` that identifies the family's read on the
    /// wire. `None` means the service must refuse before reading anything.
    first_read: Option<&'static str>,
}

/// Each family parses `receiver` with its own address rules, so the rows carry
/// the encoding that family's parser accepts - the same values its dedicated
/// tests use. A row carrying the wrong encoding would fail before any read and
/// be indistinguishable from a missing dispatch arm.
const EVM_RECEIVER: &str = "0x2222222222222222222222222222222222222222";
const SOLANA_RECEIVER: &str = "6td1W4vFnQsKKunmKprARgpMEtYdVBnZ2FVcpqxKxaoA";
const WORD_RECEIVER: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

const PAYLOAD_SIGNED_FAMILIES: &[FamilyRead] = &[
    FamilyRead {
        chain_name: "bsc",
        dst_eid: 30_102,
        receiver: EVM_RECEIVER,
        verifier: "0x3333333333333333333333333333333333333333",
        upstream: "packages/sdks/lz-v2-sdk/src/uln/evm/index.ts:186-240 hasDvnVerified/state",
        first_read: Some("eth_call"),
    },
    FamilyRead {
        chain_name: "solana",
        dst_eid: 30_168,
        receiver: SOLANA_RECEIVER,
        verifier: "4gnov6q1KFcjtwBjepBmQtuf5R4ho4XVkrytY8hk4CTF",
        upstream: "packages/sdks/lz-v2-sdk/src/uln/solana/index.ts:106-121 hasPayloadSigned",
        first_read: Some("getMultipleAccounts"),
    },
    FamilyRead {
        chain_name: "aptos",
        dst_eid: 30_108,
        receiver: EVM_RECEIVER,
        verifier: "0x3333",
        upstream: "packages/sdks/lz-v2-sdk/src/uln/aptos/index.ts:295-324 hasDvnVerified",
        first_read: Some("/view"),
    },
    FamilyRead {
        chain_name: "movement",
        dst_eid: 30_325,
        receiver: EVM_RECEIVER,
        verifier: "0x3333",
        upstream: "packages/sdks/lz-v2-sdk/src/uln/aptos/index.ts:295-324 hasDvnVerified",
        first_read: Some("/view"),
    },
    FamilyRead {
        // Initia speaks the Move view through a REST path of its own rather
        // than the shared `/view`, so it is a distinct row on purpose.
        chain_name: "initia",
        dst_eid: 30_326,
        receiver: EVM_RECEIVER,
        verifier: "0x3333",
        upstream: "packages/sdks/lz-v2-sdk/src/uln/aptos/index.ts:295-324 hasDvnVerified",
        first_read: Some("/initia/move/v1/accounts/"),
    },
    FamilyRead {
        chain_name: "starknet",
        dst_eid: 30_500,
        receiver: EVM_RECEIVER,
        verifier: "0x3333333333333333333333333333333333333333",
        upstream: "packages/sdks/lz-v2-sdk/src/uln/starknet/index.ts:99-124 hasPayloadSigned",
        first_read: Some("starknet_call"),
    },
    FamilyRead {
        chain_name: "sui",
        dst_eid: 30_378,
        receiver: WORD_RECEIVER,
        verifier: "0x3333333333333333333333333333333333333333333333333333333333333333",
        upstream: "packages/sdks/lz-v2-sdk/src/uln/sui/index.ts:501-523 hasPayloadSigned",
        first_read: Some("sui_"),
    },
    FamilyRead {
        chain_name: "iotal1",
        dst_eid: 30_423,
        receiver: WORD_RECEIVER,
        verifier: "0x3333333333333333333333333333333333333333333333333333333333333333",
        upstream: "packages/sdks/lz-v2-sdk/src/uln/sui/index.ts:501-523 hasPayloadSigned",
        first_read: Some("iota_"),
    },
    FamilyRead {
        chain_name: "ton",
        dst_eid: 30_343,
        receiver: "0:2222222222222222222222222222222222222222222222222222222222222222",
        verifier: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        upstream: "apps/gasolina/src/app/sdks/gasolinaSdk/ton/index.ts:129-249 hasPayloadSigned",
        first_read: Some("getAddressInformation"),
    },
    FamilyRead {
        // The one family this port does not read. Upstream calls
        // `ulnClient.confirmations` plus the `uln_verifiable` view; this port
        // has no Soroban read path, so it refuses instead of guessing. Left
        // unread AND unrefused it would fall through to the EVM branch, whose
        // "no attestation found" answer is "not signed" - the exact reading
        // that lets a payload be signed twice.
        chain_name: "stellar",
        dst_eid: 30_600,
        receiver: EVM_RECEIVER,
        verifier: "0x3333333333333333333333333333333333333333",
        upstream: "apps/gasolina/src/app/sdks/gasolinaSdk/stellar/index.ts:112-185",
        first_read: None,
    },
];

/// Records every request and refuses it, so the assertion is about which read
/// was attempted rather than what came back.
#[derive(Clone, Default)]
struct FirstReadRecorder {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl JsonRpcTransport for FirstReadRecorder {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(format!("{url} {body}"));
        Err("recorded".to_string())
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(url);
        Err("recorded".to_string())
    }
}

fn family_sent_event(row: &FamilyRead) -> LzSentEvent {
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = row.chain_name.to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(row.dst_eid));
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("receiver".to_string(), Value::from(row.receiver));
    event
}

#[tokio::test]
async fn payload_signed_family_table_covers_every_destination_the_dispatch_reaches() {
    for row in PAYLOAD_SIGNED_FAMILIES {
        let recorder = FirstReadRecorder::default();
        let getter = StaticProviderConfig::new(
            IndexMap::from([(
                row.chain_name.to_string(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri(format!(
                        "https://{}-rpc.example",
                        row.chain_name
                    ))],
                    quorum: Some(1),
                },
            )]),
            Some(&[row.chain_name.to_string()]),
        )
        .unwrap();
        let checks = runtime_rpc_validation_checks_from_evm_config(
            &ProviderSnapshotHandle::from_getter(&getter),
            recorder.clone(),
            "mainnet",
            &[row.chain_name.to_string()],
        )
        .unwrap_or_else(|error| panic!("{}: assembling checks failed: {error}", row.chain_name));

        // Every read here is refused by the transport, so no row can pass by
        // accident: the only thing observable is which read was attempted.
        let outcome = checks
            .validate_payload_not_signed(&family_sent_event(row), row.verifier, row.chain_name)
            .await;
        let calls = recorder.calls.lock().unwrap().clone();

        match row.first_read {
            Some(fingerprint) => {
                assert!(
                    calls.iter().any(|call| call.contains(fingerprint)),
                    "{} ({}): expected an on-chain read matching {fingerprint}, saw {calls:?}",
                    row.chain_name,
                    row.upstream
                );
                assert!(
                    outcome.is_err(),
                    "{}: a read that never answered must not be reported as unsigned",
                    row.chain_name
                );
            }
            None => {
                assert!(
                    calls.is_empty(),
                    "{}: expected no read at all, saw {calls:?}",
                    row.chain_name
                );
                let error = outcome.expect_err("an unread destination must refuse");
                assert!(
                    format!("{error}").contains("unavailable"),
                    "{}: refusal must say the read is unavailable, got {error}",
                    row.chain_name
                );
            }
        }
    }
}

/// The table above is only worth anything if it is complete. Every non-EVM
/// destination the router can build a payload for must appear in it, otherwise
/// a chain can be added, routed, signed, and never have its already-signed read
/// considered at all.
#[test]
fn payload_signed_family_table_names_every_non_evm_destination() {
    let mut listed = PAYLOAD_SIGNED_FAMILIES
        .iter()
        .map(|row| row.chain_name)
        .filter(|chain_name| *chain_name != "bsc")
        .collect::<Vec<_>>();
    listed.sort_unstable();

    // Transcribed from the dispatch arms in
    // `validation_payload.rs::validate_payload_not_signed_with_quorum`, which
    // is the only place a destination can be given a non-EVM read.
    let mut dispatched = vec![
        "solana", "aptos", "initia", "movement", "starknet", "ton", "sui", "iotal1", "stellar",
    ];
    dispatched.sort_unstable();

    assert_eq!(
        listed, dispatched,
        "a destination gained or lost a non-EVM already-signed read; the table in this \
         file and the dispatch must be edited together"
    );
}

/// Providers that could not answer must not be able to agree with each other.
///
/// Upstream reaches every family's read through a provider whose promise
/// *rejects* when the node is unreachable or the answer will not decode, and a
/// rejected promise never reaches the quorum function
/// (`packages/common-utils/src/multiFallbackQuorum.ts:52-132`). Folding those
/// failures into a shared "missing" value would let two dead endpoints form a
/// majority about a chain neither of them read - and because that majority
/// resolves as soon as it is reached, it can settle a request before a healthy
/// provider has answered at all.
///
/// Asserted for every reading family rather than for one, because the rule was
/// originally correct only on TON.
#[tokio::test]
async fn payload_signed_reads_never_let_failed_providers_form_a_majority() {
    for row in PAYLOAD_SIGNED_FAMILIES {
        if row.first_read.is_none() {
            continue;
        }
        let recorder = FirstReadRecorder::default();
        let uris = ["a", "b"]
            .iter()
            .map(|suffix| ProviderUri::Uri(format!("https://{}-{suffix}.example", row.chain_name)))
            .collect::<Vec<_>>();
        let getter = StaticProviderConfig::new(
            IndexMap::from([(
                row.chain_name.to_string(),
                ProviderConfig {
                    uris,
                    quorum: Some(2),
                },
            )]),
            Some(&[row.chain_name.to_string()]),
        )
        .unwrap();
        let checks = runtime_rpc_validation_checks_from_evm_config(
            &ProviderSnapshotHandle::from_getter(&getter),
            recorder,
            "mainnet",
            &[row.chain_name.to_string()],
        )
        .unwrap();

        let error = checks
            .validate_payload_not_signed(&family_sent_event(row), row.verifier, row.chain_name)
            .await
            .expect_err("two providers that never answered cannot clear a payload for signing");

        assert!(
            format!("{error}").contains("0 distinct successful responses, 2 errors"),
            "{}: both providers failed, so neither may count as a response: {error}",
            row.chain_name
        );
    }
}
