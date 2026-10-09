# PR #1 A2/A3/A4/B3 evidence summary

**Execution reference time:** 2026-10-08 16:02 KST (Main local); follow-up hosted/operational results are reported separately.
**Structured ledger:** [pr1-case-evidence.json](./pr1-case-evidence.json), schemaVersion 1.

## Original requirements and case results

The original requirements are A2(90–132), A3(134–164), A4(167–204), and B3(293–330) in the user-provided `PILLAR_CHANGES.md`. The results below are current execution/report evidence linked to stable case IDs; they do not represent a replay of the same case baseline/current pair from the original finding.

| Stable case ID | Original requirement | Current execution results and evidence | Evidence scope / determination |
|---|---|---|---|
| A2-FINALITY-LAG | Reject when finalized height < receipt height on Polygon/Tron | Existing verification report records rejection for lag and success for the equal-height control | verification report |
| A2-FINALITY-EQUAL-CONTROL | Allow finalized height == receipt height | Existing verification report records success at the exact height | verification report |
| A2-FINALITY-UNAVAILABLE | Fail closed when the required finalized tag is unsupported | AUDIT reports rejection without a latest fallback | runtime policy report |
| A3-READ-NOCODE-EMPTY | Pinned no-code is a non-retryable refusal after quorum agreement; sign stage 0 | no_code_negative_q2: HTTP 400, UNRESOLVABLE_COMMAND, retryable=false; healthy-quorum control HTTP 200 | TCP API handler + Reqwest fixture |
| A3-READ-CODE-PRESENT-EMPTY-CONTROL | Preserve valid empty READ results for code 0x00/0x6000 | Both cases return HTTP 200 and preserve the empty result | TCP API handler + Reqwest fixture |
| A3-READ-REVERT | Revert is a non-retryable refusal after quorum agreement; transport/timeout are separate errors | revert_negative_q2, standard_revert_negative_q2, absent_empty_revert_equal: HTTP 400, UNRESOLVABLE_COMMAND, retryable=false; non-domain errors HTTP 500 | TCP API handler + Reqwest fixture |
| A4-RECEIPT-IDENTITY-AND-REMOVED | Reject receipt/log transaction or block identity mismatches and removed=true | receipt-for-other-tx, log transaction/block mismatch, and removed-log negative case in source-consumer and proof artifacts | candidate 87b4bae source-bound local artifact |
| B3-RECEIPT-SEMANTIC-QUORUM-METADATA-CONTROL | Maintain semantic receipt quorum despite differences in irrelevant metadata such as l1Fee | valid-q2-l1fee-only signed; q2L1FeeEquality payload and signature bytes match | candidate 87b4bae source-bound local artifact |

## Coverage and instrumentation boundaries

The original report listed 351 comparisons, but the category total is 387. The retained materials contain no comparison ledger connecting the two totals. This document summarizes current results by stable case ID; the final determination for the original findings follows coverage.complete=false in the JSON ledger and verified=false for each case. Closing an original finding requires a baseline/current match for the same case ID.

The historical `signer_stage_count` is the number of metric series (0 or 1), not a numeric sample. The current value in RE003 schema 3 is an exact-tuple numeric observation; it is not interpreted as an SDK count or the number of actual signer/KMS calls. The raw artifact/hash linked to the execution result is retained in the [JSON ledger](./pr1-case-evidence.json).

## Separate execution results and remaining status

- **Main local workspace:** cargo test --workspace --locked exited with status 101. The Runtime target had 496 passed / 1 failed / 15 ignored. The existing config_loader log-capture assertion failure was recorded. The raw log is retained at maintainer-local audit/review-pr1-20261008/main-validation-95w4uR/workspace-test.log, with SHA-256 129b54eac4740fbc1e18e21957f8d0f45e94f0385dc338180e1b8b0e39e1fbe6.
- **Main local HTTP:** Expected and actual statuses matched for 33 cases using the fixture TCP API handler and Reqwest: HTTP 200 in 12 cases, 400 in 4 cases, and 500 in 17 cases.
- **Previous worker test-first record:** run-07 recorded five non-domain negative-Q2 inputs misclassified as 400 (SHA-256 9ad34908c2474db0dbfe11f4d53d44c169d9ae0919dd576b06728ada8997e022). Run-08 recorded matching statuses for 33 cases (SHA-256 5d1b39d4227e2a53478ad1981fba51393afc2a5488e4d20a8eaefbcc3edb5e25). The worker toolchain is rustc 1.96.0. These runs are maintained as separate source-bound records.
- **Follow-up hosted/operational results:** hosted run 37749547883 recorded 6/6 jobs successful and workspace results of 970 passed / 0 failed / 15 ignored. The CI image rollout and local execution are linked to their respective source identities. Operational sign-budget metrics are 0/0/0. Detailed evidence is in the follow-up evidence entries in the [JSON ledger](./pr1-case-evidence.json).

## RE-003: Numeric observation of READ stage

The 2026-10-09 follow-up verification uses Prometheus _count values for the exact stage/src_chain/dst_chain/status tuple. Two observations of the same series are counted as 2. Invalid numeric values or labels fail the test.

- Expected and actual statuses matched for all 33 real TCP HTTP cases: HTTP 200 in 12 cases, 400 in 4 cases, and 500 in 17 cases. The sign/ethereum/ethereum/ok observation is 1 for normal cases, and refusal cases have no sign tuple at any status.
- The regression based on the real metrics observer and targeted Clippy passed in the worker execution. Main's fmt check also passed. Main compared the raw artifact and source hash, and the independent reviewer checked the source and raw results in read-only mode.
- Final HTTP artifact: maintainer-local audit/review-re003-20261009/final-20261009-064136-kst/http-results.json, schema 3, SHA-256 ad84d144a8f69d0de2d0502635bd4cb4e44252fdcbfef5754b5c340dc65142d3. sign_stage_observation_count and stage_observations are stage observation values.
- Independent review: maintainer-local audit/review-re003-20261009/independent-review-followup.json, SHA-256 267fc2bfcd436649035f18cb6198da66a9ac31962ec122ded393297be25603ca. The detailed reproduction scope is in §14 of [AUDIT](../../AUDIT.md).

## In-repository case tests (2026-10-09)

Each stable case ID is linked to a committed test run by CI. The list is in the [JSON ledger](./pr1-case-evidence.json), under `inRepoCaseTests`. The record at the previous artifact path `retest-250-20261007/...` remains unchanged.

- Local run: `cargo +1.98.1 test --workspace --locked` was run in the worktree of `8b40220`. The result is 1004 passed, 0 failed, 15 ignored.
- Hosted CI: run `37903096415` on `b7fc3ab`, which merged `8b40220` into main, passed all 6 jobs. Workspace tests reported 1004 passed, 0 failed, 15 ignored.
- The B3 test receives a different receipt from each provider. With the receipt fingerprint reverted to raw JSON, this test failed with `2 distinct successful responses`, so it detects fingerprint normalization.
- The per-case `verified` value follows the ledger's `verifiedPolicy`.

Evidence: JSON ledger, comparison of final HTTP artifact and independent review · 2026-10-09 07:21 KST. In-repository case tests section: local workspace tests and mutation verification · 2026-10-09 16:59 KST, hosted CI run `37903096415` log · 2026-10-09 17:45 KST
