# PR #1 A2/A3/A4/B3 evidence 연결 보고서

**Main 검증 실행 종료:** 2026-10-08 16:02 KST  
**구조화 원장:** [pr1-case-evidence.json](./pr1-case-evidence.json), schemaVersion 1

## 요약 및 판정 기준

사용자 제공 /Users/steve/Downloads/PILLAR_CHANGES.md에서 원본 요구사항을 직접 읽었습니다. A2는 Polygon/Tron finality, A3는 lzRead no-code/revert, A4는 receipt/log identity와 removed 검증, B3는 의미 기반 receipt quorum입니다. 원본 보고서의 351 comparisons는 개별 ledger가 없고 category 합이 387로도 보고되어, 351 전체 재실행이나 개별 ID 매핑을 주장하지 않습니다. 이 원장은 original requirement를 명시적인 stable case ID로 연결한 부분 증거입니다.

A4/B3의 보존 실행은 local candidate source/build/run 경로와 binary SHA-256이 일치하는 source-consumer/proof artifact에 연결됩니다. 이는 제한된 local source-bound 실행 근거이며 독립적인 bit-for-bit 재현성 증명은 아닙니다. 원본 351 ledger ID와 baseline/current same-ID replay가 없으므로 기존 finding을 fixed_verified로 닫지는 않습니다. 보고 요약과 raw artifact는 별도로 표시합니다.

## Case별 결과

| Stable case ID | Acceptance | Baseline | 현재 결과 / 정상 control | Sign-stage 근거 | 검증 상태 |
|---|---|---|---|---|---|
| A2-FINALITY-LAG | finalized < receipt 거절 | 원본 보고서에 결함 설명, raw baseline 미확보 | 기존 verification report가 Polygon/Tron lag 거절을 보고; equal-height control도 보고 | negative refusal / positive 1 invocation은 보고수준 | 미검증 |
| A2-FINALITY-EQUAL-CONTROL | finalized == receipt 허용 | baseline 미관측 | 기존 verification report가 정확한 height 성공을 보고 | sign-stage 1회 보고 | 미검증 |
| A2-FINALITY-UNAVAILABLE | 필수 finalized tag 미지원 시 fail closed | 미관측 | AUDIT는 latest fallback 없는 거절을 보고; 운영 provider별 지원 미검증 | counter 미관측 | 미검증 |
| A3-READ-NOCODE-EMPTY | pinned no-code는 non-retryable refusal, sign 0 | 원본 finding baseline bytes 및 351 ID 미확보 | no_code_negative_q2: HTTP 400, UNRESOLVABLE_COMMAND, retryable=false; healthy quorum control HTTP 200/1 | signer_stage_count 0 | run-07/08 test-first diff는 original baseline 아님; portable fixture 미확보; 미검증 |
| A3-READ-CODE-PRESENT-EMPTY-CONTROL | code 0x00/0x6000의 empty return 보존 | positive control | 두 case HTTP 200/signed; Main HTTP raw artifact SHA e8753b3e6df4e0611bbe49d6de302641c9ad011bda572bd6a4a05c7da37f60c4 | raw signer_stage_count 각 1 | selected 19-file snapshot; portable fixture 미확보; 미검증 |
| A3-READ-REVERT | revert는 quorum 합의 후 non-retryable refusal | 원본 raw baseline 미확보; run-07은 별도 pre-fix regression | revert_negative_q2 / standard_revert_negative_q2 / absent_empty_revert_equal: HTTP 400, UNRESOLVABLE_COMMAND, retryable=false; 비-domain 오류는 generic 500 | negative 0; healthy quorum control HTTP 200/sign 1 | local artifact; baseline/351 매핑 및 portable fixture 미확보; 미검증 |
| A4-RECEIPT-IDENTITY-AND-REMOVED | receipt tx mismatch, log tx/block mismatch, removed=true 거절 | 원본 보고, raw baseline 미확보 | source-consumer의 receipt-for-other-tx/removed-log 및 proof의 negative-transaction-hash (log tx)/negative-block-hash/negative-removed-true | negative HTTP 500, sign delta 0; positive q2 HTTP 200, delta 1 | candidate 87b4bae source-bound local runtime artifact; original ledger ID 미매핑 |
| B3-RECEIPT-SEMANTIC-QUORUM-METADATA-CONTROL | l1Fee 등 무관 metadata 차이에도 quorum | 원본 issue에 500 설명, raw baseline/ledger ID 미확보 | source-consumer의 valid-q2-l1fee-only: signed, q2L1FeeEquality payload/signature bytes 모두 동일 | HTTP 200, sign delta 1; byte equality 직접 artifact | candidate 87b4bae source-bound local runtime artifact; original ledger ID 미매핑 |

## Main workspace 및 HTTP runtime 결과

Main validation은 2026-10-08 16:02 KST에 종료했습니다. 이는 local Rust execution이며 배포 CI/kind workload 실행이 아닙니다.

- Toolchain은 Rust 1.98.1, aarch64-apple-darwin, RUSTFLAGS=-D warnings입니다. cargo fmt와 workspace all-targets clippy는 exit 0으로 통과했습니다.
- `cargo test --workspace --locked`는 exit 101로 종료했습니다. Runtime target은 496 passed / 1 failed / 15 ignored이며 workspace 전체 합계가 아닙니다. Main은 기존 config_loader log-capture assertion 실패를 직접 관측했고 source와 assert는 바꾸지 않았습니다. 원시 log는 `audit/review-pr1-20261008/main-validation-95w4uR/workspace-test.log`에 보존합니다. SHA-256은 `129b54eac4740fbc1e18e21957f8d0f45e94f0385dc338180e1b8b0e39e1fbe6`입니다. 원본 실패의 정확한 registration 순서는 미확인이므로 원인을 확정하지 않습니다.
- read-http/http-results.json은 TCP API handler + Reqwest fixture를 통해 33개 HTTP case를 실행했습니다. Raw SHA-256 e8753b3e6df4e0611bbe49d6de302641c9ad011bda572bd6a4a05c7da37f60c4, 423085 bytes. Expected/actual status 불일치 0건: HTTP 200 12건, 400 4건, 500 17건. Negative cases signer-stage 0, positive signed controls signer-stage 1입니다.

| Case | Expected / actual | Result | Sign-stage |
|---|---:|---|---:|
| no_code_negative_q2 | 400 / 400 | UNRESOLVABLE_COMMAND, retryable=false | 0 |
| revert_negative_q2, standard_revert_negative_q2, absent_empty_revert_equal | 400 / 400 | 같은 non-retryable domain refusal | 0 |
| empty_call_with_0x00_code, empty_call_with_0x6000_code | 200 / 200 | empty READ result 보존, signed | 각 1 |
| singleton_no_code_two_good, singleton_revert_two_good | 200 / 200 | healthy provider quorum 성공, signed | 각 1 |
| method-not-found / timeout / missing / string / null code의 negative-Q2 cases | 500 / 500 | generic error; domain code/retryable 필드 없음 | 0 |
| 위 다섯 오류의 corresponding singleton-two-good controls | 200 / 200 | 두 healthy provider로 정상 결과 | 각 1 |

Test-first worker evidence는 별도로 구분합니다. run-07/http-results.json (SHA-256 9ad34908c2474db0dbfe11f4d53d44c169d9ae0919dd576b06728ada8997e022)에서는 다섯 비-domain negative-Q2 입력이 기대 500 대신 400으로 분류됐고, run-08/http-results.json (SHA-256 5d1b39d4227e2a53478ad1981fba51393afc2a5488e4d20a8eaefbcc3edb5e25)에서 33개 전부 기대 status와 일치했습니다. Worker delivery의 toolchain은 rustc 1.96.0입니다. Baseline source manifest SHA-256 1e49011a0c1ebb5e09e3bf083a327b34060d394e4d22c57913edc847340bcaca의 helper SHA-256은 76ef90d7f348aa916c4cd23eb39fd6fca48fe15681584ef1400f02b7eb3ad865이고, final source manifest SHA-256 4c91c7a8297951ece3c2cc35d3c2ddc85cb7a83dc6d02235fdbf91b3dbc86790의 helper SHA-256은 291c678f059973624f30ac3cb76d4ecf1f02d7abe43a814cdd89d0673cd87026입니다. E2E test source hash는 양쪽 모두 fcf7551eb4159af10eec49dd6f2a48db2feb25359c562e9107503a40b4d6385b입니다. Worker run-07/run-08 binary digest는 delivery evidence에 없어 Main의 별도 runtime binary에 연결하지 않습니다. 이는 current source-snapshot regression의 전/후 근거이며 원본 351 ledger의 A3 baseline raw나 개별 ID 매핑으로 대체하지 않습니다.

Runtime test binary target/audit-review-20261008/debug/deps/pillar_runtime-60735513aadcc7c6 SHA-256은 a4089ef24da7720e083a89f3eb8f9547eaae3203c1b9d0e89a8b2d1db610eaf9입니다. Source link는 delivery-p2.json (SHA-256 2ce7fadaf4f03fa8a2fbce0a15242a8b0a9884d94284a9bc781126dcc252568a), source-p2-final.tar.gz (SHA-256 f45f4fb5aa79720ec1b098373d7cb2ce0e8719c046bb80323af15c2b55ca93ce), source-p2-final2-sha256.txt (SHA-256 4c91c7a8297951ece3c2cc35d3c2ddc85cb7a83dc6d02235fdbf91b3dbc86790)에 기록된 19 selected source/fixture/build-input/changelog files입니다. Cargo.toml SHA-256 264be26c8b564e3a08d216f081872dc6f8404e5389fafe81237fad878847dd2b, Cargo.lock SHA-256 51a70dc1eb052efffb7db4ba497055aee8f5220fb463ce08d43f37bfd8c0dd01. 이는 전체 checkout provenance가 아니며 binary는 87b4bae candidate release binary가 아닙니다.

해당 fixture/HTTP result는 maintainer-local evidence이며 sanitized portable replay fixture를 연결하지 못했습니다. Public reviewer의 재현성은 미확보입니다. Main이 배포 CI raw result를 확정 전달하기 전까지 deployed behavior, kind run, production verification은 주장하지 않습니다.

A4/B3 current-source/binary 연결은 다음 retained local evidence로 확인됩니다. `verify-candidate.sh`는 HEAD와 Cargo 입력을 기록하고 Cargo/crates 변경 없음 확인 뒤 Rust 1.98.1 native release build를 실행해 binary hash를 남기며 source-consumer를 같은 binary 경로로 구동합니다. Candidate identity의 commit 87b4bae/tree a4582f12, Cargo.toml/Cargo.lock hash 및 toolchain은 `final-supplychain/source-identity.json`와 일치합니다. `release-binary-hash.txt`, `source-consumer.json.executedBinarySHA256`, 그리고 `operating-receipt-consumer/2026-10-08T02-10-21-944Z/proof.json.binary.sha256`의 SHA-256은 모두 `1050398ac2c2f6713b83c863e2afccd866ef52c03351e3861454f841c69c433e`입니다. 즉 A4/B3 결과는 candidate 87b4bae의 제한된 local source-bound execution으로 다룹니다. 이를 독립적인 bit-for-bit reproducible build 주장으로 확대하지 않습니다.

Raw receipt proof SHA-256 `cecb6a7ec238a015e587225ead20fe74062d9137c478c22f7838a2ddfadd9000`; `positive-q2-raw-receipt.json` SHA-256 `93190991e1dc82d1e1aa90ee45ba7c2557281095d0e568e5359cd5d3a4d4b6e0`; `positive-metadata-only.json` SHA-256 `c8866e1ad132ec084d90860a0b245fc60031c68347c30f6c2c0cefbda24c2408`. 마지막 파일은 l1Fee 변형이 아니라 log `blockTimestamp` 변형입니다. B3의 l1Fee case 및 payload/signature byte equality는 candidate `source-consumer.json` SHA-256 `dabc8cc0eb6dc3d3adecfba83da8071fdbe9c6d148d836bc9cd0aa3b8944a680`에 직접 기록되어 있습니다. Proof scope는 운영 receipt를 바탕으로 한 synthetic loopback 변형이며 KMS, 실제 chain transaction, external submission은 없다고 기록합니다.

A2의 현재 결과는 /Users/steve/orca/workspaces/pillar-client/retest-250-20261007/audit/retest-250/verification.md와 AUDIT 요약에서 연결됩니다. Per-case raw output 및 binary/source binding이 여기 연결되지 않아 PASS가 아닙니다. A3 no-code/revert와 정상 control은 아래 Main HTTP E2E 결과에 직접 연결했습니다. Invalid code/malformed DATA 등 비-domain 오류는 generic 500 경로에 남는지 별도 case로 구분합니다.

## 관련 TON lifecycle 실행의 경계

TON-HTTP-LIFECYCLE-CONTEXT는 A2/A3/A4/B3 original finding이 아니므로 그 finding들에 오기하지 않았습니다. 보존된 Linux release log (/Users/steve/orca/workspaces/pillar-client/retest-250-20261007/audit/review-80e0ad21-20261008/linux-ton/evidence/final-linux-ton-http-e2e-run2.log; SHA-256 `3a3ae47ea8a50bda92de3ee88d16786ca0afb100bf22a36ac42058b9d3ff3806`)는 x86_64/Rust 1.97.1 실행과 lifecycle/depth output을 담습니다. `final-source-binding.log` (SHA-256 `182fd1976c9f1a5d2ec9559e1c0dd7bebbcab335df8a9049c2311f5e0c7a8418`)는 read-only mount된 test source와 Cargo.toml/lock hash를 commit 87b4bae와 대조합니다. Linux Dockerfile은 Cargo inputs와 `crates/`를 build context에서 COPY하지만 build log (SHA-256 `c1844ebb035e702af4613a9877eb529f39aea35cc7f788ca5b72a8aa619983b1`)에 source revision/tree 또는 production crate hashes가 없고, run은 test file 하나만 mount합니다. 따라서 이 Linux lifecycle output은 직접 관측된 test execution이나 image의 production code를 87b4bae에 source-bind하지 않습니다. 이것은 TON artifact의 계측범위 한계이며 A4/B3 native binary의 source linkage와는 별개입니다. macOS 29,261,824 bytes는 이전 실행 보고 값이며 새 macOS 결과로 사용하지 않았습니다. macOS worker의 최종 raw artifact가 도착하면 별도 run case로 추가해야 합니다.

## 외부 재현성 및 보안 경계

- A4/B3 receipt와 실행 결과는 retest checkout 내 maintainer-local 경로에만 있습니다. Public reviewer는 local path를 읽을 수 없습니다. Original bytes는 덮어쓰지 않았고 이 보고서에 복사하지 않았습니다.
- 이번 확인 범위에서 해당 실행에 연결된 sanitized portable receipt/fixture를 찾지 못했습니다. Public review에서 A4/B3 runtime replay는 재현 불가 gap입니다.
- READ consumer JSON도 local artifact이며 JSON만으로 raw HTTP exchange replay는 불가합니다.
- KMS secret, credential, 운영 설정 값, private agent records는 포함하지 않았습니다. 8ad87eb6…와 78bdd20e… reference 대상을 추측하거나 합치지 않았습니다.

## 갱신 규칙

Main의 local workspace/HTTP 결과는 현재 반영했습니다. 배포 CI는 아직 실행·검증된 것으로 포함하지 않습니다. 추가 runtime/CI 결과는 최종 worker report와 durable raw artifact, source/binary binding을 확인한 뒤 stable case에만 연결하며, 신규 case는 결과 확인 전 통과 처리하지 않습니다. Original 351 denominator 및 ID 매핑은 ledger 회수 전까지 complete=false입니다.

---

근거: 사용자 제공 /Users/steve/Downloads/PILLAR_CHANGES.md; audit/review-pr1-20261008/main-validation-95w4uR runtime/HTTP artifacts; audit/review-pr1-20261008/read-domain delivery-p2, source-p2-final2 manifest, run-07/run-08 raw results; candidate-87b4bae source/build/receipt records; Linux TON build/run records · 2026-10-08 16:02 KST
