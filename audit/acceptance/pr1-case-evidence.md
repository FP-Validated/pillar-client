# PR #1 A2/A3/A4/B3 evidence 요약

**실행 기준 시각:** 2026-10-08 16:02 KST (Main local); 후속 hosted/운영 결과는 별도 범위로 표기.
**구조화 원장:** [pr1-case-evidence.json](./pr1-case-evidence.json), schemaVersion 1.

## 원본 요구사항과 case 결과

원본 요구사항은 사용자 제공 `PILLAR_CHANGES.md`의 A2(90–132), A3(134–164), A4(167–204), B3(293–330)이다. 아래 결과는 stable case ID에 연결한 현재 실행/보고 근거이며, 원본 finding의 동일 case baseline/current 재생을 뜻하지 않는다.

| Stable case ID | 원본 요구사항 | 현재 실행 결과와 근거 | 근거 범위 / 판정 |
|---|---|---|---|
| A2-FINALITY-LAG | Polygon/Tron에서 finalized height < receipt height 거절 | 기존 verification report가 lag 거절과 equal-height control 성공을 보고 | verification report |
| A2-FINALITY-EQUAL-CONTROL | finalized height == receipt height 허용 | 기존 verification report가 정확한 height 성공을 보고 | verification report |
| A2-FINALITY-UNAVAILABLE | 필수 finalized tag 미지원 시 fail closed | AUDIT가 latest fallback 없는 거절을 보고 | runtime policy 보고 |
| A3-READ-NOCODE-EMPTY | pinned no-code는 quorum 합의 후 non-retryable refusal; sign stage 0 | no_code_negative_q2: HTTP 400, UNRESOLVABLE_COMMAND, retryable=false; healthy-quorum control HTTP 200 | TCP API handler + Reqwest fixture |
| A3-READ-CODE-PRESENT-EMPTY-CONTROL | code 0x00/0x6000의 유효한 empty READ 결과 보존 | 두 case 모두 HTTP 200, empty result 보존 | TCP API handler + Reqwest fixture |
| A3-READ-REVERT | revert는 quorum 합의 후 non-retryable refusal; transport/timeout은 별개 오류 | revert_negative_q2, standard_revert_negative_q2, absent_empty_revert_equal: HTTP 400, UNRESOLVABLE_COMMAND, retryable=false; 비-domain 오류 HTTP 500 | TCP API handler + Reqwest fixture |
| A4-RECEIPT-IDENTITY-AND-REMOVED | receipt/log transaction·block identity 불일치와 removed=true 거절 | source-consumer 및 proof artifact의 receipt-for-other-tx, log transaction/block mismatch, removed-log negative case | candidate 87b4bae source-bound local artifact |
| B3-RECEIPT-SEMANTIC-QUORUM-METADATA-CONTROL | l1Fee 등 무관 metadata 차이에도 의미 기반 receipt quorum 유지 | valid-q2-l1fee-only signed; q2L1FeeEquality payload 및 signature bytes 일치 | candidate 87b4bae source-bound local artifact |

## Coverage와 계측 경계

원본 보고서는 351 comparisons를 적었으나 category 합은 387이다. 두 집계를 연결하는 comparison ledger는 확보된 자료에 없다. 이 문서는 stable case ID별 현재 결과를 정리하며 원본 finding의 최종 판정은 JSON 원장의 coverage.complete=false 및 case별 verified=false 상태를 따른다. 원본 finding 종료에는 동일 case ID의 baseline/current 대응이 필요하다.

과거 `signer_stage_count`는 numeric sample이 아니라 metric series 개수(0 또는 1)다. RE003 schema 3의 현재 값은 exact-tuple numeric observation이며 SDK count나 실제 signer/KMS 호출 수로 해석하지 않는다. 실행 결과와 연결된 raw artifact/hash는 [JSON 원장](./pr1-case-evidence.json)에 보존한다.

## 별도 실행 결과와 잔여 상태

- **Main local workspace:** cargo test --workspace --locked는 exit 101로 종료했다. Runtime target은 496 passed / 1 failed / 15 ignored였다. 기존 config_loader log-capture assertion 실패를 기록했다. 원시 로그는 maintainer-local audit/review-pr1-20261008/main-validation-95w4uR/workspace-test.log에 보존하며 SHA-256은 129b54eac4740fbc1e18e21957f8d0f45e94f0385dc338180e1b8b0e39e1fbe6이다.
- **Main local HTTP:** fixture TCP API handler와 Reqwest에서 33 case의 expected/actual status가 일치했다. HTTP 200 12건, 400 4건, 500 17건이다.
- **과거 worker test-first 기록:** run-07은 다섯 비-domain negative-Q2 입력의 400 오분류를 기록했다(SHA-256 9ad34908c2474db0dbfe11f4d53d44c169d9ae0919dd576b06728ada8997e022). Run-08은 33 case의 status 일치를 기록했다(SHA-256 5d1b39d4227e2a53478ad1981fba51393afc2a5488e4d20a8eaefbcc3edb5e25). Worker toolchain은 rustc 1.96.0이다. 이 실행들은 각각의 source-bound 기록으로 관리한다.
- **후속 hosted/운영 결과:** hosted run 37749547883은 6/6 jobs 성공, workspace 970 passed / 0 failed / 15 ignored를 기록했다. CI image rollout과 local 실행은 각각의 source identity로 연결한다. 운영 sign-budget metrics는 0/0/0이다. 상세 근거는 [JSON 원장](./pr1-case-evidence.json)의 후속 evidence 항목에 있다.

## RE-003: READ stage numeric 관측

2026-10-09 후속 검증은 정확한 stage/src_chain/dst_chain/status tuple의 Prometheus _count 값을 사용한다. 같은 series의 두 관측은 2로 계산한다. 잘못된 numeric 값이나 label은 테스트를 실패시킨다.

- 실제 TCP HTTP 33 case의 expected/actual status가 모두 일치했다: HTTP 200 12건, 400 4건, 500 17건. 정상 case의 sign/ethereum/ethereum/ok 관측은 1이고, 거절 case에는 모든 status에서 sign tuple이 없다.
- 실제 metrics observer 기반 regression과 targeted Clippy는 작업자 실행에서 통과했다. Main의 fmt check도 통과했다. Main은 원시 artifact와 source hash를 대조했고, 독립 검토자는 source와 원시 결과를 읽기 전용으로 확인했다.
- 최종 HTTP artifact: maintainer-local audit/review-re003-20261009/final-20261009-064136-kst/http-results.json, schema 3, SHA-256 ad84d144a8f69d0de2d0502635bd4cb4e44252fdcbfef5754b5c340dc65142d3. sign_stage_observation_count와 stage_observations는 stage 관측 값이다.
- 독립 검토: maintainer-local audit/review-re003-20261009/independent-review-followup.json, SHA-256 267fc2bfcd436649035f18cb6198da66a9ac31962ec122ded393297be25603ca. 상세 재현 범위는 [AUDIT](../../AUDIT.md)의 §14에 있다.

## 저장소 안의 case 테스트 (2026-10-09)

이전 artifact 경로 `retest-250-20261007/...`는 maintainer-local 기록이며 현재 저장소에서 다시 실행할 수 없다. 기록 자체는 바꾸지 않는다. 각 stable case ID를 CI가 실행하는 커밋된 테스트에 연결했다. 목록은 [JSON 원장](./pr1-case-evidence.json)의 `inRepoCaseTests`에 있다.

- 로컬 실행: 기준 커밋 `abe9d60` 위의 `8b40220` 작업 트리에서 `cargo +1.98.1 test --workspace --locked`를 실행했다. 결과는 1004 passed, 0 failed, 15 ignored다. 이 작업 트리는 커밋과 비교해 이 원장, AUDIT §15, 주석 줄바꿈 2곳만 달랐다.
- Hosted CI: `8b40220`을 main에 머지한 `b7fc3ab`에서 run `37903096415`가 6개 job을 모두 통과했다. Workspace 테스트는 1004 passed, 0 failed, 15 ignored다.
- B3 테스트는 provider마다 다른 receipt를 받는다. Receipt fingerprint를 raw JSON으로 되돌린 변형에서 새 테스트는 `2 distinct successful responses`로 실패했다. 같은 변형에서 이전의 라운드 기반 테스트는 통과했다.
- 이 연결은 현재 회귀 테스트다. 원본 351 comparisons의 같은 case baseline 재생이 아니므로 case별 `verified`는 `false`로 유지한다.

근거: JSON 원장, 최종 HTTP artifact와 독립 검토의 대조 · 2026-10-09 07:21 KST. 저장소 안의 case 테스트 절: 로컬 workspace 테스트와 변형 검증 · 2026-10-09 16:59 KST, hosted CI run `37903096415` 로그 · 2026-10-09 17:45 KST
