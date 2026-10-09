# pillar-client 2.6.0 retest

| | |
|---|---|
| pillar | 2.6.0 @ `09cec5c` (tag `v2.6.0`), compared with 2.5.0 @ `f5868d0`. The 2.6.0 code is `b7fc3ab`; the release commit changes only the version number. |
| Deployed | mainnet, `ghcr.io/fp-validated/pillar-dvn-client:ci-b7fc3ab41fec-r37903096415-a1@sha256:744309ed…` (2.6.0 code) |
| Reference | gasolina-audit 1.2.66 source archive `sha256:2e94b7cd…` |
| Date | 2026-10-09 |

## What was run

- **The workspace suite**, four times:
  - at `abe9d60`, before the review changes: 995 passed, 0 failed;
  - at `b7fc3ab`, locally: 1004 passed, 0 failed;
  - at `b7fc3ab`, hosted CI run `37903096415`: 6/6 jobs passed, 1004 passed, 0 failed;
  - at `09cec5c` (2.6.0), locally, with fmt, clippy `-D warnings` and the 1.94.1 MSRV check: 1004 passed, 0 failed.
- **The retest items' own tests**, 10 of them, with their evidence output printed.
- **Six counterexamples**, CE0–CE5. The same harness patch was run against both `f5868d0` and `abe9d60`.
- **Two mutation checks**, confirming that the new tests detect a reverted change:
  - the receipt fingerprint put back to raw JSON;
  - the readiness code before the F-5 change.
- **The mainnet rollout**: Deployment revision 18, 3/3 Ready. Six read endpoints matched before and after.

## Fixed in code since 2.5.0

The 2.5.0 column is this run's observation where a counterexample ran on `f5868d0`. Elsewhere it is the original retest's observation.

| Item | 2.5.0 | 2.6.0 | Commits |
|---|---|---|---|
| **Raw-JSON receipt fingerprint** | Two providers whose receipts differ only in `l1Fee` did not reach quorum: `2 distinct successful responses` (CE1, run here). | Signs once, with payload and signature bytes equal to the control. A PacketSent `data` difference is refused (CE2). | `80e0ad2`, tests `8b40220` |
| **Polygon/Tron finality** | Signed a Polygon packet above the `finalized` head. | Refuses when finalized is behind the receipt, or when the canonical header at the receipt height is missing or different. Signs once when it matches. Same chain list as the reference (`polygon`, `tron`). | `80e0ad2` |
| **Receipt/log consistency** | Signed for a `removed` log, a receipt for another tx and a log for another tx. | All three refused, sign stage 0. `removed: null` was signed on 2.5.0 (CE4, run here) and is refused now. An omitted `removed` is accepted on both. | `80e0ad2`, `5360159`, tests `8b40220` |
| lzRead empty `0x` | No `eth_getCode` follow-up. | `eth_getCode` at the same EIP-1898 pin. A unique NoCode or revert quorum is a 400 `UNRESOLVABLE_COMMAND`, `retryable=false`, before signing. Code `0x00`/`0x6000` is a valid empty return. | `80e0ad2`, `5360159`, `9e29dc9` |
| Recovery ids 2/3 | Search `0..=3`, so v = 29/30 was possible. | Rejected whenever the Ethereum-style transform is on. Raw signatures keep 2/3. | `80e0ad2` |
| Extra-context `signingContext` | Payload `{ sentEvent, from }`. | `{ sentEvent, from, signingContext }` on HTTP and Lambda, as the reference sends it. | `80e0ad2`, Lambda test `8b40220` |
| Readiness receipt RPC failure | 400 `source receipt binding changed: receipt unavailable` (CE5, run here; also at `abe9d60`). | 500 `Transaction receipt or block not found for <tx>`, the reference's text. A `null` receipt or a changed block or log is a 400. Signs in neither case. | `8b40220` |

## Found in this review, resolved in 2.6.0

The review of `abe9d60` found seven items. All are resolved in 2.6.0.

| Item | Found | Resolution |
|---|---|---|
| F-1 KMS key pinning | Each signer keeps the key identity it resolved first for the process lifetime, so key rotation takes effect on restart. | SECURITY.md, README and CHANGELOG describe rotation by replica restart and versioned key ids. |
| F-2 `l1Fee` regression test | The existing test gave both providers in a round the same receipt, so a raw-JSON fingerprint also passed it. | The test now gives each provider a different receipt, with a PacketSent `data` mismatch control. The raw-JSON mutation fails it. |
| F-3 Acceptance ledger | The case evidence pointed at maintainer-local paths. | `inRepoCaseTests` in `pr1-case-evidence.json` links the 8 cases to committed tests and hosted CI run `37903096415`. |
| F-4 Unmapped srcEid | The resolver comment quoted the reference's behavior incorrectly. | Comment corrected. HTTP tests pin the mapped-but-different 400 and the unmapped 500. |
| F-5 Readiness error class | A failed receipt re-read was counted as a changed source (400). | Counted as missing (500, the reference's text). The only runtime change in this review. |
| F-6 `removed` policy | Omitted, `null` and non-boolean `removed` needed tests. | Tests accept omitted and refuse `null` and non-boolean. AUDIT §11 marks the later change. |
| F-7 Documented conditions | The GCP/Azure identity comparison and the READ revert message comparison needed exact wording. | SECURITY.md and CHANGELOG state both conditions. |

Additional tests pin the Lambda `signingContext` payload, the empty `dvnAddress` behavior, and two URIs of one entity counting as one vote on the READ and Sui paths.

## Deliberate divergences

- **`debugInfo` formatting.** Unchanged by design.
- **Malformed-JSON and READ-on-V302 error text.** Unchanged by design.
- **vId on doma, lineasep, scroll and zksyncsep.** The EndpointV1 id is kept.
- **Source quorum.** Every provider is read and votes count per entity. Two URIs of one entity count as one vote on the READ and Sui paths.
- **Reverted receipts** are refused.
- **Unmapped source endpoint id** (`9626551`, `352774a`).
  - A trusted PacketSent whose `srcEid` this deployment does not map, with no other match, is a 500 `No chain name for endpoint id <n>`.
  - The reference skips the event and answers the 400 miss.
  - A mapped but different `srcEid` is the reference's 400.
  - HTTP tests pin both cases.
- **Unknown v1 chain id.** A 400 before any RPC. The text is the reference's; the reference's status is 500.
- **Empty `dvnAddress`.** It skips only the `hashLookup` duplicate query. Receive-library resolution and `verifiable` still run, which is stricter than the reference.

## Operational notes

- **KMS key rotation.** Rotate by restarting replicas, in the same change that updates the DVN's registered signer. Use versioned key ids. A sign response naming another key is refused.
- **GCP/Azure identity check.** The signer compares the key named in the sign response. With durable audit enabled it also requires the response to name a key.
- **Recorded-fixture coverage.** V2→V3 for migrated receivers, Canton, Stellar re-pin, and Sui, IOTA, Starknet, Stellar, TON and Aptos source resolution all pass. Sui reads over GraphQL and replays 33 equal / 9 stricter.
- **Mainnet.** After the rollout, readiness, version, chain list and signer identity matched the pre-rollout values.

## Net

Of the original eight "Not fixed" items:
- six are fixed in code: finality, receipt/log consistency, raw-JSON fingerprint, lzRead empty result, recovery ids and `signingContext`;
- two are unchanged by design: `debugInfo` and error text.

The seven items found in this review are resolved. F-5 changes runtime behavior; the others are tests and documentation.

How each fix is verified:
- The `l1Fee` fix and `removed: null` ran against 2.5.0 and the 2.6.0 code with the same harness.
- The other fixes are covered by tests on the 2.6.0 code. Their 2.5.0 behavior is the original retest's observation.

2.6.0 is released as `v2.6.0` and its code runs on mainnet.

근거: 로컬·hosted CI 테스트 출력, CE0–CE5 원시 출력(`ce-output.json`), mutation 실행, `git log -S` commit 대응, crane digest, ArgoCD·rollout 상태, 배포 전후 endpoint 비교, `09cec5c` 릴리스 검증 · 2026-10-09 18:04 KST
