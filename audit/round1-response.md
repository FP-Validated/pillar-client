# Sentry Code audit, Round 1: remediation response

| | |
|---|---|
| Baseline | `2f9305f0bd1644769169b50941ff5b72bab4be26` |
| Fixes | eleven commits on `main`, one per finding, `f30bb38`..`5a593e1`; documentation `0cec86c` |
| Status | On `main`; not yet part of a tagged release |
| Date | 2026-10-20 |

Every commit was checked on its own before it was pushed. It was formatted with
`cargo +1.98.1 fmt --all`, then passed
`clippy --workspace --all-targets --locked -- -D warnings` and
`test --workspace --locked` with zero failures. Each push has its own hosted CI run.
The tree at `0cec86c` is identical to the combined change that was verified before
it was split into commits. The hosted `audit, deny, sbom` job fails on the baseline
and on these runs, because of RUSTSEC advisories against `quinn-proto` 0.11.16 and
`rustls` that were published after the baseline. This response does not address
them.

| Finding | Commit | Outcome | Workspace tests after the commit |
|---|---|---|---|
| M-01 | [`f30bb38`](https://github.com/FP-Validated/pillar-client/commit/f30bb388bea795bd5e83ab7e7d9a6002987d1a01) | Fixed, different mechanism | 1,092 passed |
| M-02 | [`0907b3c`](https://github.com/FP-Validated/pillar-client/commit/0907b3cd2973c643411e335840471c3d89415ab0) | Fixed as recommended | 1,095 passed |
| M-03 | [`3985856`](https://github.com/FP-Validated/pillar-client/commit/3985856860c4e622ab64e1a9133a3e68b1ef380d) | Fixed, two limits differ | 1,096 passed |
| M-04 | [`a2290d0`](https://github.com/FP-Validated/pillar-client/commit/a2290d0369d00477a735941e5f1a1d06705c89e2) | Fixed as recommended | 1,097 passed |
| M-05 | [`90bf94f`](https://github.com/FP-Validated/pillar-client/commit/90bf94faa99a338a247a579b7b5a70c1398e625d) | Fixed as recommended, plus command binding | 1,101 passed |
| M-06 | [`cc4bf20`](https://github.com/FP-Validated/pillar-client/commit/cc4bf208065a1e06eada8417596ae8f5f8ac22ec) | Fixed as recommended, plus `blockTime` | 1,103 passed |
| M-07 | [`0cb7f4e`](https://github.com/FP-Validated/pillar-client/commit/0cb7f4ec32e41dada98ae165751f97eb13e369b4) | Fixed; optional L1-only policy not adopted | 1,104 passed |
| L-01 | [`e82e933`](https://github.com/FP-Validated/pillar-client/commit/e82e933ee960e058ec07a34a11e2891719d9d69f) | Fixed as recommended | 1,111 passed |
| M-08 | [`8143a9b`](https://github.com/FP-Validated/pillar-client/commit/8143a9b59a8937a5d724dfa37fb219faea476068) | Proposed fix not applied; hardened instead | 1,114 passed |
| L-02 | [`e86c656`](https://github.com/FP-Validated/pillar-client/commit/e86c656aca85430f541f6aa468f70d9780011376) | Fixed as recommended | 1,115 passed |
| L-03 | [`5a593e1`](https://github.com/FP-Validated/pillar-client/commit/5a593e162995e91632a72edb05b793bd6c548e97) | Fixed as recommended | 1,118 passed |

L-01 is committed before M-08 because M-08's trace binding reuses L-01's hash
normalization. Test counts are `test result:` totals and include three child-process
harness runs. 15 opt-in tests that need PostgreSQL, TLS or a live Canton ledger stay
ignored. The memory figures below are single `/usr/bin/time -l` runs of macOS debug
builds. They are not measurements of the Linux release image.

---

## M-01: unbounded provider JSON parsing and retained quorum values

**Outcome:** Fixed with a different mechanism from the one recommended.

**What changed**

- Every provider body is scanned for structural cost before any `serde_json::Value`
  is allocated (`ensure_json_parse_budget`, `provider_health/transport.rs`). The scan
  covers HTTP JSON and text, Lambda extra-context, Canton OAuth and sequencer
  responses, and the JSON embedded in Initia events and views. The limits are:
  - 131,072 structural units and nesting depth 128 in general;
  - 524,288 units and depth 512 for TON;
  - the existing 4 MiB wire cap.

  A body over any limit is refused before it is materialized.
- Admission for buffering and parsing: four shared slots. Each foreground target gets
  at most three active parses plus two queued, and background probes get one slot.
- Quorum retention:
  - fingerprints are streamed into SHA-256 (`canonical_json_fingerprint`), so no
    second full-size string is built;
  - only one representative value is kept per fingerprint;
  - retained values are charged against an estimated 8 MiB per candidate and a
    64 MiB shared pool;
  - reservations are released on cancellation.
- Sui GraphQL and IotaL1 event pagination: all pages kept for one request share a
  single 131,072-unit budget (`accumulate_paginated_structural_cost`). Pagination
  stops at the page that crosses it.

**Evidence**

| Case | Before | After |
|---|---|---|
| Broad receipt, real `pillar` binary | 178.9 MB peak RSS | 39.9 MB; refused before allocation |
| Standalone Initia resolver, 150,000 embedded objects | 129,073,152 B max RSS | 21,381,120 B; a normal recorded packet still resolves |
| 21 pages, each just under the per-response cap: 1 / 4 / 8 requests | 427 MB / 1.6 GB / not run | 73 MB / 152 MB / 173 MB; stops at page 3 of 21 |
| Four parses at the general cap | not run | 115.7 MB |
| Worst admissible mix: three TON parses plus one general parse | not run | 286 MB |
| 512-transaction TON trace, 4,127,526 bytes | not run | resolves |

Tests:
- `round1_bounded_json_ingress_rejects_broad_small_payloads`
- `round1_bounded_json_ingress_resolves_ton_trace_at_node_cap`
- `round1_paginated_events_share_one_structural_budget`. Before the fix it took 21
  pages; after the fix it stops at 3.
- `round1_parser_admission_keeps_cross_chain_headroom_and_releases_leases`. Bypassing
  fair admission makes this test fail, which confirms it detects the regression.
- `round1_json_quorum_budget_*`, covering deduplication, exhaustion and cancellation.

**Why we did not follow the recommendation as written**

- **Typed bounded deserialization.** We use a uniform scan before allocation instead
  of a typed struct per provider. Several paths deliberately consume generic JSON:
  quorum fingerprints and upstream-parity projections are computed over provider
  values whose shape varies by family. The scan bounds every one of those paths in
  one place. A typed struct only bounds the fields it declares.
- **`spawn_blocking`.** We did not move parsing to `spawn_blocking`. Once the scan
  bounds parse cost, the work per call is bounded. A blocking pool would add threads
  without lowering the memory peak, and memory was the resource the finding
  exhausted.
- **The limits are cost estimates.** They are not a process-wide RSS ceiling.
  `SECURITY.md` ("RPC and signing-input cost limits") documents what falls outside
  the pool: typed READ data, consumer-owned values, SDK buffers and signer state.

## M-02: integer overflow in Move, Initia and TON provider values

**Outcome:** Fixed as recommended.

**What changed**

- Move ledger timestamps and Initia calendar fields use checked arithmetic. An
  overflowing or out-of-range value makes that provider's answer a non-vote instead
  of panicking.
- TON confirmation ranges refuse a negative masterchain head, and refuse a
  subtraction that would overflow (`checked_sub`). A head that is behind the
  transaction counts as zero confirmations.

**Evidence**

| Input | Result |
|---|---|
| Aptos: `ledger_timestamp = i64::MAX`, as a number and as a string, answered first, then two honest providers | `Ok(1792454401)`; the honest quorum still forms |
| Initia: 17-digit year (`12345678901234567-01-01T00:00:00Z`) | Rejected (`None`) without a panic |
| TON: `last.seqno = i64::MIN`, `tx_seqno = 1` | 400 `block confirmation range overflow` |

Test: `round1_ton_confirmation_arithmetic_rejects_negative_head_and_clamps_behind_head`,
plus the overflow and calendar cases in `source_events_move`.

## M-03: unbounded Canton numeric and signature input

**Outcome:** Fixed. Two limits differ from the recommendation.

**What changed**

- Numeric strings are capped at 1,024 bytes before trimming or conversion
  (`MAX_JS_BIGINT_INPUT_BYTES`). Decimal parsing is linear.
- The committee signature is verified before chain-specific shape parsing, on both
  the scan path and the vApp path.
- Signatures are capped at 64 entries of at most 130 hex characters each. The
  configured quorum cannot exceed 64.
- The canonical committee payload is streamed into Keccak
  (`write_committee_payload`). It is no longer built as cloned, recursively
  concatenated strings.

**Evidence**

- A 4,000,000-digit `latestNonce`/`nonce` is refused in 2.27 ms.
- Test `round1_bigint_and_signature_shapes_are_bounded_before_work`: a
  100,000-digit value and 257 signatures are refused, while leading whitespace, `+`
  and `0X` forms are still accepted.
- The recorded upstream sequencer transcript still verifies.

**Why the limits differ**

- **1,024 bytes instead of 78 decimal digits.** Upstream reads these fields with
  JavaScript `BigInt(string)`. That accepts surrounding whitespace, a sign, leading
  zeros and `0x`/`0o`/`0b` forms. A binary `uint256` alone needs up to 258
  characters. A 78-digit cap would refuse values that upstream accepts. 1,024 bytes
  keeps every such spelling and still bounds the work: the cost is linear for
  decimal and limited by the byte cap for the other radices.
- **A fixed cap of 64 signatures instead of a multiple of committee size.** The
  committee is operator configuration, while the signature list comes from the
  sequencer. A cap tied to the local committee size could refuse a valid response
  signed by more committee members than the operator lists. A fixed cap bounds the
  recovery work to 64 ECDSA recoveries whatever the configuration.

## M-04: Base58 decoding of untrusted Solana instruction data

**Outcome:** Fixed as recommended.

**What changed:** `decode_solana_packet_sent_events` filters instructions by trusted
endpoint program id before it copies or Base58-decodes any instruction data. Untrusted
inner instructions are never decoded.

**Evidence**

- 63 untrusted CPI instructions of 13,985 characters each, alongside the recorded
  packet: the request resolves in 14 ms. Each decode the filter skips would have cost
  296 ms (about 18.6 s for all 63, debug build).
- A synthetic 1,000,000-character unrelated instruction: the recorded packet still
  resolves (nonce 3826) inside a bounded child process.

Test: `round1_solana_untrusted_large_instruction_does_not_mask_trusted_packet`.

## M-05: READ markers accepted on non-READ requests, and unbounded markers

**Outcome:** Fixed as recommended, with extra command binding.

**What changed**

- READ signing context requires `ReadV1002`, and `ReadV1002` requires READ context.
  Both checks run before source resolution.
- Caller timestamp markers are capped at 257: 256 requests plus an optional compute
  marker, matching the command decoder's own limit.
- Beyond the recommendation:
  - after the command is decoded, each caller resolution must match an actual command
    marker. Missing, extra, conflicting and out-of-range resolutions are refused
    before any readiness RPC;
  - identical resolutions are deduplicated, so they do not repeat RPC work.

**Evidence**

| Request | Result | Source resolver / RPC calls |
|---|---|---|
| V302 + READ context with 1,000 markers | 400 `READ signing context requires ReadV1002` | 0 |
| ReadV1002 without READ context | 400 `Invalid protocol type for ReadV1002` | 0 |
| ReadV1002 with 1,000 markers | 400 `resolvedTimestampTimeMarkers count exceeds maximum 257` | 0 |
| ReadV1002 with 257 markers | accepted | 1 |
| Real `pillar` binary, both mismatches and 258 markers | 400 envelopes | 0 `eth_getTransactionReceipt` |

Tests:
- `round1_core_rejects_both_protocol_mismatches_before_source_resolution`
- `round1_core_rejects_excess_read_markers_before_source_resolution`
- `round1_read_rejects_*_before_any_source_rpc`

## M-06: Solana source quorum over provider metadata

**Outcome:** Fixed as recommended, and `blockTime` is also bound.

**What changed:** Source resolution and extra-context share one projection,
`solana_transaction_projection`. It contains:

- `slot` (`u64`);
- `blockTime` (`i64` or `null`);
- `meta.err` (must be `null`);
- the fee payer;
- the `(programId, data)` pairs of trusted-program inner instructions.

Providers that differ only in fees, logs, compute units or parser metadata now agree.
A difference in any consumed field still splits the vote.

**Evidence**

- The original code produced two distinct successful fingerprints for the recorded
  transaction. The fixed resolver reaches quorum across two entities whose fees,
  logs, compute units and index metadata differ.
- Mutating `slot`, `blockTime`, the fee payer, or an inner program or its data
  changes the fingerprint.

Tests:
- `round1_solana_projection_ignores_metadata_but_binds_consumed_fields`
- `round1_solana_source_resolver_quorums_only_consumed_projection`

**Differences from the recommendation**

- **`blockTime` is in the projection.** It flows into the extra-context policy
  payload as `blockTimestamp`, so it is consumed and must be agreed on. A provider
  that omits the key entirely loses its vote. It is not counted as agreeing.
- **The extra-context path keeps every inner instruction.** The trusted-program
  filter applies to source resolution only. Upstream sends all inner instructions to
  the policy, so this path keeps parity.

## M-07: Starknet readiness not bound to the resolved receipt

**Outcome:** Fixed. The optional L1-only finality policy was not adopted.

**What changed:** Source resolution keeps Starknet evidence: the transaction hash,
block hash, block number, and the selected event's index and content. Readiness then
re-reads the receipt and the canonical block, and refuses any change to:

- the transaction identity;
- the block placement;
- the selected event's content or position;
- the execution status or finality;
- the canonical block hash.

**Evidence:** Each of eight binding changes is refused with its own message:
- block hash, block number;
- event removed, replaced, moved;
- transaction identity;
- execution status;
- canonical hash replaced.

A stable progression from L2 to L1 acceptance is still accepted. A malformed status
field is a non-vote.

Test: `round1_starknet_readiness_binds_resolved_event_to_current_canonical_receipt`.

**Why ACCEPTED_ON_L1-only was not adopted:** Both `ACCEPTED_ON_L2` and
`ACCEPTED_ON_L1` remain accepted, and `PRE_CONFIRMED` is refused. Requiring L1
acceptance would change the service's confirmation policy and hold every Starknet
attestation until L1 settlement. The finding concerned binding readiness to the
resolved receipt, which this change addresses. An L1-only policy is an operator
decision, not part of this fix.

## L-01: TON trace quorum ignored transaction hashes

**Outcome:** Fixed as recommended, plus a correction to hash decoding.

**What changed**

- Every trace node's normalized 32-byte transaction hash enters the quorum digest,
  including nodes whose `in_msg` is `null`.
- Map keys and node hashes must agree.
- Duplicate checks compare decoded bytes.
- The requested transaction must appear in the returned trace.
- Resolved hashes are logged with debug escaping.

During verification we found a bug: a hash was read as hex whenever it started with
`0x`. Standard base64 of a 32-byte hash can itself start with `0x`, about one hash
in 2,048. Such a hash is now read as hex only when it is exactly 64 hex digits, with
or without `0x`.

**Evidence**

- Changing a node hash changes the fingerprint.
- A malformed hash, or a map key that disagrees with its node, is rejected.
- Hex, base64 and base64url spellings of one request hash resolve to the same trace.
- Base64 hashes that begin with `0x` and `0X` resolve.
- Hashes containing a newline, carriage return or ESC never form a trace.

Tests:
- `round1_ton_trace_quorum_binds_every_message_node_hash`
- `round1_ton_null_message_node_hash_is_in_quorum_projection`
- `round1_ton_trace_rejects_map_key_hash_disagreement`
- `round1_ton_trace_rejects_malformed_provider_hashes`
- `round1_ton_base64_hashes_with_hex_like_prefixes_resolve`

## M-08: TON policy principal

**Outcome:** The proposed field substitution (`in_msg.destination` → `in_msg.source`)
was not applied. The principal derivation is kept, and the lookup is hardened to fail
closed.

**Why the substitution was not applied**

The finding reads the principal as if it came from the nested `PacketSent` message.
It does not. The code reads the `in_msg` of the **trace root** returned for the
requested transaction. On TON that root is the external-in message delivered to the
user's wallet:

- In the recorded mainnet trace
  (`crates/pillar-runtime/tests/gasolina_parity/source_replay/ton-v3-events.response.json`),
  the root `in_msg.source` is `null`. The root `in_msg.destination` is the originating
  wallet, `0:EF920DB74B637E091C6DB49B5C1C6A3E09908FFA31FB9547E6536DD7DB49CD2B`.
- The `PacketSent` sits nine levels deeper. Its message runs from the channel
  contract `0:316456309B…` to the controller `0:1EB2BBEA3D8C…`.
- Upstream does the same thing.
  `packages/sdks/rpc-sdk/src/ton/index.ts:230-236` (`getFromAddress`) returns
  `addressToHex(trace.transaction.in_msg.destination)`, with the comment "On TON the
  first in_msg is the external_in message that you sent to your wallet so this is the
  initial sender".

Applying the substitution would make the principal `null` for every valid trace. That
would fail every TON policy request. Reading a nested message's `source` instead
would name a LayerZero contract rather than the user. The current value is the
equivalent of EVM `from`: the account that started the transaction.

**What changed instead**

- The request hash must be a valid 32-byte TON hash (`ton_request_hash_valid`).
- The returned trace must contain the requested transaction
  (`ton_trace_contains_hash`). A provider cannot answer with a trace for a different
  transaction.
- The root `in_msg` must be present and its destination must parse strictly, as
  `0x` + 64 hex digits or a valid TON address (`ton_principal_address`). Any other
  value fails before the policy request is sent.

**Evidence**

- The recorded wallet root and the nested `PacketSent` stay valid.
- A malformed root wallet, or a trace for another transaction, never reaches the
  policy endpoint.

Tests:
- `round1_ton_recorded_trace_preserves_wallet_root_and_binds_nested_event`
- `round1_ton_malformed_root_wallet_fails_before_policy_request`
- `round1_ton_policy_cannot_switch_to_a_trace_for_another_transaction`

The legacy `/transactionTrace` fallback has not been exercised against a live
provider; upstream has the same gap. If you have a trace shape or a lookup path where
the root is not the external-in wallet message, please send it and we will re-assess.

## L-02: Aptos payload check used the source receive version

**Outcome:** Fixed as recommended.

**What changed:** The quorum-resolved receive version is passed to payload-signed
validation as `effective_receive_version`, so a V2 source routed to an Aptos V301
destination reads V301 signed state. The source's resolved `V2` label is not
rewritten. Initia and Movement V2-to-V301 routes are already refused at routing.

**Evidence:** Exercised through the public signing path:

- V301 state 0 (unsigned) → 200, with one signer call;
- V301 state 2 (already signed) → 400, with zero signer calls.

Test: `round1_v2_source_routed_to_aptos_v301_reads_v301_signed_state_before_signing`.

## L-03: `walletRestrictions` accepted but not enforced

**Outcome:** Fixed as recommended. It fails closed.

**What changed:** Any non-null `walletRestrictions`, including `{}`, `[]` and
`false`, is refused when configuration is loaded from the environment or from a file,
and again when it is converted for the runtime. Omitting the field, or setting it to
`null`, still means "no restriction". `SECURITY.md` states that no restriction policy
is implemented.

**Evidence**

- The real `pillar` binary exits before it starts listening, for `{}`, `[]` and
  `false`, with `Wallet restrictions are not supported`.
- With `null` it starts normally.

Tests:
- `round1_core_rejects_non_null_wallet_restrictions_before_signer_startup`
- `round1_core_rejects_non_null_wallet_restrictions_from_file_startup`
- `round1_core_accepts_omitted_and_null_wallet_restrictions`
