# Sentry Code audit, M-22 to M-25: remediation response

| | |
|---|---|
| Report | Round 1, 2026-10-23 |
| Fixes | Branch `steve-8000/security-audit-m22-m25-fixes`, on the H-02 to M-21 branch, unreleased |
| Date | 2026-10-26 |

| Finding | Outcome |
|---|---|
| M-22 low-confirmation TON attestation pins the duplicate check | Fixed, departing from upstream: an attestation counts as signed only at the pathway's required confirmations, and a TON MESSAGE request below them is refused before any source read |
| M-23 unverified Canton scan copies and sorts a huge answer | Fixed in part before this round, completed here: the committee check already ran first and the digest is streamed; the events array is now moved, not copied |
| M-24 a slow READ target holds shared call slots | Fixed: per-chain READ permits (H-02) taken before the process permit, and both waits end at the request deadline |
| M-25 nested JSON in `RawValue` bypasses the depth guard | Fixed, at more sinks than reported: every JSON parse of outside input refuses the reserved key, and Clippy refuses new direct `serde_json` parse calls |

All four were confirmed on `201430d` (`main`) before the fixes. The new tests are in
`crates/pillar-runtime/src/tests/m22_m25_remediation_e2e.rs`.

---

## M-22: the already-signed check ignored the attestation's confirmations

**What we confirmed.** `dvn_attestation` compared `Attestation.hash` with the packet hash
and nothing else. The TON `UlnConnection` (`ulnConnection/handler.fc`) stores whatever
attestation a configured DVN submits for a nonce in range, after `lz::Attestation::validate`
checks only its shape, overwriting that DVN's previous one, while `_committable` and
`verifiedView` count it only at `confirmations >= requiredConfirmations`. Upstream's
`hasDvnVerified` (`lz-v2-sdk/src/uln/ton/index.ts:194-206`) also compares the hash alone;
EVM, Solana, Move, Sui, Stellar and Canton all compare confirmations. Starknet reads the
contract's own `has_payload_signed` and was left as it is.

The contract's semantics were not assumed from source. The pinned mainnet `UlnConnection`
code (code hash `3a34588c…`) was run in `@ton/sandbox` 0.45.0 with the live mainnet
storage and one DVN attestation set below, at and above the requirement, with the custom
and default configuration each supplying it
(`scripts/ton-contract-semantics/emit-confirmations.mjs` →
`crates/pillar-runtime/tests/ton_contract_semantics/confirmations.json`). `verifiedView`
counts it at `stored >= required` and not below, and with `confirmationsNull` set on the
OApp's configuration the default's value is used whatever the default's own null flag;
upstream TypeScript throws there instead.

**What changed.**

- `effective_receive_confirmations` is `resolveConfirmations`; `dvn_attestation` returns
  `Matches` only for a hash match at or above it and `InsufficientConfirmations`, which is
  unsigned, below it. A replacement is signed, and the contract keeps the newer one.
- A TON-destination MESSAGE request whose `blockConfirmation` is below the requirement is
  a 400, `blockConfirmation N is below the R confirmations the destination receive config
  requires`, before any source-chain read. The requirement is quorum-agreed over the same
  two storage cells the already-signed check reads. Such a signature can never be counted
  and can only displace this DVN's usable attestation, so this is the step that keeps the
  duplicate check from being pinned in the first place. Upstream signs it.

**Tests.** `m22_ton_already_signed_matches_the_deployed_contract`: for each emulated case
the verdict equals the contract's `verifiedView`, and the packet this service derives is
the packet the contract was asked about. `m22_ton_confirmation_floor_refuses_below_requirement_before_source_reads`:
one below the requirement is a 400 after the two TON storage reads only; at the
requirement readiness proceeds to the source chain.

## M-23: the Canton scan copied the events array

**What we confirmed.** The code the report quotes was replaced on 2026-10-20 (`3985856`):
the committee signature is checked before any shape work, and the digest is computed by
streaming the canonical form into Keccak, not by cloning the response. The response is
bounded by the parser at 4 MiB and 131,072 nodes (`f30bb38`). What remained was
`events.clone()` in `scan_events`, reached with or without a committee.

**What changed.** `scan` hands the verified body to its shape function by value and the
events array is moved out. A committee-less sequencer is upstream's `NoopQuorumVerifier`
and remains allowed; making the committee mandatory is a trust-model change, not this fix.

**Tests.** `m23_committee_less_scan_near_the_cap_is_bounded`: a 3 MiB committee-less scan
of non-matching events ends in the ordinary refusal well inside ten seconds.

## M-24: a waiting READ call held a shared slot

**What we confirmed.** On `main`, each provider call took one of 32 shared permits before
the target chain's RPC budget, so calls queued behind a saturated chain held permits an
idle chain needed. The H-02 change already replaced this: a call takes its target chain's
permit (4) first and only then a process permit (16), so one stalled chain holds at most
four. Neither wait was bounded by the request deadline.

**What changed.** Both waits are bounded by the signing request's deadline, and the
error is the existing admission timeout. A caller outside an HTTP request has no deadline
and waits as before.

**Tests.** `m24_read_permit_wait_ends_at_the_request_deadline`: with the only permit held
by a stalled call, a second call under a 300 ms deadline returns
`Admission(Deadline)` at the deadline.

## M-25: the `RawValue` re-parse reset the depth budget

**What we confirmed.** `serde_json` 1.0.150 `Value`'s `Deserialize` re-parses the string
under a first key `$serde_json::private::RawValue` with a fresh 128-level budget
(`value/de.rs:132-134`). The feature is enabled by `axum` 0.7.9, not by `Cargo.toml:103`,
which enables `unbounded_depth`, so removing a feature is not available. Fourteen nested
re-parses carry 1,905 containers in 69,776 bytes, under the 100 KiB body limit. The same
re-parse is reached from the body envelope, from every provider response (whose
structural pre-scan counts only the outer document) and from the client.

**What changed.** `pillar_core::json` builds `Value`s with its own visitor, a copy of
`serde_json`'s except that an object key equal to the `RawValue` or `Number` token is
refused at any position, escaped spellings included. Typed parses (wallets, provider
configuration, the AWS secret) first walk the document under the same refusal. The
request body, envelope, provider responses (both the plain and the stacker-guarded TON
path), the client and the configuration loaders use it. `clippy.toml` disallows
`serde_json::from_str`/`from_slice`/`from_reader`, the `Deserializer` constructors and
`reqwest::Response::json`, and CI builds with `-D warnings`, so a new direct parse fails
the build; test code is exempt.

**Tests.** `m25_nested_raw_value_body_is_a_400_on_a_small_stack` (the report's shape, on
tokio's default 2 MiB worker stack, in a child process), `m25_reserved_key_is_refused_on_every_ingress`
(first key, escaped key, nested non-first key, number token, envelope, provider responses
plain and TON, depth 127 accepted and 128 refused) and
`m25_hardened_parser_matches_serde_json_on_every_fixture` (every committed JSON file parses
to the same `Value` as `serde_json`).

---

## Not changed

- Starknet reads `has_payload_signed` from the contract; whether the deployed Cairo
  compares confirmations was not established, and no change was made there.
- A Canton sequencer without a committee is still accepted, as upstream accepts it.
- With four target chains stalled at once, the sixteen process READ permits are all
  held; the fifth chain waits until its deadline.
