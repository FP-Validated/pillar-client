# Sentry Code audit, M-89 to M-95 and I-01: remediation response

| | |
|---|---|
| Report | Main Review, submitted 2026-10-28, source `3f39fba` (2.6.2) |
| Checked against | `1c44815` (2.7.3, `public/main`); every finding was still present |
| Fixes | PR #8, merged as `574ce42`; released as `v2.7.4` (`0369145`, PR #9) |
| Date | 2026-10-29 |

| Finding | Outcome |
|---|---|
| M-89 Solana readiness is not bound to the resolved source-event slot | Fixed: resolution records `SolanaSourceEvidence`; readiness refuses a re-fetch in another slot, and an event without evidence |
| M-90 Stellar can reject a new packet as if it were already signed | Fixed, departing from upstream: `Verified` is "already signed" only for a consumed nonce or this payload's stored hash |
| M-91 READ already-signed treats any stored hash as signed | Fixed: a stored READ hash no longer counts, and READ no longer reads `hashLookup` |
| M-92 unchanged remote provider data resets health history | Fixed: an unchanged refresh keeps its generation; a changed one drops only that chain's history |
| M-93 different reorg messages can let stale source data pass EVM quorum | Fixed in both stages: the quorum key has no prose, and the MPT re-read counts changed or missing receipts as a vote |
| M-94 a system proxy can rewrite supposedly local RPC answers | Fixed on both HTTP paths: literal loopback bypasses the environment proxy |
| M-95 READ timestamp resolution can splice blocks from different forks | Fixed: block N-1 must be block N's parent by `parentHash` |
| I-01 TON extra-context policy message hardening | No change: a missing, empty or unparseable TON principal is already refused (`validation_extra_context.rs`, `observe_ton_transaction_from`) |

The new scenarios are one test, `crates/pillar-runtime/src/tests/m89_m95_remediation_e2e.rs`.

---

## M-89: the re-fetched slot was never compared with the resolved one

**What we confirmed.** `solana_packet_to_lz_sent_event` stored `slot` in `extra`, and readiness
received only the transaction signature. `observe_solana_slot_confirmations` took the slot of
its own `getTransaction` response and counted confirmations from it. Both reads ask for
`finalized`, so this needs providers that disagree, not a reorg; the missing comparison is
still real, and a quorum agrees on the slot only among themselves.

**What changed.** `pillar_core::SolanaSourceEvidence { slot }` joins `SourceEvidence`, set by the
resolver. Readiness passes it down and answers `SourceChanged` when the slot differs, before
any confirmation is counted. Without evidence readiness fails closed. The extra-context policy
body still reads `extra` for Solana, as before.

## M-90: a Stellar `Verified` view was read as "this DVN already signed"

**What we confirmed.** `uln_verifiable` answers `Verified` whenever `__endpoint_verifiable` is
false. From the contract source (`@layerzerolabs/protocol-stellar-v2` 1.2.66,
`layerzero-views/src/layerzero_view.rs`, `endpoint-v2/src/endpoint_v2.rs`) that includes a nonce
more than `PENDING_INBOUND_NONCE_MAX_LEN` (256) past `inbound_nonce` with no stored hash, an
invalid receive library, and an empty payload hash, besides a consumed nonce or a stored hash
equal to the payload's. The report says "inside the pending window"; the contract refuses
outside it. The refusal was transient (the window moves) but named "Payload already signed".

**What changed.** When the view says `Verified` and this DVN has no confirmation, two endpoint
reads decide: `inbound_nonce` (nonce at or below it: done) and `inbound_payload_hash` (equal to
this payload: done). Otherwise the packet is not signed yet. The calls are encoded with
`@stellar/stellar-sdk` 16.0.1 and added to `tests/gasolina_parity/stellar_payload_signed.json`
by `scripts/gasolina-parity/emit-stellar-payload-signed.ts`; every existing entry came out
byte-identical. This departs from upstream, which refuses on `Verified` alone.

## M-91: any stored READ hash counted as signed

**What we confirmed.** `ReadLib1002.verify` overwrites `hashLookup[header][cmd][dvn]`
unconditionally, `commitVerification` needs every required DVN to hold the expected hash and
then deletes them, and `ReadLib1002View.verifiable` reports `Verifying` for a stale hash. The
READ arm of `evm_hash_lookup_is_confirmed` returned true for any non-zero hash, so the
replacement could never be produced. `blockConfirmation: 0` is accepted, as reported.

**What changed.** READ is never "signed" by its stored hash; the verdict rests on the view's
`Verified` state, and the `hashLookup` call is no longer made for READ (`EvmHashLookupResult` is
now the message form only). A `dvnAddress` on a READ request is ignored, so it is not
validated. The cost is a redundant signature when the stored hash already matches.

## M-92: the unchanged remote poll discarded the health history

**What we confirmed.** `apply_refreshed_snapshot` published every accepted refresh, `publish`
always incremented the generation, and the health source cleared its observations on a
generation change. `/ready` leans on the recent-healthy fallback when probes are refused
admission, so the first round after a refresh under load could answer 503.

**What changed.** `publish` returns the serving snapshot when providers and roster are equal.
Health observations are kept per chain with the provider configuration they were measured
against and are used only while it is unchanged; an overlapping older round cannot replace a
newer generation's entry.

## M-93: reorg observations split the vote

**What we confirmed.** The readiness key was `format!("{:?}", validity)`, which carries the
`SourceChanged` text (the block hash a provider saw, or "disappeared"). Under four providers
and `any: 2`, a moved and a missing receipt were two groups and the two providers on the old
receipt settled alone. The ULNv2 MPT re-read turned a changed receipt into an absent vote.

**What changed.** `BlockConfirmationValidity::fingerprint()` is the key at all seven readiness
sites (EVM, TON, Move, Sui/IOTA, Starknet, Stellar, Solana). `observe_uln_v2_mpt_hash_info`
returns `UlnV2MptVote::{HashInfo, SourceChanged}` and the quorum resolves over both.

## M-94: the process proxy answered requests addressed to loopback

**What we confirmed.** `ReqwestJsonRpcTransport` built its client from the environment, and the
READ path used `Matcher::from_system()`. Config validation (`validate_service_url`) and the
mainnet warning treat literal loopback as local, so a proxy could answer a request addressed to
`127.0.0.1` and see its bearer token. HTTPS goes through a CONNECT tunnel, so the exposure is
plaintext loopback.

**What changed.** `pillar_config::is_literal_loopback` is the one predicate, used by the
validation, the warning and both transports. Loopback requests use a client built with
`no_proxy()`, and the READ path skips the matcher. Other hosts keep using the environment's
proxy. The `pillar-client` SDK crate, which calls a Pillar server rather than a provider, is
unchanged.

## M-95: block N and N-1 came from separate quorum rounds

**What we confirmed.** `BlockTime` dropped `parentHash`, and `block_matches_resolved_timestamp`
checked the two timestamps only. The two rounds could settle on different forks; only block N's
hash was pinned.

**What changed.** `BlockTime` carries `parent_hash` (part of the quorum fingerprint) and the
predicate requires `previous.number + 1 == block.number` and `previous.hash == block.parent_hash`.
Block N's pinned hash commits to its parent, so no separate predecessor pin is needed. The
test-only resolver shares the predicate.

---

## Verification

The one end-to-end test runs each failure mode through the production path and records its
outcome as an artifact: M-89 (slot 900 against 1000), M-90 (five `Verified` cases and a failing
endpoint read), M-91 (three READ states and a message-library control), M-92 (an unchanged and a
real publish under refused admission), M-93 (readiness and MPT, four providers, `any: 2`),
M-94 (a child process with a hostile `HTTP_PROXY`: loopback answered by the honest listener on
both HTTP paths, a host name still proxied), and M-95 (a splicing provider). Run on the final
tree: 1 passed, 32.18 s. The PR's CI (all six jobs) ran the rest of the workspace suite. One
existing test pinned the old Solana behaviour and was changed; the READ and timestamp fixtures
gained parent hashes.
