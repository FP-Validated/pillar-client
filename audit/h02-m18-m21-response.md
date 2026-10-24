# Sentry Code audit, H-02 and M-18 to M-21: remediation response

| | |
|---|---|
| Report | Round 1, 2026-10-23 |
| Fixes | Branch `steve-8000/security-audit-h02-m18-m21-fixes`, unreleased |
| Date | 2026-10-24 |

| Finding | Outcome |
|---|---|
| H-02 one READ command can OOM the signer | Fixed: returned data is capped per `eth_call` and per command phase, READ calls in flight are capped per command, per target chain and per process, and no second full copy is made |
| M-18 failing Aptos indexer erases the signing RPC's rank | Fixed: diagnostic probe entries never write rank |
| M-19 entries sharing a URL with different credentials share one rank | Fixed: rank is keyed by URL plus a digest of the headers dialled, in probe and dispatch alike |
| M-20 IOTA sender lookup binds the rendered PTB JSON | Fixed: the vote binds digest, sender, checkpoint and status only |
| M-21 zero DVN confirmations read as already signed | Fixed, departing from upstream: a Move count must be positive, and a Sui/IotaL1 missing record is unsigned |

All five were confirmed on `87bbbda` before the fixes. H-02, M-18 to M-20 and M-21 are
one commit each, then documentation; the tests named below are in
`crates/pillar-runtime/src/tests/`.

---

## H-02: READ results had no aggregate bound

**What we confirmed.** `resolve_payload` joined up to 256 request futures and held every
result, then concatenated them; `resolved_payload_hash` decoded the whole string into a
second buffer; the build details and the HTTP response each copied it again. Each vote
also held its result twice (`data:{result}` fingerprint plus the value). Beyond the
report, the compute path cloned every response for `OnlyReduce` and held 256 map results.

**What changed.**

| Bound | Where | Value |
|---|---|---|
| One request result | `eth_call_read_observation_at_block` | 1 MiB of returned data; larger is the vote `result-too-large` |
| One lzMap or lzReduce result | `compute_call` | 1 MiB of decoded `bytes`; the vote admits the 95-byte ABI head and padding on top |
| All request results of one command | `resolve_payload` | 1 MiB, charged as each completes, before it is kept |
| All lzMap results of one command | `resolve_compute_payload` | 1 MiB, the same way |
| READ calls in flight | `RuntimeEvmReadPayloadResolver` | 4 per target chain and per command phase, 16 per process; a call holds its permits until its quorum resolves, `eth_getCode` follow-up included |

Permits are taken chain first, then process, always in that order. Chain permits are
granted in arrival order, and a command queues no more calls than its chain's limit,
so a command arriving behind large ones waits for a few calls rather than for them to
finish. Chains whose providers stall hold at most four calls each, so three can stall
at once and a fourth still has four. A lone command still runs four calls at once: 256
requests with lzMap and lzReduce at 200 ms per call finish inside the 58 s deadline.

An oversized result agreed by the quorum, or a phase over its budget, is the
non-retryable 400 `UNRESOLVABLE_COMMAND` (`ReadV1002 command is unresolvable: an
eth_call result exceeds 1048576 bytes at the pinned block`, or `...: request results
exceed 1048576 bytes` / `lzMap results`), before signing. One provider's oversized answer
is one vote. The vote fingerprint is a SHA-256 digest; revert data is kept only in its
digest. `resolvedPayloadHash` is computed by decoding the payload in 4 KiB chunks into
Keccak, with odd-length padding and error positions as before. The no-compute payload
is allocated once at its known size; `OnlyReduce` moves the results instead of cloning;
the response payload is moved out of the build details when debug output is off.

**Why 1 MiB.** The no-compute payload is delivered to `lzReceive` in one destination
transaction; geth-family txpools refuse transactions over 128 KiB. lzReduce sends every
mapped result in one `eth_call`, and geth's default HTTP request limit is 5 MiB of JSON.
1 MiB is 8x the first and leaves the second room for ABI overhead. Upstream has no
limit, so a command over it is refused here and signed upstream.

**Memory.** One command now holds at most 1 MiB per phase (2 MiB as hex), plus at most
four calls' votes per chain and sixteen across the process, each vote at most one
result. The audit's shape (256 requests at the largest legal size, quorum 2 of 3) is
refused after the cap fills without dialling the rest; the child-process test records
its peak RSS (`h02-peak-rss.json`). Concurrent commands are still bounded by the signing
admission (64 active), each holding its own phase budget. "Per process" is per resolver;
the server builds one.

**Tests.** `h02_read_result_budget_e2e.rs`: per-call and per-phase boundaries (exactly 1
MiB signs, one byte more refuses); 256 legal results refused before the remaining
requests are dispatched; one hostile oversized provider loses only its vote while two
agreeing on oversize refuse; lzMap budget, and one lzMap and one lzReduce result of
exactly 1 MiB decoded resolve while 1 MiB + 1 refuses; one command peaks at four calls,
eight commands across four chains at sixteen with every chain at four; with three
chains stalling every call for 50 s under four commands each, the fourth chain's READ is
unaffected; a one-request command behind three 64-request commands on one chain
resolves within four call delays; a 256-request map-reduce command at 200 ms per call
resolves inside 58 s; the streamed hash equals
`keccak(guid || decode(payload))` for empty, `0x`, odd, multi-chunk and invalid
payloads; the production HTTP route signs a 1 MiB result with and without debug output
and answers 1 MiB + 1 with 400 `UNRESOLVABLE_COMMAND` and no sign stage; peak RSS of
the audit's shape in a child process.

## M-18: auxiliary probe overwrote the voting RPC's rank

**What we confirmed.** The Aptos/Movement indexer entry is `diagnostic` and excluded
from chain health (Round 3 L-04), but `seed_from_report` still recorded it under its
`report_url`. With `no-code-indexer` or `event-indexer` equal to the RPC base, the
indexer's failure (it answers a GraphQL POST at a REST URL) overwrote the RPC's rank.
The same holds for the Initia indexer and TronWeb entries.

**What changed.** `seed_from_report` skips diagnostic entries. Dispatch never looks one
up (`provider_rank_key` derives only the voting provider's identity), so nothing is lost.
TON v3 probe entries are not diagnostic (they decide TON health). They used to write
rank under the v3 endpoint while v3 dispatch looked up the v2 identity, so a dead v3
endpoint behind a live v2 one was dispatched first. Both now use `ton_v3_rank_key`,
`ton-v3 ` plus the v3 endpoint and its header digest, which no primary key can equal.

**Tests.** `m18_auxiliary_probes_never_write_the_voting_rank`: Aptos with the indexer at
the RPC base, RPC healthy and indexer failing, dispatches the RPC; RPC failing and
indexer healthy still refuses, on Aptos and Initia.
`m18_ton_v3_dispatch_ranks_by_the_v3_probe`: a dead v3 endpoint alone refuses v3
dispatch while v2 dispatch keeps it; with a live second provider, v3 dispatches the
live one first; the v3 key is never serialized.

## M-19: one rank slot per URL, whatever the credential

**What we confirmed.** Probe entries were keyed by the URL dialled and dispatch by the
URL alone, without headers; Aptos/Movement move `?auth=` into a header and drop the
query. Two entries with one URL and different keys shared a slot, and the later probe
won.

**What changed.** `provider_rank_key(chain, uri)` is the family's dial URL, plus, when
headers are sent, ` headers:` and a SHA-256 digest of the headers with lowercased names
in sorted order. Every voting probe (EVM, Aptos/Movement, Solana, Sui/IotaL1, Starknet,
Stellar, TON v2, Initia, Tron, Canton, and the unregistered-type fallback) and
`plan_dispatch` use this one function, so writes and lookups cannot drift. The digest is
taken after the Aptos `?auth=` move, so `?auth=K` and `authorization: Bearer K` are one
identity. An entry without headers keeps its plain URL key. The key is
`#[serde(skip)]` and never reaches `/provider-health`. Initia drops its query without
moving it to a header, so entries differing only in query are one identity, as dialled.

**Tests.** `m19_a_dead_credential_does_not_rank_the_live_one` (live only, live then dead,
dead then live, through the real probe, seed and dispatch; neither key nor credential is
serialized); `m19_rank_key_names_the_identity_dialled`.

## M-20: IOTA sender vote bound the rendered PTB

**What we confirmed.** `observe_sui_transaction_from` read only the sender but put
`/transaction/data/transaction` in the vote. In `iotaledger/iota` v1.34.1 the fullnode
renders transactions through its module cache (`iota-json-rpc/src/read_api.rs:1359`),
where `primitive_type` turns `Option<T>` into `vector<T>`
(`iota-json/src/lib.rs:625-627`), while `iota-indexer` uses the package resolver
(`iota-indexer/src/models/transactions.rs:268`). That the resolver renders the `Option`
struct is the report's claim; we did not run either backend.

**What changed.** The vote binds digest, sender, checkpoint and status. The transport
still checks the digest. Sui's arm bound canonical BCS and is aligned the same way.

**Tests.** `m20_iota_sender_quorum_ignores_the_rendered_ptb`: a fullnode-shaped and an
indexer-shaped answer for one transaction agree on the sender; a different sender or
checkpoint still splits the quorum.

## M-21: zero confirmations read as already signed

**What we confirmed.** `get_verification_confirmations` returns 0 when the DVN has no
record, in LayerZero-v2 Aptos and Initia `uln_302` (`msglib.move:107-109`) and in
LayerZero-Aptos-Contract `uln-301`; `is_verified` returns false without a record. The
recorded mainnet capture is `["0"]`. Pillar compared `count >= required`, as upstream
Gasolina does, so a required 0 made every packet already signed.

**What changed.** V302 (Aptos, Movement, Initia) signs-as-already-done only for state 2
or `0 < count >= required`; Aptos V301's `dvn_confirmed` gains the same `count > 0`. The
VERIFIED and inbound-nonce paths are unchanged. This departs from upstream; the worst
case is one redundant signature for a DVN that stored 0.

Sui and IotaL1 `uln_302::get_confirmations` aborts `EConfirmationsNotFound` without a
record (`receive_uln.move`, `table_ext::borrow_or_abort!`), and `verified` is false
then and `confirmations >= required` with one. Pillar read the abort as 0, as upstream
does, so a required 0 was signed; the abort is now no record and unsigned, and a stored
count, 0 included, is compared with `>=`. Stellar already read a `Void` answer as
unconfirmed and is unchanged.

The independent review of this change found that Pillar passed the raw 81-byte packet
header to `bytes32::from_bytes`, which aborts with `EInvalidLength`, also code 1
(`utils/sources/bytes32.move`). Upstream passes `keccak256(packetHeader)`
(`lz-v2-sdk/src/uln/sui/index.ts:387-391`), the key `receive_uln::verify` stores. So
on Sui and IotaL1 every DVN-confirmation read aborted and was taken for zero; only
state VERIFIED was ever detected. The header is now hashed first, and a payload hash
that is not 32 bytes is refused before any read, so code 1 can only come from
`get_confirmations`. No live `devInspect` was run.

**Tests.** `m21_zero_confirmations_are_unsigned_even_when_zero_are_required` (V302, the
recorded Aptos, Movement and Initia configs rewritten to require 0) and
`m21_v301_zero_confirmations_are_unsigned_even_when_zero_are_required`, through the
public route: count 0 signs at VERIFYING and VERIFIABLE, VERIFIED or a positive count at
the requirement is `Payload already signed`.
`m21_sui_and_iota_missing_confirmations_are_unsigned_even_when_zero_are_required`: on
Sui at a required 0 a missing record is unsigned and a stored 0 or 1 is already signed,
and `get_confirmations` receives `keccak256(packetHeader)`; on IotaL1 a missing record
is unsigned.

---

## Not changed

Nothing the review left open remains: the Sui/IotaL1 absence case, TON v3 ranking, READ
fairness across commands and chains, and the decoded lzMap/lzReduce boundary are fixed
above.
