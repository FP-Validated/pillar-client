# Sentry Code audit, Round 3: remediation response

| | |
|---|---|
| Baseline in the report | `3f39fbad972794e5a9c598ea46a310334a4a4415` (2.6.2) |
| Branch point | `201430d26feaa5bc2339479e4c7adecbeff21ef7` (`main`, 2.7.1 records) |
| Fixes | `12c2d87` (M-12), `bcf0d7f` (M-13), `d48b9a4` (M-14), `76eb188` (L-04); same class as M-12 outside the findings `dd02252`; unreleased |
| Date | 2026-10-22 |

All four findings were still present on `main` at `201430d`, which carries the
Round 1 and Round 2 remediation. M-12 and M-13 were first reproduced there with
throwaway tests through the production resolver and validator; M-14 by dropping
`get_provider_health_report` mid-round. The first regression tests were written before
the fixes and failed on `201430d`; the ones added later fail with their fix reverted.

| Finding | Commit | Outcome |
|---|---|---|
| M-12 Aptos quorum on whole JSON | `12c2d87` | Quorum and the retained value use the consumed fields only |
| M-13 TON v2-only `Missing` votes | `bcf0d7f` | Only `v3-endpoint` providers are planned, counted and asked, in all three TON v3 paths |
| M-14 report cache bypass by disconnect | `d48b9a4` | The report is the retained result of the health round; no caller runs or cancels a round |
| L-04 auxiliary probes in chain health | `76eb188` | Auxiliary entries are `diagnostic`, excluded from chain health, and cannot fail the round |

---

## M-12: Aptos-family source quorum compared whole REST answers

**Outcome:** Fixed as recommended, with a wider field set than the report's table.

**What we confirmed first.** `get_move_transaction` and `get_aptos_json` fingerprinted
the provider's whole JSON. With two providers at quorum 2 and the archived mainnet V301
transaction (`tests/gasolina_parity/aptos_v301_source_tx.json`), removing only
`txn_limits_request` from one answer, or filling the three `write_table_item.data`
values as a table-info indexer node does, gave `No Move transaction … quorum: response
set is ambiguous or incomplete; 2 distinct successful responses, 0 errors`. Identical
answers resolved. The fixture also carries `replay_protection_nonce`, another field a
release added, so the same split recurs whenever the REST schema grows.

**What changed**

- A Move transaction keeps `hash`, `txhash` (Initia), `version`, `type`, `success` and
  `events`; a block keeps `block_height` and `block_hash`. The projection is both the
  fingerprint and the value returned, by moving the fields out of the response.
- It applies to the `by_hash` source read and every `get_aptos_json` transaction and
  block read: the ULNv2 (V1) source path and the executor adapter-params lookup.
  The account-resource read keeps its whole value; `post_aptos_json` is unchanged.
- An Initia transaction keeps only `key` and `value` on each event attribute. The LCD
  also returns an `index` flag per attribute, which each node sets from its own
  `app.toml` `index-events`, so honest nodes differ on it. Mainnet LCD answers carry it.
  This applies where every Initia transaction read starts (`unwrap_initia_tx`), so the
  source read, readiness and the sender read in extra context all see the same events.
  A re-review after the first fix found that the projection kept `events` whole and
  Initia still split on this flag, and that the sender read had the same exposure.

**Why more fields than the report lists.** The accumulator returns the lowest-index
value of the agreeing group. A field left out of the fingerprint but read afterwards
would come from one provider without agreement. `version` selects the V301 executor
lookup, so it must be bound; `hash`/`txhash` bind identity and `type` marks a pending
transaction. A wrong `version` would in practice fail the guid match rather than sign,
but the rule is that nothing unagreed is read.

**Evidence**

- `round3_m12_aptos_node_release_and_indexer_differences_still_reach_quorum`: two
  providers, quorum 2, one without `txn_limits_request` or with decoded table writes;
  the archived V301 send resolves with its 150,000 lzReceive gas after two `by_hash`
  and two `by_version` reads.
- `round3_m12_aptos_v1_transaction_and_block_extras_still_reach_quorum`: the ULNv2
  path with an extra top-level field on one provider's transaction and block resolves
  the same event as one provider.
- `round3_m12_aptos_consumed_fields_still_split_the_quorum`: a different event,
  `success`, `version` or `hash` on one provider still refuses.
- `round3_m12_initia_node_index_events_still_reach_quorum` and
  `round3_m12_initia_sender_read_ignores_node_index_events`: two Initia providers at
  quorum 2, one indexing every attribute and one only `type_tag`, agree on the source
  event and on the sender; a changed attribute value still refuses both.
- With only `packet_resolver.rs` restored to `201430d`, the first two fail; the third
  passes either way, as it should. With the attribute normalization removed, both
  Initia tests fail on their agreement case.

## M-13: TON readiness counted providers without a v3 endpoint

**Outcome:** Fixed as recommended, extended to timestamps and extra context.

**What we confirmed first.** With `any:2`, two v3 and two v2-only providers gave
`No block confirmation for chain ton quorum: … 2 distinct successful responses, 0
errors`; one v3 and two v2-only providers returned the fabricated quorum as
`Transaction trace or masterchain info not found`. v2-only providers ranked first
also delayed the v3 providers by the 2 s stall timeout each. The TON timestamp and
extra-context paths already treated a missing endpoint as a non-vote, but shared the
delay and had no explicit capability error. The trace resolver was already correct.

**What changed**

- `plan_ton_v3_dispatch` selects providers whose `v3-endpoint` parses, refuses before
  RPC when their entities cannot meet the strategy (`TON provider pool needs quorum …
  parseable v3-endpoint`), and orders, health-checks and staggers only that subset.
- The accumulator's pending set is the dispatched subset, so an excluded provider
  cannot hold back an unambiguous result.
- Readiness without an agreed packet seqno fails before dispatch, with the existing
  message. The readiness, timestamp and extra-context TON paths all use the helper.

**Not changed.** The rank used to order and health-check that subset is still the one
keyed by the configured URI, which the TON v2 probe sets. A provider whose v3 endpoint
alone is down still ranks as healthy and can be in the first wave. One whose v2 endpoint
alone is down is ordered last and delayed; the call is refused only when the healthy
rest cannot meet the strategy. The v3 probe result decides chain health only. Ranking
by the v3 probe is separate work.

**Evidence**

- `round3_m13_ton_readiness_ignores_providers_without_v3_endpoint`: v2-only providers
  listed first; readiness passes with zero virtual delay and only the two v3
  `masterchainInfo` reads.
- `round3_m13_ton_readiness_refuses_when_v3_entities_cannot_meet_the_strategy`: one
  v3 provider, and two v3 URIs of one entity, are refused with zero RPC.
- Timestamp and extra-context equivalents of both, using the recorded v3 `/events`
  response for the sender read.
- With only the M-13 production files restored, all six fail;
  `round3_m13_ton_readiness_without_agreed_seqno_dials_no_provider` passes either way
  and pins that the new early error still dials nothing.

## M-14: a disconnecting caller restarted the report's probe round

**Outcome:** Fixed, by a different mechanism from the one recommended.

**What we confirmed first.** The report was cached only after the round completed
inside the handler future. hyper 1.10 closes an HTTP/1 connection that reaches EOF
mid-request unless `half_close` is enabled, which Pillar does not, and drops that
future. Five requests abandoned after 100 ms started five rounds, and the report was
never cached.

**What changed**

- `RpcProviderHealthSource` retains the full report of each successful round with the
  provider generation it probed. Startup, the 15 s cache refresh and the 150 s rank
  refresh all go through it. When rounds overlap, the newest start wins; staleness is
  counted from completion, as the cache counts it from publication.
- The route calls the same `ProviderHealthCache::read()` as `/provider-health`, then
  returns the retained report if it describes the serving generation and is within
  the 120 s stale allowance. Otherwise it answers 500 without probing.
- `ProviderHealthCache::read()` no longer probes inside the caller. When nothing is
  servable it waits for a refresh task the cache owns, the same kind it already
  spawned for a stale value. This matters beyond the report: a REMOTE provider
  configuration publishes a new generation on every successful 60 s refresh, even
  when unchanged, which made every cached value unservable once a minute. A caller
  that disconnected then cancelled the round, and `/provider-health`, which is public,
  took the same path. A refresh that a pinned request such as `/ready` waits for still
  probes the request's pinned configuration, as the inline refresh did.
- `ProviderHealthReportCache` and its TTL are removed.

**Why not a separate refresh coordinator.** The cache already owns a refresh task,
bounded by the background lane, aborted with the app. It computed the full report and
kept only the booleans. Retaining that report and routing every refresh through the
owned task gives the route the existing lifecycle, removes the duplicate probing and
adds no new task type.

**Evidence**

- `round3_m14_cancelled_report_requests_cannot_restart_probe_rounds`: within the TTL,
  five abandoned requests probe nothing. Past it, five abandoned requests share one
  round, which completes and is served with its new check time.
- `abandoned_reads_share_one_owned_refresh_round` (pillar-core): with an empty cache,
  and again after the generation changes, three abandoned reads cause one round and
  the next read is served from it.
- `round3_m14_retained_report_keeps_the_newest_round_of_the_serving_generation`: an
  older round finishing last does not replace the newer report, and another
  generation or a report past the stale allowance is not served.
- The existing `readiness_answers_from_one_generation_when_a_refresh_lands_mid_probe`
  holds the pinned-configuration behaviour of a waited-for refresh.
- With the M-14 runtime files restored, the first fails; with the inline refresh
  restored in `read()`, the pillar-core test fails; with only the ordering guard
  removed, the third fails; without the pin carried into the task, the readiness test
  fails. An independent review found that last case before it was fixed.

**Boundaries.** A configuration refresh still costs one probe round per published
generation; callers share it. The tests drive the handler and cache futures, not a TCP
socket; hyper's disconnect behaviour was confirmed from its 1.10.1 source. The route
answers 500 until a round has succeeded for the serving generation, for example for
up to 15 s after a failed startup probe.

## L-04: auxiliary probes decided chain health

**Outcome:** Fixed as recommended.

**What we confirmed first.** `event-indexer`, `no-code-indexer` and `tron-web-url` are
read only by provider health. One Aptos indexer outage made `aptos` unhealthy, and a
roster advertising only Aptos `NotReady`.

**What changed**

- `ProviderHealthEntry.diagnostic` is serialized as `true` on the Aptos/Movement
  indexer, Initia indexer and TronWeb entries and omitted otherwise.
- Chain `healthy` and `observed` are computed over the other entries. Every observed
  primary entry must still be healthy, as before. TON v3 probes stay primary, because
  TON source signing reads v3.
- Unlike the other auxiliary probes, the Initia indexer probe propagated an admission
  error, so a JSON parser saturated by signing failed the whole health round, for every
  chain. It now records the entry as not attempted.

**Initia in practice.** The Initia indexer probe falls back to the LCD latest-block
endpoint the primary probe uses, so it is unhealthy only when the primary is too.
Marking it diagnostic changes no Initia health outcome; the admission change above does.

**Evidence**

- `round3_l04_auxiliary_outage_is_a_diagnostic_not_chain_health`: Aptos and Tron stay
  healthy with the indexer or TronWeb at 503; the entry stays in the report as a
  diagnostic.
- `round3_l04_primary_outage_still_fails_the_chain_whatever_the_indexer_says`.
- `round3_l04_aptos_readiness_ignores_indexer_but_not_primary_failure`: an Aptos-only
  roster is `Ready` with the indexer down and `NotReady` with the primary down.
- `round3_l04_initia_indexer_admission_does_not_fail_the_health_round`: an Initia
  indexer refused by parser admission leaves a not-attempted diagnostic entry and a
  healthy chain.
- With the aggregation, probe marking and admission handling restored, the four tests
  above other than the primary-outage one fail; that one passes either way.

**Not changed.** One unhealthy primary still marks the chain unhealthy even when the
rest could meet the quorum (`provider_health_marks_aptos_unhealthy_when_ledger_info_is_not_numeric`).
That is a separate policy choice and is left as it is.

---

## Structural invariants

| Invariant | Test |
|---|---|
| Quorum compares exactly the fields that are consumed, and only those are returned | `round3_m12_*` |
| A provider that cannot perform a read neither votes nor delays those that can | `round3_m13_*` |
| Abandoning a request cannot restart or discard shared probe work | `round3_m14_*` |
| Endpoints signing never reads cannot take a signer out of service | `round3_l04_*` |
