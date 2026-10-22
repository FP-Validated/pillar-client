# Sentry Code audit, H-01, M-15 and M-16: remediation response

| | |
|---|---|
| Baseline in the report | `3f39fbad972794e5a9c598ea46a310334a4a4415` (2.6.2) |
| Branch point | `fc8d9e9` (Round 3 remediation branch, not yet on `main` at `201430d`) |
| Fixes | `de722d6` (H-01), `7a1a226` (M-16), unreleased; M-15 was fixed by `677d676`, released in 2.7.0 and 2.7.1 |
| Date | 2026-10-22 |

| Finding | Commit | Outcome |
|---|---|---|
| H-01 TON BOC with a deep unreachable chain aborts the process | `de722d6` | Every declared cell, reachable or not, must be at most 1,024 deep before any cell is built; the hostile provider loses its vote and the quorum signs |
| M-15 compromised eMudhra intermediates in the WebPKI trust store | `677d676` | Already fixed and released; no code change |
| M-16 valid sparse-mask pruned branch fails the whole TON trace | `7a1a226` | `ton_core` 0.3.7 hashes pruned branches with one stored hash per set mask bit; Pillar now attests these traces, unlike upstream |

---

## TON BOC ingress

Every TON BOC a provider returns, whether account storage
(`validation_payload_ton.rs`) or a trace message body (`source_events_ton.rs`, also
reached from `validation_extra_context.rs`), goes through
`pillar_layerzero::boc_from_bytes_with_limits` inside that provider's own future,
before any quorum. The stages, in order:

| Stage | Owner | Checks | Bounds |
|---|---|---|---|
| 1. Header | Pillar, wire bytes | Magic, field widths, offsets, one root | Cell count at most `max_msg_cells` 8,192 or `max_acc_state_cells` 65,536 (config param 43) |
| 2. Depth | Pillar, wire bytes | References point forward; depth of **every** declared cell | At most 1,024 (`CellTraits::max_depth`); nothing is built before this passes |
| 3. Construction | `ton_core` 0.3.7 `BoC::from_bytes` | By its own documentation: exotic layouts, level masks, Merkle hashes, per-cell depth, CRC32C and exact length; pruned branches store one hash per set mask bit | Drops deeper than 128 levels are deferred to a loop |
| 4. Exotic policy | Pillar | Storage and LayerZero event bodies refuse exotic cells; other trace bodies accept valid ones | Unchanged |
| 5. Vote | Pillar | A refused BOC is that provider's non-vote (storage `Unavailable`, trace `None`) | The other providers still decide the quorum |

Invariants:

1. No cell object exists unless every declared cell is at most 1,024 deep, so no drop
   recursion is deeper than that; `ton_core` keeps it to 128.
2. One provider's BOC can only cost that provider its vote. A stack overflow cannot be
   caught (`catch_unwind` only handles panics), which is why stages 2 and 3 bound the
   recursion rather than recovering from it.
3. Valid pruned branches of every level mask parse; six masks match pytoniq-core's
   hashes, and 19,715 mainnet BOCs parse to the same hashes under 0.1.3 and 0.3.7. This
   was not checked against the TON node itself.
4. Stage 2 belongs to Pillar and does not depend on the library: it would hold if
   `ton_core` regressed.

---

## H-01: deep unreachable chain aborts the signer

**Outcome:** Fixed by bounding every declared cell (stage 2). The report's first
recommendation; the second, non-recursive drop, comes with `ton_core` 0.3.7 (M-16).

**What we confirmed.** `boc_root_depth` computed the depth of every cell and returned
the root's. `ton_core` 0.1.3 `RawBoC::into_ton_cells` builds every declared cell into a
temporary vector in reverse order; when it is dropped, the head of a chain nothing
references goes last and drops the whole chain recursively. Three providers at quorum
2, one returning such a BOC, on a 2 MiB tokio worker (macOS arm64):

| Path | Debug build | Release build |
|---|---|---|
| Trace body, unreachable chain of 4,096 to 8,192 cells | Process aborts (stack overflow) | Resolves; the margin was not measured and depends on the compiler |
| Account storage, 8,192 or 16,384 cells | Process aborts | Resolves |
| Account storage, 65,535 cells | Process aborts | Process aborts |

So in production builds the account-storage path is the one that aborts. The honest
controls (honest providers only; a reachable deep chain, which stage 2 already refused)
resolved, and the refused provider never voted: the only defect was the abort.

**What changed.** `boc_max_depth` returns the deepest declared cell. The account and
message limits are unchanged; no on-chain BOC carries a cell deeper than the TON node
allows.

**Tests.** `refuses_an_unreachable_chain_deeper_than_ton_cell_depth` (1,024 accepted,
1,025 refused); `rejects_chains_at_the_cell_limits_in_two_mib_worker` (child process, 2
MiB thread, reachable account chain plus unreachable chains at both cell limits);
`h01_unreachable_message_chain_from_one_provider_leaves_the_quorum_signing` and
`h01_unreachable_storage_chain_from_one_provider_leaves_the_quorum_signing` (child
process, production resolver and payload validator on a tokio worker, hostile provider
dispatched first, the two honest providers reach quorum with the same result as without
it). With the fix reverted the first fails and the other three abort their child with
SIGABRT.

## M-15: compromised eMudhra intermediates

**Outcome:** Already fixed; no code change.

`677d676` (2026-10-21) moved `rustls` 0.23.45→0.23.46, `rustls-webpki`
0.103.15→0.103.16, `webpki-roots` and `webpki-root-certs` 1.0.8→1.0.10. It is in tags
`v2.7.0` and `v2.7.1`. RUSTSEC-2026-0381, -0382 and -0383 (CVE-2026-111943) name exactly
these patched versions. The lockfile carries one `rustls-webpki`, 0.103.16.

The report suggests checking the container's CA bundle too. The binary does use the
operating system store for cloud SDKs: AWS through `rustls-native-certs` 0.8.4, GCP KMS
through `reqwest` 0.13.4 and `rustls-platform-verifier` 0.7.0, and the image copies
`ca-certificates.crt` from the pinned build image. `rustls-webpki` 0.103.16, however,
refuses the eight eMudhra intermediate keys (`DISTRUSTED_SPKIS`) while building any
path, whatever store the anchor came from. That covers every client verifying through
it; we did not trace whether the platform verifier does so on Linux. RPC traffic uses
`reqwest` 0.12 with the patched `webpki-roots`.

The report's title overstates the impact: a forged RPC certificate lets an attacker
answer as that provider, which is one vote; it does not reach the signing key.

## M-16: valid sparse-mask pruned branch fails the whole trace

**Outcome:** Fixed by upgrading `ton_core` to 0.3.7. This deliberately departs from
upstream.

**What we confirmed.** A pruned branch stores one hash and depth per set bit of its
level mask. `ton_core` 0.1.3 `calc_pruned_hash_depth` read one per level, so masks
`0b010`, `0b100`, `0b101` and `0b110` failed with `failed to fill whole buffer`.
`ton_message_digest` parses every trace message body and the trace fingerprint fails
when one does, so a valid proof in any message of the trace cost the whole trace its
quorum. The report's 49-byte BOC reproduced exactly. Because that BOC is a level-2
root, we also built a level-0 body,
`MerkleProof(MerkleProof(ordinary → pruned branch, mask 0b010))`, which a message can
carry. In the recorded mainnet trace with that body on the `excesses` message, the
PacketSent still decoded, but two honest providers failed with `0 distinct successful
responses, 2 errors`.

**Upstream has the same defect.** `@ton/core` 0.63.1 `exoticPruned` reads `mask.level`
hashes and refuses both BOCs (`Offset + Length = 528 is out of bounds`), and upstream
parses every trace body (the `bodyChanged` parity variant fails with `Invalid
CRC32C`). The LayerZero reference DVN therefore cannot attest such a trace either. We
attest it anyway: the PacketSent is decoded from its own message, the proof elsewhere
in the trace is valid TON data, and refusing it only blocks a real packet. A packet
whose other required DVNs run `@ton/core` will still wait on them.

**Upgrade.** `ton_core` 0.3.7 (2026-10-02) reads one hash per set bit, checks every
cell as its documentation describes and defers deep drops. Its API was compatible; the source
changes are one `clone_on_copy` lint and the removal of Pillar's own CRC32C check on
trace bodies, which 0.3.7 now performs for every BOC together with an exact length
check. Every existing test passed unchanged, including the upstream-recorded DVN
payload and codec fixtures and the `bodyChanged` CRC parity variant, so the bytes
Pillar signs over did not change. Its stricter checks (level masks, Merkle hashes,
per-cell depth, and CRC32C and exact length on storage too) refuse only malformed BOCs
that no honest provider returns, and a refused BOC is a non-vote. The lockfile adds
`ton_macros` 0.2.3, `derive_setters` 0.1.9 and a second
`darling`; `cargo deny check` reports duplicates as warnings, as configured, and
`cargo audit` is clean.

**Tests.** `hashes_pruned_branches_of_every_level_mask_like_an_independent_parser`: all
seven masks parse, and six match pytoniq-core's hashes, an implementation independent
of `ton_core`. pytoniq-core refuses mask `0b110`, so that one is checked for parsing
only. Exotic cells stay refused where the caller asks. Also
`parses_a_level_zero_body_holding_a_sparse_pruned_branch` (pytoniq-core hash) and
`m16_valid_sparse_pruned_branch_body_keeps_the_trace_quorum`, where two providers
resolve the recorded send with that body to the same event as without it. All three
fail on `ton_core` 0.1.3.

---

## Not changed

- TON exotic cells stay refused in account storage and LayerZero event bodies.
- Whether the TON node refuses BOCs with unreachable cells was not checked, so it is
  not relied on; stage 2 makes them harmless.
- Linux x86_64 stack use was not measured; the regression tests run on the CI
  platforms.
