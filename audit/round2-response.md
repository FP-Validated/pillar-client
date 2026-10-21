# Sentry Code audit, Round 2: remediation response

| | |
|---|---|
| Baseline in the report | `3f39fbad972794e5a9c598ea46a310334a4a4415` (2.6.2) |
| Branch point | `7736ecb8fd9cee6abd658a223972e58fc0bf341e` (Round 1 remediation on `main`) |
| Fixes | four commits, one per finding, `4cbef24`..`d256797`, after dependency update `677d676` |
| Date | 2026-10-21 |

All four findings were reproduced on `main` before any change, against the source and
with throwaway tests, and each one held. The fixed tree is formatted with
`cargo +1.98.1 fmt --all`, passes
`clippy --workspace --all-targets --locked -- -D warnings`, and passes
`test --workspace --locked` with 1,125 passed, zero failed and 15 ignored.
`cargo +1.94.1 check` (MSRV), `cargo audit` and `cargo deny check` pass.
Each new test was run against the pre-fix code with only the fix reverted, and fails
there.

This report numbers its Canton finding M-08. That is a different finding from Round 1
M-08 (TON extra-context policy principal, fixed by `8143a9b`); below it is written
"M-08 (Canton)".

| Finding | Commit | Outcome |
|---|---|---|
| M-11 URL redaction cost | [`4cbef24`](https://github.com/FP-Validated/pillar-client/commit/4cbef248e24dbdb4da55c579d56f9bd36f2c6a99) | Fixed as recommended; long text is truncated rather than replaced |
| M-09 READ codec versions | [`2a4a20f`](https://github.com/FP-Validated/pillar-client/commit/2a4a20f2108a95e7033d573798a15e5e95327cd7) | Fixed as recommended; one acceptance criterion corrected |
| M-10 Initia scalar views | [`be506f2`](https://github.com/FP-Validated/pillar-client/commit/be506f25e5f922abc52e6a9d0f429521b3deec18) | Fixed, following upstream rather than a type allow-list |
| M-08 (Canton) provider health | [`d256797`](https://github.com/FP-Validated/pillar-client/commit/d256797160a79dffef83d3a202ad9a3a2da6849b) | Fixed as recommended; the ledger is probed, the sequencer is not |
| Dependencies | [`677d676`](https://github.com/FP-Validated/pillar-client/commit/677d67606a4c6c2c5a048f3b73a3b09467b5344a) | Not a finding: RUSTSEC fixes that turned the hosted `audit, deny, sbom` job red |

---

## M-11: quadratic URL redaction in provider health

**Outcome:** Fixed as recommended. Over-long text is truncated, not replaced.

**What we confirmed first.** `find_url_start` searched the whole remainder for both
`https://` and `http://` on every URL. A string made only of `https://` URLs never
stops the `http://` search early. In a release build, a single configured provider
answering `eth_chainId` with a 4 MiB string of `https://a ` tokens kept the health
report busy for 221.7 s; 1 MiB took 13.8 s. The report's 10 s deadline did not
interrupt it, because the work has no await point. The finding names IOTA, but the
EVM probe passes its `result` to the same function, so every EVM chain on a live
roster was exposed. Startup runs the health probe before it binds the listener, so
the same answer also delays startup.

**What changed**

- `find_url_start` looks for the next `http` from the current position and accepts it
  only when `://` or `s://` follows. The caller resumes after the URL it returns, so
  each byte is read once. The set of URLs found is the same as before.
- After redaction, each string in the report is cut to 64 KiB and ends with
  `…[truncated N bytes]`. Before this, the report could retain up to 4 MiB per
  provider until the next refresh.

**Evidence**

- `round2_m11_hostile_health_response_is_redacted_within_the_probe_deadline`: a local
  HTTP provider and the production `reqwest` transport. The fixed debug build finishes
  the 4 MiB report in 0.36 s. With only the fix reverted, the same test ran for 1,150 s
  and failed.
- The same test checks that a credential repeated through the payload (userinfo, path
  and query) never appears in the report, and that the retained text is capped.

**Why we truncate rather than replace with a fixed message.** Redaction finishes
before truncation, so the retained prefix holds no credential. Truncating the other
way round could cut a URL before its `@` and publish part of the userinfo. The first
64 KiB of a provider's error is useful to an operator. A fixed message would discard
it and buy no extra safety.

## M-09: READ command versions were not checked

**Outcome:** Fixed as recommended.

**What we confirmed first**

- Through the production composition, commands with command version 2 or `0xffff`,
  or request version 2, were resolved and signed. The read target got two `eth_call`s
  and the response carried one signature. Compute version 7 decoded too.
- Upstream does the same. `Command.decode` in `@layerzerolabs/lz-v2-utilities`
  3.0.168 reads every version with the V1 layout.
- On chain, `ReadCmdCodecV1` (`lz-evm-messagelib-v2` 3.0.168, `uln/libs`) reverts with
  `InvalidVersion` for all three fields. A DVN on the standard `DVNFeeLib` calls it when
  a job is assigned. So for an OApp whose READ configuration includes this DVN, a
  non-V1 command should not reach a `PacketSent`. We regard the change as fail-closed
  agreement with the on-chain codec and protection for a future codec version, not as
  closing a path we could exploit today.

**What changed**

- `decode_evm_read_command` refuses a command, request or compute version other than 1
  with `400 Unsupported READ <field> version: N`.
- Other malformed READ commands were 500s and are now 400s: unsupported resolver or
  compute type, compute setting or timestamp flag, truncated input, trailing bytes,
  and a zero block number. The client chose these values, so they are not server
  faults.

**Evidence**

- `official_vectors_read_cmd_codec_v1_refuses_every_other_version` changes only the
  version byte of the pinned official vector, to 0, 2 or 0xff, for each of the three
  fields. Every case is refused.
- `round2_m09_unsupported_read_codec_versions_are_refused_before_read_rpc_and_signing`
  runs the HTTP route on the production composition. For each field, the answer is
  400. The only RPC is the source `eth_getTransactionReceipt`, and no sign-stage
  observation is recorded.
- Both tests fail with the decoder reverted. The V1 READ vertical, HTTP E2E and
  official-vector tests are unchanged and pass.

**Acceptance criterion corrected.** The report asks for zero RPC calls. That cannot
hold: the command exists only inside the source `PacketSent`, so it must first be read
from the source receipt. The refusal happens right after that read, in the same
synchronous preflight as the message-hash check. That is before any READ-target RPC,
any other validation RPC, and the signer.

## M-10: Initia scalar view responses were refused

**Outcome:** Fixed. We follow upstream's handling rather than an allow-list of types.

**What we confirmed first.** Initia mainnet (`rest.initia.xyz`, recorded 2026-10-20)
answers the three views this path reads with bare values, not arrays:

- `endpoint::get_config` answers `"\"000000000000000f…\""`;
- `uln_302::verifiable` answers `"3"`;
- `msglib::get_verification_confirmations` answers `"\"0\""`.

A two-value view answers an array, for example `["0","0x0"]`. Pillar's shared decoder
turned every non-array into "unavailable". Every provider therefore lost its vote, and
every Initia destination with a payload-signed subject was refused. Upstream wraps a
non-array as `[value]` (`multiprovider/src/initia.ts:412-415`). The existing test hid
the problem because it fed array-shaped `data` that the node never returns. The same
behaviour was already present at the report's baseline, so this is not a Round 1
regression.

**What changed**

- Response handling is split by chain:
  - Initia parses the `data` string and wraps a non-array as one element.
  - Aptos `/view` still requires a top-level array.
- Each view's caller already checks its element: the receive library must be an
  address, `get_config` an encoded config, `verifiable` a state from 0 to 4, and
  confirmations a `u64`. A value of the wrong type is still a non-vote.

**Evidence**

- The four recorded exchanges and an unregistered-receiver error are committed under
  `crates/pillar-runtime/tests/gasolina_parity/initia_public_node/`, with SHA-256s
  listed in its README.
- `evm_v302_to_initia_reads_recorded_legacy_view_scalars` runs EVM to Initia through
  the HTTP route, with resolver, validator, builder and signer:
  - with the recorded answers, the request signs: 200 and one signature;
  - with state 2 (verified), it refuses: 400 and no signature;
  - with confirmations at the required 15, it refuses: 400 and no signature.
- The existing Initia test now uses the recorded shapes.
- Both tests fail with the decoder reverted. The Aptos and Movement resolve-and-sign
  test still passes.

**Why not an allow-list of scalar types.** The report asks that only the types the
contract returns be accepted. That check already exists, one step later, where each
view's value is used. A second, chain-wide type list would have to be kept in step
with every view's return type. It would also diverge from upstream, which accepts any
non-array and lets the consumer reject it.

**Not recorded.** No OApp registered on Initia mainnet was available for
`get_effective_receive_library`, which is a two-value view. Its shape is taken from
the same endpoint module's two-value view, recorded as exchange 001.

## M-08 (Canton): Canton had no provider-health probe

**Outcome:** Fixed as recommended. We probe the ledger and not the sequencer.

**What we confirmed first**

- `canton` is `CANTON` in the static chain table, but the health dispatcher had no arm
  for it. Its own doc comment claimed every type had one.
- The fallback marked every Canton `rpc` entry unhealthy without sending a request.
  Startup then seeded that rank into the tracker that dispatch shares.
- With the rank seeded, a ledger that would have answered was refused with
  `Not enough healthy providers … (0 healthy of 1 configured)`. No ledger or token
  request was sent.
- Through the production composition, a Canton-only roster was `NotReady`. A mixed
  roster stays ready, because readiness requires any one healthy chain, but its Canton
  sender reads were still refused.
- Upstream probes Canton with `getLedgerEndOffset` (`multiprovider/src/canton.ts:105-109`).

**What changed**

- A `CANTON` arm calls `GET {jsonApiUrl}/v2/state/ledger-end`
  (`common-canton` 1.2.66 `client/canton-client.ts:994-997`). A numeric `offset`
  means healthy.
- The probe uses the same `CantonLedgerAuth` (OAuth2 client credentials,
  `CANTON_CLIENT_SECRET`) and the same URL rules as the ledger sender read.
- The probe's rank key is the dispatch key for the configured URI.
- Any probe failure marks only that entry unhealthy: missing OAuth configuration, a
  rejected token, an HTTP error, or a non-numeric offset. It cannot fail the rest of
  the report.
- The inaccurate comment is corrected.

**Evidence**

- `round2_m08_canton_ledger_is_probed_and_fails_closed` runs a Canton-only roster
  through the production composition and the shared rank tracker:
  - a working ledger gives `/ready` 200, `{"canton":true}`, rank `Normal`, and the
    sender read returns `Erin::1220`;
  - ledger-end 503, token 401, a non-numeric offset and missing OAuth each give `/ready`
    503, `{"canton":false}` and rank `Unhealthy`. The sender read is refused without
    reading the ledger, and no secret appears in the report.
- `round2_m08_canton_failure_does_not_fail_other_chains`: when Canton cannot
  authenticate, `ethereum` is still reported healthy.
- `no_non_evm_chain_falls_through_to_the_unregistered_health_probe` is derived from the
  static table, like the existing tests for the four other dispatch sites. Any future
  non-EVM chain without a probe fails it.
- `a_failing_probe_excludes_the_provider_from_dispatch_for_every_family` now includes
  Canton, with a credential-bearing URI. It checks that the rank key the probe records
  is the one dispatch looks up.
- With the `CANTON` arm removed, the roster test and both Canton E2E tests fail.

**Ledger only, not the sequencer.** Upstream's Canton health covers the `rpc` (ledger)
entries only. Those are also the only entries dispatch ranks and quorums. The single
sequencer entry signs destination attestations and is not part of a provider pool.
This matches the report's own observation that Canton destination signing does not
depend on the ledger quorum.

---

## Structural invariants

The report closes with four invariants. Each is now held by a test:

| Invariant | Test |
|---|---|
| Every supported chain type reaches a real health probe | `no_non_evm_chain_falls_through_to_the_unregistered_health_probe` |
| An unsupported protocol version is refused before RPC and signing | `round2_m09_unsupported_read_codec_versions_are_refused_before_read_rpc_and_signing` |
| A chain's RPC response is read by that chain's contract | `evm_v302_to_initia_reads_recorded_legacy_view_scalars`, with recorded Initia responses |
| Synchronous work on external input has a bounded cost | `round2_m11_hostile_health_response_is_redacted_within_the_probe_deadline` |
