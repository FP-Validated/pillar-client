# Audit guide

This file is the entry point for an external security review. It states what the
repository contains, how to rebuild and re-run every check that does not need private
inputs, the threat model and trust boundaries, how acceptance evidence is classified,
and what cannot be reproduced from this repository alone.

`SECURITY.md` remains the authority for operator responsibilities, the durable signing
audit, admission accounting, every known divergence from upstream ("Where responses
still differ from upstream") and known caveats. This file does not restate them.

## 1. What the service does

`pillar` is a LayerZero DVN. For a sign request it resolves the source `PacketSent`
event through a provider quorum, checks readiness (confirmations), expiration,
already-signed state and optional extra context, builds the destination ULN verify
call data for the destination chain family, and signs its hash with a KMS key or a
local mnemonic. A signature is an on-chain attestation, so a wrong signature is the
primary harm. See `README.md` for the HTTP surface and configuration.

## 2. Repository contents

Everything tracked here is in scope. Nothing outside the tree is needed to build,
lint or run the default test suite.

| Path | Content |
| --- | --- |
| `crates/*/src` | Product code; workspace layout in `README.md` |
| `crates/pillar-config/src/generated_*.rs` | Generated LayerZero tables (signing-critical addresses, endpoint ids, capability). Never hand-edited; provenance header in each file |
| `crates/*/src/tests*`, `crates/*/tests` | Unit, integration and E2E tests: at `3edb5d23`, `cargo test --workspace` runs 954 and ignores 15 (sections 6 and 10) |
| `crates/*/tests/**/*.json`, `*.hex`, `*.body` | Fixtures: upstream-executed outputs, recorded public-chain RPC responses, official LayerZero vectors, synthetic inputs |
| `crates/pillar-config/examples/provider-config/` | Example provider files on reserved `.example` hosts; no real endpoint or key |
| `scripts/` | Table generators, parity emitters (`scripts/gasolina-parity/`), the CI integrity check and the acceptance-matrix builder |
| `audit/acceptance/` | Acceptance matrix generated from committed inputs (section 5) |
| `Cargo.toml`, `Cargo.lock`, `deny.toml`, `Dockerfile`, `.github/workflows/ci.yml` | Build, dependency policy, image, CI |

## 3. Reproduce

Toolchains: Rust 1.98.1 with rustfmt and clippy (CI baseline), Rust 1.94.1 for the
declared `rust-version`, Node.js for `scripts/*.mjs`. All dependencies come from
crates.io through `Cargo.lock`; there are no git dependencies and no `[patch]`.

```bash
cargo +1.98.1 fmt --all --check
cargo +1.98.1 clippy --workspace --all-targets          # CI sets RUSTFLAGS="-D warnings"
cargo +1.98.1 test --workspace --locked
cargo +1.94.1 check --workspace --locked --all-targets  # MSRV
cargo audit && cargo deny check                          # advisories, licenses, sources
node scripts/check-generated-config-integrity.mjs        # generated tables vs their headers
node scripts/build-acceptance-matrix.mjs --check         # matrix vs committed inputs
docker build --build-arg VCS_REVISION="$(git rev-parse HEAD)" -t pillar-client:audit .
```

The default suite needs no network, database, KMS or cluster. Six E2E tests write a
JSON artifact per run under `local/e2e-runs/` (gitignored); set
`PILLAR_E2E_ARTIFACT_DIR` to redirect them:
`crates/pillar-api/tests/log_record_forgery.rs`, `crates/pillar-cli/src/phase1_review_e2e.rs`,
`crates/pillar-runtime/src/tests/{background_headroom_e2e,health_availability_e2e,postgres_audit_e2e}.rs`,
`crates/pillar-signer/src/azure/wire_e2e.rs`.

## 4. Threat model

### Assets

- The DVN signing key (KMS key or mnemonic) and every signature it produces.
- Correctness of the attested message: source event, pathway, nonce, payload hash,
  destination contract, `vId`, expiration.
- Credentials in configuration: API bearer tokens, RPC provider headers, KMS
  credentials, Canton OAuth2 client secret, audit database URL.
- Availability of signing for configured pathways.

### Adversaries considered

- Any network caller that reaches the HTTP port, with or without a valid token.
- A dishonest, faulty or compromised RPC provider, below the configured quorum.
- A source-chain user who crafts transactions, events or payloads.
- A reorg on the source chain between resolution and signing.
- Someone who reads logs, metrics or the startup report.

Not defended in code: a compromised host or KMS principal, an operator who configures
a quorum that one entity can satisfy (flagged at startup as
`single-provider-trust-root`), a majority of colluding providers, and fleet-wide rate
limiting (budgets are per process). `SECURITY.md` "Operator responsibilities" lists
the controls left to the deployment.

### Trust boundaries

| Boundary | Trusted side assumes | Enforced in | Failure mode required |
| --- | --- | --- | --- |
| HTTP caller → API | Bearer token from `PILLAR_API_AUTH_TOKENS` (≥32 chars) unless the operator opens sign routes; request fields are untrusted | `crates/pillar-api/src/lib.rs` (`authorized`, request shape gates), `crates/pillar-cli/src/main.rs` (header/request deadlines, connection cap) | 401, or 400 for malformed input, before any provider or signer call |
| Request → packet | Only the `PacketSent` emitted by the trusted contract for the requested version and pathway is accepted | `crates/pillar-runtime/src/layerzero_runtime/packet_resolver.rs`, per-family `source_events_*.rs` | 400 on identity mismatch; never sign a packet the request does not name |
| RPC providers → validation | Answers are counted per `(category, entity)`; differing answers never merge | `crates/pillar-runtime/src/provider_health/**` | Fail closed when the strategy is not met or two answers could each meet it |
| Readiness / reorg | Confirmations from the validated block; READ calls pinned by block hash with `requireCanonical` | `layerzero_runtime/validation_readiness.rs`, `layerzero_runtime/read_payload.rs` | Refuse unpinned or non-canonical reads; no fallback by number |
| Static tables → builders | Addresses, endpoint ids and `vId` come from generated tables per environment | `crates/pillar-config/src/generated_*.rs`, `crates/pillar-layerzero/src/**` | Unsupported `(chain, environment, version)` is an error, never a default |
| Extra-context service | External yes/no over HTTPS or Lambda; URL must be absolute, without userinfo, and `https` on mainnet/testnet, checked at startup | `crates/pillar-config/src/lib.rs` (`validate_service_url`), `layerzero_runtime/validation_extra_context.rs` | Process refuses to start on a bad URL; a rejection or error stops the request before the builder and signer |
| Canton sequencer / ledger | Sequencer reads verified against a configured committee when set; ledger read needs OAuth2 client credentials | `layerzero_runtime/canton_sequencer.rs`, `layerzero_runtime/canton_ledger.rs` | Refuse before any request without credentials; refuse on `sandbox`/`localnet` |
| Validation → signer | Signer sees only the 32-byte digest built from validated data; key and address derivation per chain family | `crates/pillar-signer/src/**`, `crates/pillar-runtime/src/signer_runtime/assembly.rs` | Unsupported KMS provider fails clearly; secrets redacted in `Debug` and zeroized |
| Signer → audit store (optional) | Intent and result committed before a 200 when `PILLAR_AUDIT_ENABLED=true` | `crates/pillar-core/src/audit.rs`, `crates/pillar-runtime/src/audit.rs` | No 200 before result commit; unknown outcomes retained, never replayed |
| Process → logs / metrics | Caller-controlled values bounded or omitted; labels from fixed allowlists | `crates/pillar-api/src/lib.rs`, `crates/pillar-metrics/src/**`, `startup_report.rs` | No secret or caller hash in terminal logs; no unbounded label cardinality |

### Invariants worth attacking first

1. No signature for a packet other than the one the request names, on the trusted
   emitter, for the requested pathway and version.
2. No signature below the configured provider quorum or confirmation depth.
3. No signature for a destination contract, environment or `vId` the tables do not
   name; every divergence from upstream is listed in `SECURITY.md`.
4. No request reaches the signer before source resolution, validation (readiness,
   expiration, already-signed state, extra context) and call-data construction have
   succeeded (`sign_request_v2`, `crates/pillar-core/src/lib.rs`; the v1 route
   delegates to it). Malformed caller input is refused with 400 at the HTTP boundary.
   This is not a "no 5xx" property: some caller-chosen input still answers 500, as
   upstream does, for example an unavailable chain name, a missing `dvnAddress` on a
   Solana or Stellar destination, or a read that misses provider quorum.
5. No secret reaches a log, metric, `Debug` output or error body.

### What a 5xx does and does not show

An error response never carries signatures or partial signatures. A 5xx alone does
not prove that no signature was produced. Failures can occur after a signer or KMS
call has started:

- In a multi-wallet request, an earlier wallet can have signed before a later one
  fails; the request then fails as a whole.
- With the durable audit enabled, a failure to commit result evidence after the KMS
  call returned is an error response.
- The 58s request deadline and the end of the shutdown grace period close the
  connection without a response while a KMS call can be in flight.
- With the audit disabled, the optional Azure hedge can start a second remote
  signing attempt; cancelling the losing attempt does not prove it was not sent.

With the durable audit enabled, each wallet attempt is committed before its KMS call
and retained; an attempt without completion evidence stays unresolved and is never
recorded as "not signed" (`SECURITY.md`, "Durable signing audit"). With the audit
disabled, which is the default, no record distinguishes these cases.

## 5. Acceptance evidence

`audit/acceptance/acceptance-rows.csv` has one row per (environment, chain, role, ULN
version) for every version the capability table lists as `ACTIVE`: 1696 rows.
`node scripts/build-acceptance-matrix.mjs` regenerates it from committed inputs only,
and CI runs it with `--check`. Each row names its evidence. The status kinds are
separate and are not summed into one completion figure:

| Kind | Status | Rows | Meaning |
| --- | --- | --- | --- |
| Exact route evidence | `final-response` | 18 | The production HTTP path answered the same as upstream's own server for this row, offline over recorded public receipts (`historical_smoke.json`, 16 pathways) |
| Component evidence | `component-exact` | 831 | An upstream-executed fixture covers this exact row at builder, resolver or refresh level, not over HTTP |
| Family inference | `family` | 822 | Only another chain of the same family, role and version was executed; this row reaches the same table-driven code. Not evidence for the row itself |
| Divergence | `extension` | 9 | Deliberate, evidenced difference from upstream (testnet `vId`, `SECURITY.md`) |
| Divergence | `upstream-unsupported` | 2 | Upstream throws for every contract role of the chain; both refuse |
| Open | `incomplete` | 14 | Rollout-gated, unmeasured, or no executed evidence |

Gates and decisions recorded in the matrix and enforced in code
(`layerzero_rollout_block_reason`, `crates/pillar-config/src/lib.rs`):

- **Testnet `moninet` is excluded** (6 rows). 8 of 10 deployment addresses match
  LayerZero's metadata, 2 are unpublished, and no public RPC or EVM chain id was
  available. The rollout gate refuses it.
- **Testnet `ton` stays rollout-gated** (2 rows). A delivered testnet packet was read
  and the already-signed check refuses it over real storage; the signing path was not
  run there. The gate is unchanged until the operator decides the rollout.
- **Canton source** (3 rows, `incomplete` against upstream). The ledger read follows
  the published `common-canton` 1.2.66 source and is covered by this repository's own
  tests: synthetic ledger, identity provider and token in the default suite, and an
  opt-in run against a real Canton ledger (section 6). The maintainers accepted these
  self-tests as the Canton acceptance basis. That is a maintainer decision, not
  upstream-executed evidence, so the status is unchanged.
- **Testnet `scroll` destination** (3 rows): `vId` could not be read on chain.

What the matrix is not: it is not a record of live production traffic, and no row is
promoted by family inference. Live checks made by the maintainers against their own
deployment are not part of this repository; section 9 summarizes the deployed release
and the limits of its post-rollout check.

Open review item outside the matrix: the Solana signer address reported for an Azure
key is a fixed rule checked against a fixture; its binding to the on-chain Solana DVN
verifier is not proven in this repository and is under review (`SECURITY.md`, "Where
responses still differ from upstream").

## 6. Ignored tests

`cargo test --workspace --locked` skips 15 tests that need external inputs. Through
`7dc694ca` it skipped 13; `3edb5d23` added the two TLS tests below.

### Durable audit against PostgreSQL (11 tests)

`crates/pillar-runtime/src/tests/postgres_audit_e2e.rs` (9) and
`audit_reconnect_e2e.rs` (2). They need a disposable PostgreSQL that holds no other
data:

- reachable at `127.0.0.1` (the reconnect test asserts the host and proxies to it);
  plaintext is accepted only on loopback;
- a role that may `CREATE SCHEMA`, create tables, `CREATE FUNCTION ... LANGUAGE plpgsql`
  and `CREATE TRIGGER` / `CREATE CONSTRAINT TRIGGER` in its own database;
- each case creates a new schema `<case>_<pid>_<n>` and does not drop it.

```bash
export PILLAR_AUDIT_E2E_DATABASE_URL='postgres://<role>:<password>@127.0.0.1:5432/<database>'
cargo test -p pillar-runtime --lib --locked -- --ignored postgres_audit --test-threads=1
```

The crash test re-runs the test binary as a child with
`--ignored --exact tests::read_vertical_tests::durable_process_worker`, passing
`PILLAR_AUDIT_E2E_WORKER_MODE` and `PILLAR_AUDIT_E2E_WORKER_NAMESPACE`; that worker is
the 12th ignored test and is not meant to be run by hand.

### Canton ledger (1 test)

`canton_ledger_tests.rs::canton_sender_is_read_from_a_live_ledger_through_the_production_path`
reads sender parties from a real, unauthenticated Canton JSON API through the
production code path, with a synthetic OAuth2 token. It needs a ledger you control
with contracts whose `sender` you know:

```bash
export PILLAR_CANTON_LIVE_JSON_API='http://127.0.0.1:<port>'
export PILLAR_CANTON_LIVE_PARTY='<party id>'
export PILLAR_CANTON_LIVE_CASES='[{"updateId":"<id>","sender":"<party>"}]'
export PILLAR_CANTON_LIVE_ARTIFACT=/tmp/canton-live.json   # must not exist
cargo test -p pillar-runtime --lib --locked -- --ignored --exact \
  tests::canton_ledger_tests::canton_sender_is_read_from_a_live_ledger_through_the_production_path
```

The maintainers' ledger is not available to auditors.

### Durable audit over TLS (2 tests)

`crates/pillar-runtime/src/audit.rs`:
`audit_tls_e2e_trusted_certificate_serves_writes_and_readiness_over_tls` and
`audit_tls_e2e_refuses_untrusted_issuers_and_other_hosts`. They need a disposable
PostgreSQL that accepts only TLS:

- listening on `127.0.0.1`; the tests connect with
  `host=<name> hostaddr=127.0.0.1 port=<port> user=pillar dbname=pillar_audit_tls_e2e`
  and send no password, so `pg_hba.conf` needs only
  `hostssl all pillar 127.0.0.1/32 trust`;
- a server certificate with `DNS:localhost` in its subject alternative names, issued
  by a CA you created for the test;
- a second, unrelated CA that issued nothing for this server;
- the role rights listed for the PostgreSQL tests above.

```bash
export PILLAR_AUDIT_TLS_E2E_PORT='<port>'
export PILLAR_AUDIT_TLS_E2E_CA_DER=/path/to/test-ca.der         # issued the server cert
export PILLAR_AUDIT_TLS_E2E_OTHER_CA_DER=/path/to/other-ca.der  # unrelated CA
cargo test -p pillar-runtime --lib --locked -- --ignored audit_tls_e2e
```

The first test writes an attempt and its evidence and answers readiness, and asserts
that `pg_stat_ssl.ssl` is true for both the write and the readiness sessions. The
second test expects `durable audit: store unavailable` for the unrelated CA, for the
WebPKI roots that production uses, and for host name `pillar-audit-other-host.invalid`.
The default suite covers the refusal to fall back to plaintext
(`audit_tls_target_that_refuses_tls_is_not_retried_in_plaintext`).

## 7. Inputs that are not in this repository

- **Upstream TypeScript service.** Parity is measured against `gasolina-audit` 1.2.66
  (manifest sha256 `8ad87eb6…`; `SECURITY.md` "Which upstream tree the `TS:`
  citations refer to"). It is not a published package and is not distributed here.
  `PILLAR_AUDIT_ROOT` names a checkout of it. Without it you cannot run
  `generate-layerzero-environment-capability.mjs`, the static and TON generators, the
  emitters in `scripts/gasolina-parity/`, or `check-layerzero-environment-parity.mjs`.
  The Rust comparisons against their committed outputs do run, so a reviewer can
  check this code against the fixtures, but not regenerate the fixtures from upstream.
- **npm packages.** `@layerzerolabs/lz-definitions` and `@layerzerolabs/lz-ton-sdk-v2`
  are public; the static, legacy-id and TON generators accept an `npm pack` extract
  (`README.md` "Development"). A regenerated table must equal the committed file.
- **Recorded responses.** Fixtures hold recorded public-chain RPC answers.
  `crates/pillar-runtime/tests/gasolina_parity/aptos_v301_source_provenance.json`
  names the public URL and the sha256 of the recorded body; the body itself is not
  committed, and a re-fetch may not be byte-identical.
- **Live evidence.** Runs against the maintainers' deployments, clusters, KMS keys and
  Canton ledger, and their raw logs, are not published. Nothing in section 5 depends
  on them.

## 8. Provenance and licensing uncertainty

- `LICENSE` (MIT) covers this repository's own code. It grants no rights in
  third-party material.
- Third-party inputs and the license each one states, as found in the copies the
  maintainers used. This records what the inputs say; it is not a license clearance.

  | Input | Used for | Stated license |
  | --- | --- | --- |
  | `@layerzerolabs/lz-definitions` 3.1.15 | endpoint ids in `generated_layerzero_evm.rs`; all of `generated_layerzero_legacy_chain_ids.rs` | Package `LICENSE`: Business Source License 1.1, Licensor LayerZero Labs Ltd, Licensed Work "LayerZero Protocol", Change Date 2025-02-01. The parameters name no Change License and no Additional Use Grant. 3.1.2, used by earlier releases, ships the same text |
  | `@layerzerolabs/lz-v2-utilities` 3.0.168 | the options decoder upstream ran to produce `evm_options.json` | `package.json` declares `BUSL-1.1`; the package ships no license file |
  | `@layerzerolabs/lz-ton-sdk-v2` 3.0.168 | `generated_ton_layerzero.rs` | Not recorded |
  | Upstream service `gasolina-audit` 1.2.66 | deployment addresses in `generated_layerzero_evm.rs`; `generated_layerzero_environment.rs`; `generated_chain_metadata.rs`; parity fixtures; the TON proxy cell | No license file at the snapshot root; its workspace packages declare `"license": "MIT"` together with `"private": true` |
  | `@layerzerolabs/common-canton` 1.2.66 | the Canton ledger read, ported | npm registry metadata declares MIT |

  Whether the generated tables and fixtures are copies or derivative works of these
  inputs, which notices they then need, and the redistribution terms for outputs of
  the upstream service have not been determined.
- The TON proxy storage cell in `crates/pillar-runtime/src/layerzero_runtime/ton_v3_builder.rs`
  was produced by a bundle compiled from upstream's `common-ton` encoder. That bundle
  is not distributed, so the constant cannot be regenerated from this repository.
- Upstream-derived data is pinned by hashes: input sha256 values in every
  generated-file header and the `producedBy` block that most parity fixtures carry.
  A reviewer can check consistency but not origin without the upstream tree.

## 9. Publication and CI status

This tree was prepared from the maintainers' internal branch. Internal history is not
published. Relative to the internally tested source, the publication changed
documentation, code comments, example hostnames, the OCI `source` label, CI
configuration, the acceptance-matrix builder and its output, and a comment in the
integrity check.

CI run [37314461749](https://github.com/FP-Validated/pillar-client/actions/runs/37314461749)
on commit `a4d8ff3d1b2a0e70e140bd77aea99539de103c09` (at that time the last commit
that changed code, tests or CI; `7dc694ca` and `3edb5d23` later changed code and tests
and have no CI run, section 10) passed all five jobs: `fmt, clippy, test`, `minimum
supported rust version` (Rust 1.94.1), `generated config integrity` (including
`build-acceptance-matrix.mjs --check`), `audit, deny, sbom` and `container image`. The
Rust test job reported 934 passed, 0 failed and 13 ignored. These are test-function
counts. They are not route counts and not acceptance-matrix rows; section 5 classifies
the rows separately. The 13 tests ignored in that run are opt-in (section 6) and are
not run by CI. Later commits that change only Markdown get their own CI run.

The source repository is public. Release images that the maintainers deploy are
published to a private container package and are not part of this repository. An
image built from this tree must carry
`org.opencontainers.image.source=https://github.com/FP-Validated/pillar-client` and
`org.opencontainers.image.revision=<this repository's commit>`.

Deployed release, as of 2026-10-05: the maintainers' mainnet deployment runs one
linux/amd64 image built once from source commit
`ff249a1b83edcc25a099d5b7e0706d4c36248b67`, image digest
`sha256:af496b5b37c17378f92d432e8d5574a2e1c635f5f48be842a14aa8abcd631fe0`. It was
rolled out by commit `6e10b27f3dce113aaa3ce97d48c4cb462ed6c8aa` in the maintainers'
private GitOps repository. That source commit changed only Markdown relative to
`a4d8ff3d`. The commits after it up to `70141ac9`, which added this paragraph, changed
documentation only. `7dc694ca` and `3edb5d23` changed code; section 10 gives their
status. The running image's revision label, as recorded at that rollout, names
`ff249a1b`, not a later commit.

Signer identity after that rollout: each of the three pods, read on its own, reported
the same `/signer-info` address for `ethereum`
(`0x06bb41FE76F41429f55aC8C355ac8669769A1ba1`) and for `solana`
(`EboBSUoobiqt7JYcH46ro7TGBjtE2vczKnUmsiWy6Ffy`). No `/signer-info` value was recorded
from the replaced pods immediately before the rollout. So it is not verified that these
addresses are unchanged by this rollout. Equality with the committed fixtures is not
evidence of that either. The binding of the reported Solana address to the on-chain
verifier is still the open review item in section 5. No signing request was made
against the deployment.

## 10. Remediation status, 2026-10-06

This section records the state on 2026-10-06. It does not change the dated results
in section 9.

Two commits after `70141ac9` change code and tests:

- `7dc694ca53ef4941532a39808e71530b5300d9a5` fixes seven findings of a public audit:
  audit TLS provider, `hostaddr` plaintext gate, readiness probe queue, JSON error
  redaction, transport `Debug` redaction, EVM signer order and TON readiness depth.
- `3edb5d237120c9c37493c2ad8be3a69cfcc8c20e` gives audit readiness its own connection
  and one time budget, stops echoing input keys and values in provider-config and
  quorum-strategy errors, and adds TLS and TON regression tests.

An independent reviewer accepted the executable code of both commits. The later
commits change documentation only, except three. The release commit for 2.5.0 also
sets the workspace version and the workspace packages' `Cargo.lock` entries from
2.4.1 to 2.5.0; it changes no executable logic and no third-party dependency. The
two CI fixes below change one loop in `pillar-client` and the audit readiness probe.

### Local checks

These ran on a maintainer workstation, not in CI, with rustc and clippy 1.96.0, not
the CI baseline 1.98.1. When they ran, no CI run existed for `7dc694ca`, `3edb5d23`
or later commits; the next subsection records the first.

- `cargo test --offline --workspace`: 954 passed, 0 failed, 15 ignored. It ran on the
  `3edb5d23` tree before a last edit to one ignored test,
  `postgres_audit_waiter_timeout_preserves_active_commit_and_session` in
  `audit_reconnect_e2e.rs`; the PostgreSQL run below covers that edit.
- `cargo fmt --all --check`: clean. `cargo clippy --offline --workspace --all-targets`:
  exit 0 with one `clippy::nonminimal_bool` warning at
  `crates/pillar-runtime/src/tests/gasolina_parity_tests.rs:72`. That file is unchanged
  since `a4d8ff3d`, which passed CI clippy with `-D warnings`. Clippy 1.98.1 was not run.
- The 11 PostgreSQL tests in section 6 passed against a disposable PostgreSQL 18.6 on
  loopback.
- The 2 TLS tests in section 6 passed against a disposable PostgreSQL 18.6 that
  accepted only TLS, with test-only CAs.
- In the maintainers' runs, `durable_process_worker` ran only as the child of the
  crash test, which asserts its exit codes 73 and 74. The independent reviewer
  confirmed this coverage. The reviewer also ran the worker once by hand without
  `PILLAR_AUDIT_E2E_WORKER_MODE`. Without a mode it runs a separate missing-wallet-scope
  check. That run passed with `sdk_calls` 0 and `attempts` 0.
- The Canton ledger test did not run. No ledger, party, recorded `updateId` or
  `PILLAR_CANTON_LIVE_*` input was available.

### CI on the release commits

CI run [37397588068](https://github.com/FP-Validated/pillar-client/actions/runs/37397588068)
on the 2.5.0 release commit `d3b282150e51594fd91d825c1aa56ffe8584680a` failed in the
`fmt, clippy, test` job. Clippy 1.98.1 with `-D warnings` reported
`clippy::chunks_exact_to_as_chunks` at `crates/pillar-client/src/lib.rs:531`, in the
EVM signer-order helper that `7dc694ca` added. The other four jobs passed. The next
commit replaces `chunks_exact(2)` with `as_chunks::<2>()` and does not change what
the helper returns. Locally, with Rust 1.98.1 and `RUSTFLAGS="-D warnings"`, that job's
commands then passed: `cargo fmt --all --check`, `cargo clippy --workspace
--all-targets` (no warning), `cargo test --workspace --locked` (954 passed, 0 failed,
15 ignored) and the release build. `cargo check --workspace --locked --all-targets`
also passed on Rust 1.94.1.

CI run [37399413275](https://github.com/FP-Validated/pillar-client/actions/runs/37399413275)
on that fix, `d947947057f0759f05c94e34faae3663723ed216`, failed in the same job:
`audit_concurrent_readiness_probes_share_one_budget_and_one_connection` counted 9
connections where at most 2 are allowed. The other four jobs passed. The cause is in
the audit readiness probe that `3edb5d23` added, not in the test. The lane wait and the
dial ran under one timeout that polls its future before its deadline, so a probe
granted the lane after its budget had run out still dialed once. Whether that happens
depends on the order in which expired probes are woken; no local run before this one
showed it. The fix waits for the lane and then dials only within the budget that is
left. Tests count dial attempts (`probe_generation`, incremented before each
connect) rather than accepted connections, because a connection the client drops at
once may never be accepted. With the previous probe,
`audit_readiness_probe_granted_the_lane_after_its_budget_does_not_dial` counts 5 dial
attempts where 1 is expected. The concurrent test now gives its 12 probes one shared
request deadline and staggers their starts; the previous probe makes 12 dial attempts
there, expected 1. Its old 1–2 connection bound assumed that every probe started
within two timer ticks, so a slow runner could fail it against correct code.
`audit_readiness_probe_without_a_request_deadline_keeps_the_store_budget` makes 2 dial
attempts, expected 1, when the second step reuses the full store timeout instead of
what is left of it. Locally, with Rust 1.98.1 and `RUSTFLAGS="-D warnings"`, the job's
commands then passed again, with 956 tests passed, 0 failed and 15 ignored, and
`cargo check` passed on Rust 1.94.1.

### Deployment

Kubernetes and Argo CD metadata, read on 2026-10-06 between 00:26 and 00:35 UTC:

- The maintainers' mainnet deployment still runs the image digest named in section 9,
  `sha256:af496b5b37c17378f92d432e8d5574a2e1c635f5f48be842a14aa8abcd631fe0`, on all
  three pods.
- Its GitOps source is still commit `6e10b27f3dce113aaa3ce97d48c4cb462ed6c8aa`.
- `7dc694ca`, `3edb5d23` and the later documentation and version commits were not
  built, published as an image or deployed at that read. No `v2.5.0` image tag, Git
  tag or GitHub release existed when checked at 00:55 UTC.
- The revision label `ff249a1b` is the provenance recorded at the 2026-10-05 rollout.
  The container package is private and anonymous registry inspection was denied, so
  the label was not read again.

### Effect on that deployment if released with unchanged configuration

Configuration facts below come from the GitOps values file. The pods' environment was
not read.

- The values set `PILLAR_AUDIT_ENABLED: "false"`. Then `AuditConfig::from_map` returns
  `None` (`crates/pillar-config/src/execution.rs:150-153`) and no audit store or
  database connection exists (`crates/pillar-runtime/src/execution.rs:43-50`). The
  audit TLS and readiness changes do not run.
- The chain list has 18 chains and no TON or Canton chain. The TON readiness change
  does not run.
- No server crate depends on `pillar-client`, so its signer-order and `Debug` changes
  are not in the image.
- `pillar-core`, `pillar-signer` and `pillar-layerzero` are unchanged since
  `ff249a1b`. Hash, call-data, signing and address-derivation code is the same.
- The remaining runtime effect is the text of provider-config and quorum-strategy error
  messages and refresh logs. Which configurations are accepted does not change.

### Remaining limits

- **Remote TLS.** Only a local synthetic TLS server was tested. No remote database was
  tested. `SECURITY.md` states the trust and plaintext rules. With audit on, each
  process uses at most two database connections: one for writes and one for
  readiness. These limits apply when audit is enabled. They do not block a release
  that keeps audit off.
- **Canton.** The live test needs the inputs in section 6. Canton code did not change
  after `ff249a1b`, and the deployment has no Canton chain. The maintainers rely on the
  repository's own Canton tests.
- **TON response depth (not fixed, present since before `ff249a1b`).** The independent
  reviewer reported that a recorded toncenter testnet `/events` response nests JSON
  266 levels deep, beyond the default `serde_json` recursion limit.
  `bounded_json_response` decodes provider responses with that default
  (`crates/pillar-runtime/src/provider_health/transport.rs:429`), so such a response
  fails to decode. The reviewer's replay of that response removed its `decoded` field;
  it is not a raw end-to-end transport pass. It is not known whether LayerZero TON
  traffic produces such responses. The deployment above has no TON chain.
- **Signer addresses.** As in section 9, the addresses after the next rollout are not
  verified unless each pod's `/signer-info` is recorded before and after it.
