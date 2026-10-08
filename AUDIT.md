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
- **TON response depth.** 이번 수정은 TON 전용 decoder에 4 MiB 응답 제한과 512-level JSON container nesting 제한을 적용한다. 실제 localhost HTTP 경로에서 합성 depth 266과 512를 허용하고 513을 거부했다. 250-node trace의 실제 fetch, fingerprint와 해제도 검증했다. JSON nesting은 trace node 수와 다르다. 보고된 266-depth 원본 응답은 찾지 못했으므로 원본 replay는 아직 미확인이다. 기존 archived fixture의 depth는 25이며 원본 증거를 대신하지 않는다.
- **Signer addresses.** As in section 9, the addresses after the next rollout are not
  verified unless each pod's `/signer-info` is recorded before and after it.

## 11. 리테스트 후속 수정, 2026-10-07

`f5868d0428cf3edb585dca5a396c02e37d3d0ade`를 기준으로 source finality, receipt integrity, READ empty return, extra-context, recovery ID와 TON 응답 경계를 수정했다.
통합 검증과 재현 명령은 maintainer-local `audit/retest-250/verification.md`에 보존한다. 원시 실행 출력과 로컬 관측 자료는 이 source 체크포인트에 포함하지 않는다.
이 문서의 과거 배포 설명은 과거 시점의 근거다. 2026-10-07 검증 당시 변경은 미커밋·미게시 상태였다. 이 체크포인트는 source 게시용이며 production 배포를 포함하지 않는다.

### 범위와 의도적인 차이

- `polygon`과 `tron`만 finalized policy를 추가한다. Receipt 높이의 canonical header number/hash 결속은 reference보다 엄격하다. 지원하지 않는 finalized RPC에 latest fallback을 하지 않는다. 운영 provider의 finalized 지원은 실제 RPC로 검증하지 않았다.
- Receipt quorum은 typed semantic fields를 비교한다. Receipt/log의 transaction/block identity와 명시적인 `removed=false`를 요구한다. Optional `0x` prefix는 같은 transaction hash로 비교하지만 RPC wire 값은 바꾸지 않는다.
- Source evidence 확장으로 validation audit hash는 이전 버전과 byte 단위로 비교할 수 없다. 원래 보관한 evidence는 수정하지 않는다.
- Extra-context consumer는 새 typed `signingContext` 필드를 허용해야 한다. 알 수 없는 입력 필드와 없는 optional 값은 typed serialization에 남지 않는다. Live Lambda와 cloud KMS는 호출하지 않았다.
- TON 제한의 단위는 JSON container nesting이다. 512 nesting은 512 trace levels를 뜻하지 않는다. 허용된 최대 trace levels는 envelope에 따라 달라지며 대략 254이다. 원본 JSON 해제는 반복형이다. 변환된 trace tree의 일반 해제는 허용된 depth로 제한한다.

### Azure Solana 근거와 남은 조건

공개 LayerZero-v2 commit `9c741e7f9790639537b1710a203bcdfd73b0b9ac`의 `dvn_config.rs`는 64-byte signer `X||Y`를 정의한다. Anchor/Borsh layout은 첫 signer의 byte offset 17을 뒷받침한다. 이 근거는 해당 source layout만 확인한다.

Main은 2026-10-07 17:36:52 KST에 공식 공개 Solana mainnet RPC로 계정 `EqkXVEeapm7JqrS1W3AGeN5ZwCRLDUHtr1XY9TuVr4rD`를 조회했다. Finalized slot은 `454171112`이다. Owner는 `9U6MUTuH9XZFoP993kq3We6gu95NbJhNM82cdpbpyF9n`이다. `DvnConfig` discriminator와 signer 수 1을 확인했고 offset 17의 64 bytes가 Azure fixture와 일치했다. 원본 응답 SHA-256은 `ca5c00de9c4104173926b95f8ad7f36e6b811c0c0b8d86d1e972605c43548e14`이다.

이 관측만으로 Azure binding 전체를 닫지 않는다. 해당 owner의 deployed executable/version과 source 대응이 필요하다. 같은 immutable Azure key version의 독립 공개키 응답도 필요하다. 이번 작업은 Azure API를 호출하지 않았다.

### Reference provenance와 진단 차이

- 리테스트 원본 SHA-256은 `0ef2ddc5f3f2796818f3e895c9410122568c9a90de345eb42db813216ab8e531`이다. 보고서의 `78bdd20e…`와 저장소의 `8ad87eb6…`는 hash 대상과 전체 값이 확인될 때까지 같은 식별자로 합치지 않는다.
- 원본 `gasolina-audit-main.zip` SHA-256은 `2e94b7cdc0e9f4bdfecba47ac391b3e619bfd9ad6d0dfc069ae4c498ef42d090`이다. Archive comment의 `213cd50097f5c19438a28ecb5ec63da99d8485e7`을 독립 검증한 reference commit이라고 주장하지 않는다.
- 보고서는 351 comparisons를 적었지만 category 합은 387이다. 중복과 적용 대상을 설명하는 comparison ledger가 없으므로 이번 작업은 351 전체 재실행을 주장하지 않는다. 기존 acceptance matrix의 1696 rows는 다른 집계다.
- 원본 보고서는 checksummed target과 bytes32-padded sender/receiver의 `debugInfo` 차이를 293건으로 집계했고 signature는 같다고 보고했다. Malformed JSON과 READ-on-V302는 같은 status code에서 error text가 달랐다고 보고했다. 이는 작성자 보고이며 Main의 새 reference replay가 아니다. 이 진단 형식은 바꾸지 않았다. Finalized lag의 confirmation 표시값은 reference의 `-1`과 다르지만 두 구현 모두 signing을 거부한다. 오류 종류와 sign-stage 진입 여부를 검증했다.

근거: audit/retest-250/verification.md와 원본 리테스트 보고서 · 시각 미상

## 12. `80e0ad21` 감사 후속 개발, 2026-10-08

정상 입력의 처리와 서명 성공을 acceptance로 유지한다. 거부 시나리오만 통과한 결과는 완료로 취급하지 않는다.

- TON 변환은 bounded postorder plan을 만든 뒤 필요한 scalar만 투영한다. 같은 transaction을 여러 node에 복제하지 않는다. Duplicate hash와 잘못된 topology를 거부한다. 최대 node 수는 512다. 변환 후 JSON container depth도 512로 제한한다. 생략된 leaf children은 빈 배열로 처리한다. 이 정규화는 children 누락에서 오류가 나는 upstream quorum 함수와 의도적으로 다르다. `/events`와 legacy `/transactionTrace`의 HTTP 경로로 이 차이를 검증한다. 입력의 미사용 metadata는 output에 복제하지 않는다. Object와 Array를 직접 조립한다.
- 실제 HTTP TON fixture를 별도 release 프로세스에서 실행했다. Stack은 2 MiB다. 정상 chain, 512-node star, 4 MiB 미만 큰 metadata 입력과 depth-505 입력을 처리했다. Malformed 입력 뒤의 정상 요청도 성공했다. Quorum 조기 반환, loser 해제와 cancellation을 확인했다. `/usr/bin/time -l`이 관측한 최대 RSS는 29,261,824 bytes다. macOS의 OS 강제 RSS 제한이라고 주장하지 않는다.
- 실제 HTTP `ReqwestJsonRpcTransport`와 `RuntimeServerApp`으로 READ 서명을 실행했다. Empty call과 code `0x00` 및 `0x6000`은 기준과 같은 signature를 반환했다. Provider 3개 중 정상 2개는 불량 1개가 있어도 quorum 2로 서명했다. 잘못된 DATA와 서로 다른 provider의 부분 observation은 signer에 진입하지 않았다. Call과 code의 provider header 및 EIP-1898 pin을 함께 확인했다. HTTP가 생성한 `Content-Length`는 요청 body 길이에 따라 다르므로 provider header 비교에서 제외했다.
- Receipt의 생략된 `removed`를 false로 정규화했다. true, null과 잘못된 타입은 거부한다. 실제 CLI에서 정상 quorum 2, `l1Fee` 차이, 모든 `removed` 생략과 생략/false 혼합이 동일 payload와 signature로 성공했다. Log index 중복은 최초 resolution과 readiness 재조회에서 거부한다. 최초 resolution은 모든 log를 검사하고 readiness 재조회는 선택된 PacketSent log를 검사한다. 운영 Ethereum→Celo의 원본 finalized PacketSent receipt도 local CLI에서 서명했다. Metadata와 생략/false 변형을 포함한 정상 3개는 같은 payload와 signature를 냈고 integrity 및 quorum 변형 11개는 sign-stage 진입이 0이었다. 운영 receipt는 바꾸지 않았고 정상 API pathway 주소만 upstream 형식으로 표현했다.
- 운영 `ovh-cluster/rpc-mainnet/lz-rpc`의 Ethereum과 Polygon RPC를 읽기 전용으로 확인했다. Finalized head, receipt/canonical block 결속, EIP-1898 call/code와 존재하지 않는 hash의 거부를 관측했다. 첫 Polygon probe는 code가 없는 잘못된 주소를 사용했다. 원시 실패 자료를 보존하고 운영 receipt에서 관측한 token 주소로 수정해 정상 결과를 확인했다. 운영 provider 설정에는 Tron이 없다.
- 운영 EVM endpoint 17개의 정상 EIP-1898 call/code를 확인했다. 16개는 존재하지 않는 hash를 거부했다. Hyperliquid proxy는 같은 잘못된 hash에 정상 DATA를 반환했다. 2026-10-08 11:09 KST의 기존 upstream 직접 조회에서는 QuickNode도 이를 거부하지 않았고 Alchemy는 정상 historical hash를 처리하면서 잘못된 hash를 두 메서드 모두 거부했다. 이 문제는 latest fallback으로 우회하지 않는다. 검증된 archive 경로를 분리하고 unsafe upstream으로 failover하지 않는 운영 설정이 필요하다. 설정이나 배포는 아직 바꾸지 않았다.
- 2026-10-08 10:23 KST의 읽기 전용 조회에서 immutable Azure key version의 공개키, 운영 Pillar의 공개키와 finalized Solana DVN config의 signer가 같은 64-byte `X||Y`임을 확인했다. Config slot은 `454395711`이다. Owner program은 executable이며 program-data의 배포 slot은 `432734589`이다. 공개 verified-build registry는 이 program을 `is_verified=false`로 반환했다. Deployed program과 source의 재현 가능한 대응은 별도 조건으로 남긴다. Live KMS 서명과 on-chain 서명 검증은 실행하지 않았다.
- Closed-schema HTTP policy consumer는 `sentEvent`, `from`, typed `signingContext`만 허용했다. Candidate CLI의 정상 receipt 6개는 이 consumer를 통과해 서명했다. 운영 배포의 direct env와 envFrom key 목록에는 extra-context 설정이 없었다. 정책 설정 확인에서는 credential 값을 조회하지 않았다. Archive upstream probe는 기존 URL reference를 process memory에서만 사용했고 URL과 credential 값을 evidence에 보관하지 않았다.
Maintainer-local 근거는 `audit/review-80e0ad21-20261008/`에 보존한다. `verify-candidate.sh`는 committed source와 HEAD의 일치를 검사한다. Runner는 candidate SHA, toolchain과 Cargo 입력 hash를 기록한다. 이어서 fmt, clippy, workspace test, release CLI smoke와 MSRV check를 실행한다. 로컬 runner 결과와 hosted CI 결과를 구분한다. 기존 `80e0ad21`의 CI 성공으로 새 candidate를 인증하지 않는다.

이 source 변경은 registry 게시나 production 배포를 포함하지 않는다. Section 11의 관측은 과거 근거로 유지한다. 원본 351 comparison ledger와 축약 reference hash의 대상은 확인된 자료로만 연결한다.

근거: audit/review-80e0ad21-20261008의 원시 실행 기록과 hyperliquid-archive-upstreams.json · 2026-10-08 11:09 KST

## 13. PR #1 리뷰 후속 조치, 2026-10-08

### RE-002: 결정적 READ 거절과 장애의 구분

Runtime은 DATA, pinned NoCode와 execution revert를 별도 observation으로 집계한다.
Runtime은 기존 category와 entity 정책으로 유일한 quorum을 확인한 뒤 domain refusal을 반환한다.
단일 불량 provider는 정상 provider quorum을 거절로 바꾸지 않는다. 서로 다른 결과의 quorum이 동시에 성립하면 signer에 진입하지 않는다.

Revert 분류는 numeric code `3` 또는 numeric code `-32000`과 정확한 `execution reverted` 메시지의 조합만 인정한다. 메시지의 대소문자는 구분하지 않는다.
Runtime은 제공된 revert DATA를 검증하고 fingerprint에 포함한다. 생략과 유효한 `0x`는 같은 빈 DATA이며, null·잘못된 타입·잘못된 hex는 vote를 얻지 못한다.
Timeout, transport 장애와 다른 RPC error는 non-retryable domain refusal로 바꾸지 않는다. HTTP consumer 계약은 [README.md](./README.md)에 명시했다.

실제 TCP API handler와 Reqwest provider fixture의 관측은 다음과 같다.

| 결과 | Case 수 | HTTP status | Sign-stage |
|---|---:|---:|---:|
| 정상 처리 | 12 | 200 | 각 1회 |
| Quorum으로 확인한 domain refusal | 4 | 400 | 0회 |
| 장애·불완전 DATA·모호한 quorum | 17 | 500 | 0회 |

각 case의 실제 status는 기대값과 일치했다. Empty call의 code `0x00` 및 `0x6000`과 1-bad/2-good 정상 control을 유지했다.
원시 요청·응답·pin·provider header와 signer counter는 `audit/review-pr1-20261008/main-validation-95w4uR/read-http/http-results.json`에 보존한다.
이 파일의 SHA-256은 `e8753b3e6df4e0611bbe49d6de302641c9ad011bda572bd6a4a05c7da37f60c4`다.
실행한 runtime test binary의 SHA-256은 `a4089ef24da7720e083a89f3eb8f9547eaae3203c1b9d0e89a8b2d1db610eaf9`다.
이 실행은 아직 commit하지 않은 후속 source를 Rust 1.98.1로 검증한 로컬 실행이다. HEAD `87b4bae`의 기존 CI나 운영 배포 실행으로 표현하지 않는다.

독립 리뷰에서 발견한 잘못된 revert 분류는 같은 case ID로 수정 전과 후를 대조했다.
`read-domain/run-07/http-results.json`의 SHA-256은 `9ad34908c2474db0dbfe11f4d53d44c169d9ae0919dd576b06728ada8997e022`다.
수정 전에는 method-not-found, timeout 및 잘못된 code 형식의 5개 case가 domain refusal로 오분류됐다.
`read-domain/run-08/http-results.json`의 SHA-256은 `5d1b39d4227e2a53478ad1981fba51393afc2a5488e4d20a8eaefbcc3edb5e25`다.
수정 후에는 이 case들이 internal 오류로 남고 정상 독립 provider의 quorum은 성공했다. 원본 351 comparison의 case ID로 임의 매핑하지 않는다.

### 전체 검증과 CI 증거의 경계

Rust 1.98.1과 `RUSTFLAGS=-D warnings`의 fmt 및 workspace all-targets clippy는 통과했다.
같은 workspace test는 전체 성공이 아니다. Runtime 결과는 496 passed, 1 failed, 15 ignored다.
실패한 기존 `provider_config_refresh_failure_logs_the_position_but_not_the_value`는 빈 log capture를 관측했다. 해당 source와 보안 assert는 바꾸지 않았다.
원시 workspace log의 SHA-256은 `129b54eac4740fbc1e18e21957f8d0f45e94f0385dc338180e1b8b0e39e1fbe6`다.
조사 작업자는 독립 harness에서 다른 NoSubscriber thread의 첫 callsite 등록으로 tracing InterestCache가 로그를 누락하는 메커니즘을 재현했다고 보고했다. 원본 실행의 registration 순서는 미확인이므로 원본 실패 원인은 추론으로 남긴다.
이 조사는 `audit/review-pr1-20261008/refresh-log-investigation/`에 보존한다. 새 READ HTTP 경로와 직접 연결되는 subscriber 변경은 찾지 못했다.

후속 hosted CI run `37749547883` 기록: PR head `9e29dc93acbeaf13bc65a6eaf85ef4de0ac71473`, CI checkout `ff3fb4ad19e790ba5193011b88a62ee840521bd7`, tree `fb07731b2ff2d96b9ad5e06159473822915bd3bd`; 6개 job 성공. Hosted workspace 970 passed / 0 failed / 15 ignored (985 unique)이며 Main local runtime 496 passed / 기존 log-capture fixture 1 failed / 15 ignored와 별도다.
Hosted READ HTTP artifact 33건은 expected/actual status가 일치했다 (200 12, 400 4, 500 17). Quorum 확인 no-code/revert 4건은 `UNRESOLVABLE_COMMAND`, `retryable=false`, signer stage 0이며 timeout/transport·불완전 관측·모호한 결과는 domain refusal이 아닌 500으로 남았다. 1-bad/2-good healthy quorum은 성공했다. CI image를 Docker CLI로 실행한 별도 6-case READ smoke와 SDK signature recovery 3건은 `audit/review-pr1-20261008/ci-image-http-smoke/`에 보존한다. 이는 실제 image 실행이지 운영 KMS 서명이나 Kubernetes 전체 테스트가 아니다.
운영 rollout은 existing Deployment `3/3` updated/ready/available, `/ready` HTTP 200 및 `/signer-info` signer identity 응답을 기록한다. Image는 `ghcr.io/fp-validated/pillar-dvn-client:ci-ff3fb4ad19e7-r37749547883-a1@sha256:4ac2cbcd560b7bc1607f7846027509d42c881aacbf557d8d882100d804e80aae`로 digest 고정한다. 영구 `version` 응답 `v2.5.0`은 image identity 대체물이 아니다.
기존 chain/entity/quorum과 18개 `LAYERZERO_AVAILABLE_CHAIN_NAMES`를 유지하고 Hyperliquid URI만 기존 Alchemy-backed `hyperliquid-pinned` alias로 변경했다. ConfigMap 변경 checksum은 `985bee4a4f0dda1da8d743765536e6e95c744cbab284a792dde36c3b9fbf795c`다. Live pin-control은 historical number/hash의 call/code 일치와 missing-hash error를 관측했지만 동일 provider selector 비교라 독립 oracle/fork/failure injection이 아니다. 실제 정상 MESSAGE의 운영 KMS 서명은 미관측이다. Original351 ledger, original raw266 replay, original78 manifest 연결, A2/A4/B3 original-case mapping, Solana program-source build는 미확인이라 원본 8 finding 전체를 `fixed_verified`로 닫지 않는다.

### RE-001: 기존 운영 Deployment의 한정 교체

운영 적용 대상은 기존 `ovh-cluster/rpc-mainnet/lz-rpc`와 `ovh-cluster/layerzero-mainnet/pillar-dvn-client-mainnet`이다. 별도 테스트 Deployment는 만들지 않는다.
준비한 `hyperliquid-pinned` alias는 기존 Alchemy URL reference만 사용한다. Generic Hyperliquid route와 다른 chain, Secret, signer identity 및 entity quorum 정책은 유지한다.
Pillar의 Hyperliquid URI만 alias로 바꾸고 CI가 만든 image를 기존 private registry 경로에서 digest로 고정한다.
정확한 image와 ConfigMap diff, 기존 resource identity, rolling 전략 및 rollback을 운영 승인 전에 함께 제시한다. 전체 Argo Application의 기존 drift는 반영하지 않는다.
기존 계획에서 정상 historical hash/missing hash control, noncompliant-upstream failover 차단 및 정상 MESSAGE 서명을 사후 확인 항목으로 제시했다. 현재는 앞의 제한 pin-control만 관측됐고, 독립 failover 장애주입과 운영 KMS 정상 MESSAGE 서명은 미관측이다.
기존 운영 Deployment 변경/rollout은 `audit/review-pr1-20261008/operating-rollout/`에 보존한다. 실제 ready/signer-info 및 pin-control 결과가 있으나 `metrics.prom`의 sign budget started/success/error가 각각 0이어서 운영 KMS의 정상 MESSAGE 서명은 수행·관측하지 않았다. Main은 startup log에서 Azure signer, 18 chains, `any:1` quorum 및 API auth disabled 설정이 유지됐다고 보고했다. Private GitOps main 게시와 minimal patch/rollback은 retained evidence로 구분하며 Public PR은 미병합이다.
별도의 f26c3fb GitOps validator run `37768428872`는 success이고 Harbor mirror run `37768428871`은 failure다. Mirror workflow는 `contents:read`만 가졌고 GHCR mirror username/token secrets는 비어 있었으며, Main이 제공한 mirror log의 exact-digest lookup은 `MANIFEST_UNKNOWN`으로 끝났다. 이는 그 workflow의 GHCR source-read/auth 실패이지 image 미게시 증거가 아니다. Main은 로컬 인증 및 실제 3-Pod pull에서 같은 digest를 읽었다고 보고했다. Source-read 권한 remediation은 필요하지만 package permission/credential 변경은 승인·실행되지 않았고 raw failure는 보존했다. 이는 Pillar hosted CI `37749547883` 6/6 success와 별도다. `gitops-followup-ci.json`과 `mirror-secret-metadata.json`은 관측 artifact이며 startup/mirror log와 pull 확인 세부는 Main-reported로 구분한다.
추가 관측 경계: 별도 independent review의 마지막 live re-query는 2026-10-08 20:40:20 KST이며 report SHA-256은 `1b0f13b28c8072abfed7ff333f1bfadae2c768d4dd438aa919d9eb735f03af84`다. Main이 22:36 KST에 기록한 report byte 확인 시각은 관측 시각이 아니다. Main은 final Deployment를 22:38 KST에 다시 확인했고, `pillar-deployment-final.json`은 3/3 replicas/updated/ready를 기록한다. 반면 `metrics.headers`의 Prometheus 관측은 20:34:18 KST이므로 sign-budget 0/0/0을 22:38 이후 상태로 확대하지 않는다.
같은 시점대의 좁은 fresh discovery는 Arbitrum 단일 64-block window에 PacketSent 0 (20:32:41 KST), BSC 단일 window에 source candidate 0 (마지막 RPC 20:36:15 KST), Base 단일 64-block window에 PacketSent 5건이나 destination EID 30168/30302 모두 지원되지 않아 supported candidate 0 (head 조회 20:36:28 KST)으로 기록됐다. Main은 기존 Ethereum 후보 3건은 이미 Verified라고 별도 보고했다. 이는 기존 증거이며 fresh scan 결과가 아니다. 이 scan은 normal signing canary를 만들지 않았고 KMS/normal API POST·signature가 없다. 한정 window의 후보 부재로 전체 normal path의 불가능을 추론하지 않는다.
QuickNode 독립 control은 22:37:59–22:38:00 KST 관측에서 chain/block identity 일치, historical call mismatch를 기록했다. 최초 결과의 code mismatch는 hex text를 bytes 대신 hashing한 비교 오류였고, 보존된 offline comparison은 2041-byte code identity 일치로 정정했으나 call mismatch는 남는다. QuickNode는 eligible provider에서 계속 제외하고, independent PIN-VALID 완료로 주장하지 않는다. Alchemy temporal control은 22:42:24–22:42:28 KST historical block number/hash 및 call을 20:22:48 KST의 기존 관측과 재현했고 latest call은 달랐다. 이는 동일 deployed route의 시간 비교일 뿐 independent oracle, 실제 fork 또는 failure injection이 아니다.
F1/F2 rollback은 기존 minimal plan의 순서를 따른다: consumer source의 두 field를 먼저 revert하고 Target2 ConfigMap/Deployment를 되돌려 3-Pod rollout 완료를 기다린 뒤, proxy source alias를 되돌리고 Target1을 rollback하여 rollout 완료를 확인한다. Live-only rollback과 whole-app sync는 금지한다. 계획만 갱신됐으며 rollback은 실행되지 않았다.
별도 three-provider historical-state probe는 2026-10-08 22:49:35.620–22:49:52.496 KST에 historical block n−1/n/n+1의 read-only eth_call 9건을 보존했다. SELF 3건은 transport/JSON observation 실패, QuickNode 3건은 성공했으나 n 결과가 22:38 KST sample과 달랐고, Alchemy 3건은 20:22:48.008 KST의 이전 historical 결과를 유지했다. 독립 PIN-VALID 완료는 아니며 QuickNode는 제외 상태다. Zero StateRoot는 Ethereum state-proof의 한계이지 request pin 불가능의 단독 증거가 아니다.
SELF direct existing Service control pin-self-service-control.json (ovh-cluster/rpc-mainnet/rpc-hyperliquid-mainnet-node-01-rpc:3001/evm)는 22:57:33.375–22:57:36.747 KST의 5개 read-only RPC다. chainId 0x3e7, historical block 0x2dc3f31/hash 0xb9dea23449cb0d58d846784fcef02260c94dfb769f66981c70edb497523a0ab1은 일치했고 n−1/n/n+1 call은 모두 SELF 0x00000000000000000000000000000000000000000002ab88d99c0f8c248f52f9, Alchemy 0x00000000000000000000000000000000000000000002ab169fb0aa81ce948969로 달랐다. 이 direct service는 hash-pinned READ eligible에 추가되지 않았고, normal independent PIN-VALID 또는 archive consistency 전체 완료가 아니다.
Credential/Secret 경계: preparation 단계와 이번 direct SELF query 모두 Secret lookup이 없었다. 별도로 앞선 22:38/22:49 Main direct probes는 endpoint를 Secret payload에서 메모리상 읽었으나 credential을 저장·공개·변경하지 않았다.
최종 runbook은 consumer/proxy를 각각 strict-mode bash subshell로 분리하고, consumer 완료 뒤 proxy source alias revert 및 재조회 단계를 요구한다. consumer rollout 오류/timeout이면 중단하고 proxy alias를 유지한다. 일반 Hyperliquid route와 v2.5.0 복귀는 RE-001 위험을 재도입하고, maxUnavailable 1로 proxy rolling 중 용량이 절반까지 줄 수 있다. scan-only mirror source-read 문제는 별도로 기록한다. 실제 rollback과 KMS·권한 변경은 없었다.
Main-reported cleanup (2026-10-08 22:47:36 KST): 네 task-owned forward의 정확한 PID/command를 확인 후 종료했고 18545/19873/18546/19874에서 ps/lsof 잔여가 없었다. 사용자 18080은 미변경, 운영 workloads는 유지됐다. du: operating-rollout 428 KiB, hosted-ci 201480 KiB, source-checkouts 2264 KiB. raw evidence, original CI tar, source Git metadata 보존; shared build caches, 이전 Docker artifacts, spookfish 소유 8 files는 삭제하지 않았다. cleanup zero로 주장하지 않는다.
Main-reported 23:01:32 KST cleanup: PID 90100와 command를 확인하고 새 SELF forward를 종료했다. 전체 5개 owned-forward ports 18545/18546/18547/19873/19874에서 lsof 잔여가 없었다.
근거: Main local raw run; hosted CI run 37749547883 independent review; ci-image-http-smoke; operating-rollout; fresh Arbitrum/BSC/Base; pin-independent-control.json, pin-independent-comparison.json, pin-temporal-control.json, pin-three-provider-state.json, pin-self-service-control.json; Main-reported cleanup; minimal-existing-rollout · latest direct observation: SELF call comparison finished 2026-10-08 22:57:36.747 KST; PID 90100 stopped/five-forward lsof check 23:01:32 KST (provider state 22:49:52.496 KST; reviewer live re-query 20:40:20 KST; sign metrics 20:34:18 KST)
