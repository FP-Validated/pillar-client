# Audit guide

This editable guide summarizes the repository, reproducible checks, trust boundaries and dated review evidence. It is not the original external audit report; source reports and raw evidence remain in their recorded locations.

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
`single-provider-trust-root`, warned on each refresh that changes those chains to a non-empty set, and
counted in `pillar_provider_single_entity_chains`), a majority of colluding providers, and fleet-wide rate
limiting (budgets are per process). `SECURITY.md` "Operator responsibilities" lists
the controls left to the deployment.

### Trust boundaries

| Boundary | Trusted side assumes | Enforced in | Failure mode required |
| --- | --- | --- | --- |
| HTTP caller → API | Bearer token from `PILLAR_API_AUTH_TOKENS` (≥32 chars) unless the operator opens sign routes (`PILLAR_PUBLIC_SIGN_ROUTES=true`) or turns auth off (`PILLAR_API_AUTH_ENABLED=false`, every route public); request fields are untrusted | `crates/pillar-api/src/lib.rs` (`authorized`, `constant_time_token_match`, request shape gates), `crates/pillar-runtime/src/server_app/server_trait.rs` (`auth_token_matches`), `crates/pillar-cli/src/main.rs` (header/request deadlines, connection cap) | 401, or 400 for malformed input, before any provider or signer call |
| Provider-config source → quorum | `providers-v2.json` and `quorum-strategy.json` from a local file or an S3/GCS bucket define entities and strategies; a writer of that source sets the trust root | `crates/pillar-config/src/provider_validation.rs`, `crates/pillar-runtime/src/config_loader.rs` | Refuse unknown fields, unknown strategy categories and zero-entity strategies; a refresh that cannot sign keeps the previous snapshot; single-entity chains are logged and counted |
| Request → packet | Only the `PacketSent` emitted by the trusted contract for the requested version and pathway is accepted | `crates/pillar-runtime/src/layerzero_runtime/packet_resolver.rs`, per-family `source_events_*.rs` | 400 on identity mismatch; never sign a packet the request does not name |
| RPC providers → validation | Answers are counted per `(category, entity)`; differing answers never merge | `crates/pillar-runtime/src/provider_health/**` | Fail closed when the strategy is not met or two answers could each meet it |
| Readiness / reorg | Confirmations from the validated block; READ calls pinned by block hash with `requireCanonical` | `layerzero_runtime/validation_readiness.rs`, `layerzero_runtime/read_payload.rs` | Refuse unpinned or non-canonical reads; no fallback by number |
| Static tables → builders | Addresses, endpoint ids and `vId` come from generated tables per environment | `crates/pillar-config/src/generated_*.rs`, `crates/pillar-layerzero/src/**` | Unsupported `(chain, environment, version)` is an error, never a default |
| Extra-context service | External yes/no over HTTPS or Lambda; URL must be absolute and without userinfo, `https` on mainnet, and `https` or `http` to a literal loopback address elsewhere, checked at startup | `crates/pillar-config/src/lib.rs` (`validate_service_url`), `layerzero_runtime/validation_extra_context.rs` | Process refuses to start on a bad URL; a rejection or error stops the request before the builder and signer |
| Canton sequencer / ledger | Sequencer reads verified against a configured committee when set; ledger read needs OAuth2 client credentials | `layerzero_runtime/canton_sequencer.rs`, `layerzero_runtime/canton_ledger.rs` | Refuse before any request without credentials; refuse on `sandbox`/`localnet` |
| Validation → signer | Signer sees only the 32-byte digest built from validated data; key and address derivation per chain family | `crates/pillar-signer/src/**`, `crates/pillar-runtime/src/signer_runtime/assembly.rs` | Unsupported KMS provider fails clearly; secrets redacted in `Debug`; mnemonic seeds and derived keys held in `Zeroizing` buffers |
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
deployment are retained as maintainer-local evidence. Sections 9 and 13 summarize
the dated releases, rollout observations and their scope.

Azure-backed Solana evidence includes the public-key/config correspondence in
section 12. The remaining audit acceptance conditions are centralized in
`SECURITY.md`, "Where responses still differ from upstream".

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

## 9. Publication, CI and release status

Public CI and deployment observations are point-in-time evidence; they do not certify later source or a live signing path.

| Run / source | Result | Historical significance |
| --- | --- | --- |
| [37314461749](https://github.com/FP-Validated/pillar-client/actions/runs/37314461749), `a4d8ff3d` | 5/5 jobs; Rust 934 passed, 0 failed, 13 ignored | Last code/CI baseline before `7dc694ca` and `3edb5d23`; test counts are not acceptance rows. |
| [37397588068](https://github.com/FP-Validated/pillar-client/actions/runs/37397588068), `d3b282150e51594fd91d825c1aa56ffe8584680a` | 4/5 jobs; clippy failed on `clippy::chunks_exact_to_as_chunks` in `crates/pillar-client/src/lib.rs:531` | Fixed by replacing `chunks_exact(2)` with `as_chunks::<2>()`. |
| [37399413275](https://github.com/FP-Validated/pillar-client/actions/runs/37399413275), `d947947057f0759f05c94e34faae3663723ed216` | 4/5 jobs; readiness test observed 9 connections (bound 2) | Fixed probe budget/lane ordering; later 956 passed, 0 failed, 15 ignored locally on Rust 1.98.1; MSRV check passed on 1.94.1. |
| [37749547883](https://github.com/FP-Validated/pillar-client/actions/runs/37749547883), PR CI checkout `ff3fb4ad19e790ba5193011b88a62ee840521bd7` | 6/6 jobs; hosted workspace 970 passed, 0 failed, 15 ignored | Separate from Main local runtime 496 passed, 1 failed, 15 ignored (existing refresh-log capture case); exact source/tree and raw output are retained under `audit/review-pr1-20261008/`. |

The 2026-10-05 release was image `sha256:af496b5b37c17378f92d432e8d5574a2e1c635f5f48be842a14aa8abcd631fe0`, built from `ff249a1b83edcc25a099d5b7e0706d4c36248b67` and rolled out via private GitOps commit `6e10b27f3dce113aaa3ce97d48c4cb462ed6c8aa`. Three pods reported Ethereum `0x06bb41FE76F41429f55aC8C355ac8669769A1ba1` and Solana `EboBSUoobiqt7JYcH46ro7TGBjtE2vczKnUmsiWy6Ffy`; no before-rollout identity was recorded, so identity continuity was not established.

## 10. Remediation and dated test status

Commits `7dc694ca53ef4941532a39808e71530b5300d9a5` and `3edb5d237120c9c37493c2ad8be3a69cfcc8c20e` addressed seven public-audit findings and subsequent audit readiness, redaction and regression-test findings. Independent review accepted their executable code. The 2.5.0 version/lockfile update changed no executable logic or third-party dependency.

| Check, as recorded | Result and boundary |
| --- | --- |
| Local Rust 1.96.0 workspace | 954 passed, 0 failed, 15 ignored; fmt clean; clippy exited 0 with one `nonminimal_bool` warning. It preceded the final edit to one ignored PostgreSQL test. |
| PostgreSQL / TLS opt-in tests | 11 PostgreSQL and 2 TLS tests passed against disposable PostgreSQL 18.6; crash-worker coverage was via its parent test, with exit codes 73/74 asserted. |
| CI 1.98.1 fix checks | After both CI failures, local fmt/clippy/test/release checks passed (954 then 956 tests respectively); MSRV check passed on 1.94.1. |
| Canton live-ledger test | Not run; required ledger, party and live inputs were unavailable. |

At the 2026-10-06 deployment read, the old image remained on all three pods and the newer code was not deployed. GitOps values had audit disabled, 18 chains and no TON/Canton; thus audit TLS/readiness and TON/Canton behavior were not exercised there. This is a dated state superseded by the 2026-10-08 rollout summarized in §13. The local missing-wallet-scope worker check had `sdk_calls=0` and `attempts=0`; it is not a deployment signing test.

## 11. 2026-10-07 retest: scope and provenance

The follow-up to baseline f5868d0428cf3edb585dca5a396c02e37d3d0ade changed source-finality policy, receipt integrity, empty READ returns, extra-context, recovery ID and TON response boundaries. Reproduction details remain in audit/retest-250/verification.md; original evidence is preserved.

- Only `polygon` and `tron` gained finalized policy. Receipt-height canonical header number/hash binding is stricter than reference; unsupported finalized RPC does not fall back to latest. Production-provider finalized support was not established by that retest.
- Receipt quorum compares typed semantic fields and checks receipt/log transaction and block identity plus `removed=false`. Optional `0x` prefixes normalize for comparison without changing the RPC wire value. Source-evidence expansion means validation audit hashes are not byte-comparable with the earlier schema.
- TON's 512 limit is JSON container nesting, not trace-node depth; envelope-dependent usable trace depth is about 254. The reported original depth-266 response was unavailable; its replay remains unverified.
- Public LayerZero-v2 commit `9c741e7f9790639537b1710a203bcdfd73b0b9ac` supports the 64-byte signer `X||Y` layout and offset 17. The 2026-10-07 finalized Solana account read (slot `454171112`, owner `9U6MUTuH9XZFoP993kq3We6gu95NbJhNM82cdpbpyF9n`) matched the Azure fixture; response SHA-256 `ca5c00de9c4104173926b95f8ad7f36e6b811c0c0b8d86d1e972605c43548e14`. This did not establish deployed-program/source correspondence or an independent Azure public-key match.
- Later changes supersede four of these dated statements: `5360159` accepts an omitted `removed` as `false` and refuses `null` or a non-boolean; the same commit caps TON trace nodes at 512 alongside JSON nesting; the 2026-10-08 probe in §12 matched the immutable Azure key version's public key; and `7a2c33f` reports `-1` when the finalized block is behind the receipt, as upstream does. §15 records the 2026-10-09 review follow-up and §16 the full review that followed it.

| Reference evidence | Recorded value / limitation |
| --- | --- |
| Retest report | SHA-256 `0ef2ddc5f3f2796818f3e895c9410122568c9a90de345eb42db813216ab8e531`; reported `78bdd20e…` and repository manifest `8ad87eb6…` are not equated until their hash targets are known. |
| `gasolina-audit-main.zip` | SHA-256 `2e94b7cdc0e9f4bdfecba47ac391b3e619bfd9ad6d0dfc069ae4c498ef42d090`; archive comment `213cd50097f5c19438a28ecb5ec63da99d8485e7` is not independently verified as the reference commit. |
| Original comparison coverage | Report states 351 comparisons, but category totals are 387 and there is no comparison ledger. The 1696 acceptance rows are a different measure; no 351-case rerun or remapping is claimed. |

The original report attributes 293 `debugInfo` differences (checksummed target vs bytes32-padded sender/receiver) with equal signatures, and reports malformed-JSON / READ-on-V302 error-text differences. These are report findings, not a new reference replay. Finalized-lag confirmation text differs (`-1` vs local value), while both sides refuse signing. Source report and raw data remain unchanged.

## 12. 2026-10-08 follow-up: behavior and provider controls

The `80e0ad21` work retained successful-path acceptance as well as refusals. TON conversion uses a bounded postorder plan, projects only required fields, rejects duplicate hashes and invalid topology, and caps node count and JSON nesting at 512; omitted leaf children normalize to an empty array. The intentional upstream difference and HTTP coverage for `/events` and legacy `/transactionTrace` are recorded in `audit/review-80e0ad21-20261008/`. A separate release-process HTTP run exercised normal/malformed inputs, 512-node star and depth-505 cases; observed peak RSS was 29,261,824 bytes (not an OS-enforced limit).

Receipt/READ controls exercised successful semantic normalization and fail-closed cases: empty READ call and code `0x00`/`0x6000` preserved signatures; quorum 2 succeeded with 1 bad provider; malformed/partial observations and receipt integrity/quorum violations did not enter signer stage. The original finalized Ethereum→Celo receipt was used read-only as input to local CLI runs. A closed-schema test policy consumer accepted only `sentEvent`, `from` and typed `signingContext`. The deployed configuration had no extra-context setting.

| Provider/control | Observation | Eligibility / limit |
| --- | --- | --- |
| OVH Ethereum and Polygon | Finalized head, receipt/canonical-block binding, EIP-1898 call/code and missing-hash rejection observed. Initial Polygon address was invalid; raw failure retained and probe repeated with receipt-derived token address. | Read-only controls; no Tron endpoint configured. |
| 17 production EVM endpoints | Normal EIP-1898 call/code observed on all; 16 rejected a missing hash. Hyperliquid proxy returned DATA for the missing hash. | Unsafe route is not a hash-pin control. |
| QuickNode controls | At 2026-10-08 11:09 KST, direct upstream call/code controls returned DATA for a nonexistent hash. Later historical call results also differed. The initial code mismatch was corrected as a text-vs-bytes hashing error; 2041-byte code identity matched. Evidence: maintainer-local `audit/review-80e0ad21-20261008/hyperliquid-archive-upstreams.json` and later pin controls. | Excluded from eligible pinned READ providers for hash-pin noncompliance. No latest fallback. |
| Alchemy controls | The 11:09 KST direct upstream control processed a valid historical hash and rejected a nonexistent hash for both methods. Later historical number/hash and call reproduced the earlier 20:22:48 KST read; latest call differed. | Historical/missing-hash and temporal controls; independent fork/failure injection is a separate acceptance scope. |
| SELF direct Hyperliquid service | At block `0x2dc3f31` / hash `0xb9dea23449cb0d58d846784fcef02260c94dfb769f66981c70edb497523a0ab1`, chain ID matched; n−1/n/n+1 calls differed from Alchemy. | Not added to eligible hash-pinned providers; not complete archive-consistency evidence. |
| Azure / Solana (2026-10-08 10:23 KST) | Immutable Azure key version, Pillar public key and finalized DVN signer matched at slot `454395711`; program-data deployment slot `432734589`. Verified-build registry returned `is_verified=false`. | Deployed program/source correspondence remains open; no live KMS signature or on-chain signature verification. |

The direct SELF probe and three-provider historical probe are read-only; their raw records are `pin-self-service-control.json`, `pin-three-provider-state.json` and neighboring pin-control JSON under `audit/review-pr1-20261008/operating-rollout/`. No provider configuration was changed in this phase.

## 13. PR #1 READ policy and bounded rollout (2026-10-08; merged 2026-10-09)

RE-002 keeps DATA, pinned NoCode and execution revert as distinct provider observations. A non-retryable `UNRESOLVABLE_COMMAND` refusal is returned only after the configured category/entity quorum uniquely agrees. One provider's NoCode cannot override a healthy DATA quorum; ambiguous competing quorums, timeout, transport errors, malformed DATA and other RPC errors do not become domain refusals. Revert classification accepts numeric code `3` with any message, or numeric code `-32000` only with the exact `execution reverted` message (case-insensitive), and validates/fingerprints revert DATA. Consumer contract: [README.md](./README.md).

| Evidence | Result and boundary |
| --- | --- |
| Main local HTTP/provider fixture | 33 cases: HTTP 200=12, 400=4, 500=17, all expected statuses; negative cases had no sign-stage series. Stage series count at that time was not a numeric invocation count. `http-results.json` SHA-256 `e8753b3e6df4e0611bbe49d6de302641c9ad011bda572bd6a4a05c7da37f60c4`; test binary `a4089ef24da7720e083a89f3eb8f9547eaae3203c1b9d0e89a8b2d1db610eaf9`. |
| Revert classifier before/after | Same five method-not-found, timeout and malformed-code cases corrected from false domain refusal to internal error; healthy independent-provider quorum succeeded. Raw `read-domain/run-07` and `run-08` hashes: `9ad34908c2474db0dbfe11f4d53d44c169d9ae0919dd576b06728ada8997e022` / `5d1b39d4227e2a53478ad1981fba51393afc2a5488e4d20a8eaefbcc3edb5e25`. Not mapped onto the original 351 comparisons. |
| Hosted CI / image smoke | PR head `9e29dc93acbeaf13bc65a6eaf85ef4de0ac71473`; CI checkout `ff3fb4ad19e790ba5193011b88a62ee840521bd7`, tree `fb07731b2ff2d96b9ad5e06159473822915bd3bd`. Run `37749547883`: 6/6 jobs, 970 passed / 0 failed / 15 ignored. READ artifact had 33 status-matched cases; separate CI-image smoke covered 6 cases and 3 SDK signature-recovery checks. Not an operational KMS signature. |
| Existing Deployment rollout | At 2026-10-08 22:38 KST, 3/3 updated/ready/available, `/ready` 200 and signer identity response. Digest `ghcr.io/fp-validated/pillar-dvn-client:ci-ff3fb4ad19e7-r37749547883-a1@sha256:4ac2cbcd560b7bc1607f7846027509d42c881aacbf557d8d882100d804e80aae`; ConfigMap checksum `985bee4a4f0dda1da8d743765536e6e95c744cbab284a792dde36c3b9fbf795c`. Existing chain/entity/quorum and 18-chain list retained; only Hyperliquid URI changed to existing Alchemy-backed `hyperliquid-pinned` alias. |
| Pin-control / signing scope | The deployed selector passed historical number/hash and missing-hash controls. Prometheus sign-budget started/success/error was 0/0/0 at 20:34:18 KST. QuickNode remains excluded from pinned READ eligibility; noncompliant-upstream failover and latest fallback are prohibited. Independent failover controls and operational MESSAGE signing belong to the separate acceptance scope below. |

PR #1 was unmerged at the 2026-10-08 rollout observation; it was subsequently merged as `4395c70` (2026-10-09). That merge fact does not change the dated deployment record. The image/ConfigMap change used the narrow existing Deployment targets, not a separate test Deployment. Rollback safety is two-stage: revert the consumer fields and wait for Target2's 3-Pod rollout before reverting the proxy alias and rolling back Target1; stop on consumer error/timeout, keep the alias, and do not use live-only rollback or whole-Application sync. No rollback, Secret/credential change or permission change was performed.

### Shared evidence limits

| Scope | Current evidence boundary |
| --- | --- |
| Source/reference coverage | 351-report count has no case ledger; original 266-depth response replay, `78bdd20e…` manifest target and A2/A4/B3 original-case mapping remain unverified. Do not mark all original findings `fixed_verified`. |
| Azure and production KMS | Solana signer bytes matched observed keys/config, but verified deployed-program/source correspondence remains open. No live KMS normal-message signature or on-chain signature verification was observed. |
| Canton / remote audit TLS | Canton live-ledger test did not run; audit TLS tests were local synthetic PostgreSQL only. |
| Operation / cleanup | Fresh chain discovery was window-bounded, not a canary. Forward cleanup was reported for owned PIDs/ports; user port 18080 and workloads were left unchanged. Raw evidence and caches/artifacts were intentionally retained, so cleanup was not zero-state. |

Detailed raw evidence, source/run inputs and operational records are retained as maintainer-local evidence under `audit/retest-250/`, `audit/review-80e0ad21-20261008/`, `audit/review-pr1-20261008/` and `audit/review-re003-20261009/`. This guide summarizes their findings.

## 14. RE-003: READ stage observation-count instrumentation, 2026-10-09

READ HTTP E2E aggregates the numeric values of Prometheus _count by stage/src_chain/dst_chain/status tuple. Each HTTP case uses a new app and metrics registry. An incorrect count/label in a matching row is a failure; only an absent tuple is zero. A negative case fails if a sign-stage observation exists, regardless of HTTP status. In artifact schema 3, sign_stage_observation_count and stage_observations are counts of stage observations, not SDK/KMS calls. Existing schema 2 evidence was not changed.

| Verification scope | Observed result | Evidence and limits |
| --- | --- | --- |
| Numeric regression | Worker run: using the actual PillarMetricsStageObserver and registry, it verified two observations of the same tuple, counts 0/1/2, and a malformed matching row. sign_stage_metric_observations_are_not_series_cardinality was 1 passed, 0 failed, 512 filtered. | Evidence for numeric red is in the worker narrative records red-phase.txt and regression-plan.txt. The raw result for malformed-row red is in a separate session receipt artifact://4530. The final green raw log is retained in the maintainer-local final directory. |
| TCP HTTP E2E | Ran 33 cases with actual POST /v2/resolve-and-sign against the final source: HTTP 200 12, 400 4, 500 17; all matched the expected status. Includes empty return and 1-bad/2-good control. | Results are stated according to the worker run record. Main checked that the exact tuple counts and scalar in the final JSON match and that negative cases have no sign series. |
| Targeted Clippy / formatting | Worker run: Rust 1.98.1 runtime test-target Clippy succeeded. Main run: cargo +1.98.1 fmt --all --check passed. | The verification covered the runtime test target and workspace formatting. |
| Independent read-only review | The reviewer reviewed the source and HTTP raw artifact read-only and accepted evidence-classification additions F1–F3. | The findings and review scope are retained in independent-review-followup.json. |

Test source crates/pillar-runtime/src/tests/read_data_http_e2e.rs SHA-256: 0680778bb17a2e7ee271a0d1493afa4b68e8f4a6badc4f780d4994c8efbea3df (source-bound time 2026-10-09 06:41:36 KST). Final raw artifact audit/review-re003-20261009/final-20261009-064136-kst/http-results.json SHA-256: ad84d144a8f69d0de2d0502635bd4cb4e44252fdcbfef5754b5c340dc65142d3.

The raw logs in the Final directory are worker tool-output transcripts that include harness lines. SHA-256: tcp-http-e2e.log 7152d8423cd9bb21439049187c71506a89eb9c11e1030e5e4cf19d0fbd9e6fb4; numeric-regression.log b4ed2da0adbe9c653c4ce46394a0f9fa01cb4a4f0b4892efbc0436ca5146a2fe; clippy.log a945bfda3e7ff7d3bd5a3a896f2579ba36aa91191d79418ab24459bd1073a170. Numeric regression ran with a test-name filter and --quiet, so individual test names were not printed. The test binary SHA-256 was not recorded at the time. The source hash is not the run binary hash or proof of independent binary reproducibility.

The top-level audit/review-re003-20261009/http-results.json and tcp-http-e2e.log are intermediate runs from before the parser fix and are not used as final results. Their SHA-256 values are 67f2de440249ba5e7aea62222cd81f5962c048dcccaf3f98a3d29197945470e9 and 4e72c75e23b4b371a6f962cc8b3f691682fa310a72e02c98663b45a7d38e0f35, respectively. The bytes are preserved.

**Change and verification scope:** Changes to READ HTTP E2E and the audit document. Numeric regression, fixture TCP HTTP, targeted Clippy, formatting, and independent source/artifact review were performed. Source-bound records and operational acceptance remain separate scopes. The status of RE-001 and the original comparison ledger follows the shared evidence boundary in §13.

Evidence: audit/review-re003-20261009/run-log.txt, final artifact and logs, Main artifact comparison and fmt check, independent-review-followup.json · 2026-10-09 06:47 KST

## 15. 2026-10-09 Client Review and 2.6.0 Release

Review of baseline commit `abe9d60` found improvement items F-1–F-7; all were addressed and released in 2.6.0. Only F-5 changed signing policy; the rest are tests and documentation. Item-by-item results are recorded in the original retest format in [retest-2.6.0.md](audit/retest-2.6.0.md).

| Item | Finding in review | Action | Verification |
| --- | --- | --- | --- |
| F-1 KMS key pinning | Each signer uses the key identity it first verified for the lifetime of the process. | Stated in SECURITY Operator responsibilities, README, and CHANGELOG that rotation takes effect after restart. | Source comparison (`aws.rs`, `azure/adapter.rs`, `gcp.rs`) |
| F-2 `l1Fee` regression test | The existing test gave both providers the same receipt in every round. | Added a test giving each provider a different receipt and a PacketSent data mismatch control. | With a mutation reverting the fingerprint to raw JSON, the new test fails with `2 distinct successful responses`, while it passes on current code. |
| F-3 acceptance ledger | Case evidence pointed to a maintainer-local path. | Linked 8 cases to committed tests and a hosted CI run using `inRepoCaseTests` in `pr1-case-evidence.json`. | Local workspace run, hosted CI run `37903096415` |
| F-4 unmapped srcEid | The upstream citation in the resolver comment did not match actual behavior. | Retained the intentional 500 policy and corrected the comment. Added HTTP tests for mapped srcEid 400 / unmapped srcEid 500. | `packet_identity_http_tests` |
| F-5 readiness error classification | An RPC failure during receipt re-query was recorded as `SourceChanged`(400). | Records it as `Missing`(500, `Transaction receipt or block not found for <tx>`). | Pre-change code returned 400 `source receipt binding changed: connection reset by peer`; after the change, it returns 500 and the full signing path has 0 sign-stage observations |
| F-6 `removed` policy | Tests were needed to lock in acceptance of omission and rejection of `null`. | Added tests accepting omission and rejecting `null`/non-bool, and marked the subsequent change in §11. | `production_vertical_signs_when_receipt_logs_omit_removed` and others |
| F-7 documentation conditions | GCP/Azure identity comparison conditions and READ revert message comparison needed to match the documentation. | Reflected them in SECURITY and CHANGELOG. | Source comparison (`gcp.rs:65-67`, `azure/client.rs:69-79`, `evm_payload_observations.rs:325-326`) |

Additional behavior was locked in with tests:
- `signingContext` in the Lambda policy payload
- For an empty `dvnAddress`, omit only `hashLookup` and retain `verifiable`
- Two URIs for one entity count as one vote in READ and Sui

| Verification | Result |
| --- | --- |
| `cargo +1.98.1 fmt --all --check` | Passed |
| `cargo +1.98.1 clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo +1.98.1 test --workspace --locked` (`b7fc3ab`, `09cec5c`) | 1004 passed, 0 failed, 15 ignored (one nested child-process run excluded) |
| `cargo +1.94.1 check --workspace --locked --all-targets` | Passed |
| Hosted CI run `37903096415` (`b7fc3ab`, main push) | 6/6 jobs passed. Workspace 1004 passed, 0 failed, 15 ignored |

Review counterexamples CE0–CE5 were run by applying the same patch to `abe9d60` and `f5868d0`. CE1 (two providers differing only in `l1Fee`) was rejected on `f5868d0` and signed on `abe9d60` with the same payload and signature as the control. Raw output is maintainer-local .review-evidence-20261009/ce-output.json (SHA-256 `c16ec43befa3f752e47471baab4e9c9dd39149dde8e13e79ce150c2ede65048d`).

### Operational Deployment, 2026-10-09

Merged `8b40220` into main as `b7fc3ab` and deployed to mainnet. The previous source tree of the production image matched `abe9d60`, so F-5 is the only operational behavior change.

| Stage | Result |
| --- | --- |
| CI image | Run `37903096415` attempt 1, checkout tree `a3231a193e7bd25fe5999d1ac80973d16e0962d7`, revision label `b7fc3ab`; refuses to start if configuration is missing. Tar SHA-256 `c17265c03979c7afebcdf945be3339cd96ae7a8e9b84f05dd46d0564b4b6ceed` |
| Registry | Published the same tar with `crane push` to `ghcr.io/fp-validated/pillar-dvn-client:ci-b7fc3ab41fec-r37903096415-a1`. Remote digest `sha256:744309ed6274dce919054969d51064578e423dd0a315cc8763f2c9016e1692d0`; remote config SHA-256 matches CI image ID `b765f410…`. |
| GitOps | Changed one image-tag line in `FP-Validated/ovh-chain-repo` `f9af3f9`. The helm render diff is also one Deployment image line. |
| Sync | Hard-refreshed aks-cluster ArgoCD `pillar-dvn-client-mainnet`, then synced only the Deployment at revision `f9af3f9`. |
| Rollout | ovh-cluster `layerzero-mainnet` Deployment revision 18, 3/3 Ready, all three pods on the new digest, 0 restarts |
| Before/after deployment comparison | Responses from `/ready`, `/version`, `/environment`, `/available-chains`, and `/signer-info` (ethereum, solana) were unchanged from before deployment. Signer identity was retained. |

Rollback procedure: revert `f9af3f9` in `ovh-chain-repo` and sync only the Deployment in the same way. The previous image `ci-21b4955b00c0-r37891292805-a1@sha256:1fd4b09f…` is in the registry.

### 2.6.0 Release, 2026-10-09

- Release commit `09cec5c`, tag `v2.6.0`, GitHub release `v2.6.0`.
- The release commit changes the workspace version and 10 workspace entries in `Cargo.lock` from 2.5.0 to 2.6.0. Executable logic and external dependencies are the same as in `b7fc3ab`. The binary does not use `CARGO_PKG_VERSION`, so the running `b7fc3ab` image is 2.6.0 code.
- Raised the minor version due to breaking changes and an HTTP status change.
- fmt, clippy `-D warnings`, workspace tests (1004 passed, 0 failed, 15 ignored), and MSRV 1.94.1 check all passed on the release commit.

Evidence: local fmt/clippy/test/MSRV runs, mutation runs, raw output for review counterexamples · 2026-10-09 17:00 KST. Operational deployment section: hosted CI logs and artifact, crane digest, ArgoCD status, rollout and pod image ID, before/after endpoint comparison · 2026-10-09 17:45 KST. 2.6.0 release section: local fmt/clippy/test/MSRV runs on the release commit · 2026-10-09 18:00 KST

## 16. 2026-10-09 Full Review

Reviewed all code and documentation in rounds, based on documentation commit `548c691` for 2.6.0. In each round, independent reviewers for each area performed static review and comparison against the local copy of upstream 1.2.66. Code changes were checked with regression tests, the relevant crate's test suite, or CI check scripts; regression tests and suite output are in maintainer-local `.full-review-20261009/evidence/`. Each subsequent round re-reviewed changes from the preceding round and the surrounding code. Round 7 found no code items; after checking one documentation sentence found in that round against the code and correcting it, the review ended.

| Round (review target) | Area | Findings | Fix commits |
| --- | --- | --- | --- |
| 1 (`548c691`) | EVM readiness | JSON-RPC `error` from receipt re-query ends as 400, failed reads count as `Missing` votes and prevent `Sufficient`, `polygon`/`tron` confirmation wording, MPT block-query format and requests without source evidence, reference hash for TON readiness | `7a2c33f` |
| 1 | READ and payload | `ReadV1002` calls `getUlnConfig`, which ReadLib1002 does not provide; READ readiness requires exact latest-block agreement across providers; timestamp marker's `blockConfirmation`; READ response `payload` format; extra-context `onChainEvent` value; comparison of resolved ULN version | `07fb5ed`, `937a3a6` |
| 1 | Non-EVM | Sui event paging (`last: 50`), Sui digest comparison, Stellar result fingerprint, IOTA event ordering and paging, Stellar ScVal size and depth, TON BoC cell-count preallocation, ULNv2 refresh range calculation | `93853af`, `759f10a` |
| 1 | Configuration, CI, image | Undefined strategy category, strategy key that does not match provider, single-entity strategy for refresh, entity label in startup report, mainnet non-HTTPS URI warning, empty environment-variable value, converter default strategy, generated table digest, CI container job order and provenance, image `curl`, documentation/code mismatch | `45af150`, `6ab8872`, `4e7711a`, `cd82438` |
| 1 | Signer and audit | Durable audit quota, `/ready` audit probe, mnemonic seed re-derivation, zeroization of intermediate values, token-list copy | `5763ada` |
| 2 (`b04a0d9`) | Readiness | Provider failures in non-EVM families counted as `Missing` votes | `469f12d`, `b27333e` |
| 2 | Non-EVM | Stellar ScVal variant 19 and 20 lengths, Stellar `G…`/`C…` `dvnAddress`, Solana `options` format, Sui cursor, chain names for which IOTA paging applies, Sui/IOTA cumulative response limits, IOTA transaction digest comparison | `f656cfb`, `af2eaef`, `2ddecd8` |
| 2 | TON | BoC parsing and message cell split size | `cd8b10a` |
| 2 | Configuration, signer, CLI | Chain assignment for a mnemonic wallet with a different chain type, Secrets Manager default region, response termination at connection lifetime, backoff after accept error, remote configuration load timeout, single-entity warning and gauge update conditions, lazy seed creation and token comparison, heartbeat metric HELP, image version for tag build | `99f22de`, `f5ab404` |
| 2 | READ and audit | READ signing compatibility (including empty resolved payload), audit capacity flag, round 1 per-packet quota could block a packet due to `srcTxHash` notation variants and a 64-attempt limit | `5258287`, `86046cd`, `2ddecd8`, `810692b` |
| 3 (`8c43be0`) | Readiness | Preserve admission error on zero-voter quorum, malformed 200 responses from Move/Starknet/Stellar, Solana `null` response | `4779729`, `d39168c`, `c947674`, `e33af25` |
| 3 | TON and Solana | Exotic cell and level mask, panic in root hash/depth calculation, cell-count limit, first ref-chain read, propagate Solana `options` decode error, `vec-c` source attribution | `c73a93f`, `eed8be4` |
| 3 | Signer, configuration, CLI | BIP-39 checks for both seed types, chain with no assigned wallet, IO limit including header time, Secrets Manager region ordering | `f6bbf6b` |
| 3 | Documentation | README, SECURITY, AUDIT behavior descriptions | `754de71`, `06f80f1` |
| 4 (`06f80f1`) | TON | BoC validation traversal expands shared cells into a tree and does not return for a small DAG BoC (40 cells, 247 bytes), single 4,096-cell limit rejects UlnConnection storage with many `hashLookups`, reject exotic cells in trace body | `0589720` |
| 4 | Readiness and configuration | Malformed block response on Aptos ledger-version path, warning for provider URI `http://[::1]` | `91337ea` |
| 4 | Documentation | 400 for EVM `null` receipt, Solana `options` scope, strategy-key warning timing, quorum vote error log, READ error wording | `9411227` |
| 4 | Documentation | Added this section (§16) and references to §11 and CHANGELOG | `b87be2b` |
| 5 (`b87be2b`) | TON | Dropping a deep linear chain BoC (depth 65,534) below the 65,536-cell limit overflows the 2 MiB worker stack; hash-based visited set lets an exotic cell under a level-mask-spoofing parent pass validation; serialization of a large provider-generated default receive config (65,013 cells, depth 1,012) takes 24.7 seconds in test profile | `a052fa0`, `a0ad592` |
| 5 | Readiness | `version` for which no block request can be formed on Aptos tx-hash path counted as a `Missing` vote | `a5af7ad` |
| 6 (`7731afd`) | TON | Depth precheck does not skip hash and depth bytes of hash-storing cells (descriptor bit 4), rejecting BoCs in that format | `ae88839` |
| 6 | Documentation | Non-EVM readiness malformed-format scope, Aptos `null` response description, mainnet Uln storage fixture source, measured workload description | `b7ecb00` |
| 7 (`b7ecb00`) | All | No code items. One sentence in this section describing Aptos `null` transaction | Commit that completed this section |

Decisions made during the rounds:
- Durable audit quota is documented per-attempt behavior. Retries of the same packet also consume quota, so SECURITY advises configuring authentication or an edge rate limit on the signing route when audit is enabled.
- Solana `dvnAddress` accepts base58 only. Upstream rejects hex with `new PublicKey` in payload-signed validation, so round 1's acceptance of hex was reverted in round 2.
- Kept the Starknet receipt fingerprint projection. There was no evidence that providers returned different values for compared receipt fields.
- TON message cell splitting follows the 1016-bit split in upstream 1.2.66 `common-ton/src/cells.ts`. `vec-c` in `ton_dvn_verify.json` is calculated by this repository's builder.
- TON BoC cell limits use mainnet config param 43 (read via toncenter `getConfigParam`). Account storage is limited to `max_acc_state_cells` 65,536; messages and trace bodies to `max_msg_cells` 8,192. Measured mainnet storage is 15 cells for UlnConnection, 532 for Uln, and 1,223 for UlnManager; the connection storage fixture with 600 attestation nonces also reads within this limit. Peak RSS of the test process parsing a BoC filled to the limit with cells without refs or data is 60,850,176 bytes for 65,536 account cells and 11,403,264 bytes for 8,192 message cells.
- TON BoC depth limit is the TON node cell-structure limit, `CellTraits::max_depth` (1,024, `ton-blockchain/ton` `crypto/vm/cells/CellTraits.h`). Config param 43's `max_vm_data_depth` (512) is a separate, narrower on-chain limit. The parser calculates depth from the raw BoC reference graph and rejects it before creating cell objects; this calculation, like `ton_core`, skips hashes and depth bytes stored in cells. Exotic validation runs on each popped cell, and child refs are expanded once per cell node identity. The visited key is node identity, not the representation hash a provider can manipulate.
- Default receive config serialization is limited to 2,048 unique cells. Config for mainnet Uln storage (532 cells) uses 2 cells; the testnet fixture config uses 3. Below the depth limit, the maximum size for two required/optional DVN chains is 2,047 cells. Serialization of a max-size config took 24 ms in release build. Mainnet fixture `ton_mainnet_uln_storage.b64` is the `data` from toncenter `getAddressInformation` response for Uln `EQAXRMTd2d1IW72G7U71RuGNiP2M2NfQp5U69W667far3CYo`, read at masterchain seqno 97941002 on 2026-10-09 23:06 KST.
- In non-EVM readiness, 200 responses with missing or malformed fields are excluded as provider failures. Upstream Aptos `aptosBlockHeightQuorumFn` puts a `null` block and a block missing `block_height` in the same bucket. Pillar counts a `null` block on the Aptos ledger-version path and a `null` transaction on Initia as `Missing` votes; it treats a `null` transaction on the Aptos and Movement tx-hash paths and a `null` block after a transaction as provider failures.

The behavior in the §15 F-5 row changed in this review. An RPC failure during readiness receipt re-query is excluded from voting, rather than counted as a `Missing` vote (`7a2c33f`, `4779729`). When no EVM provider succeeds, the response is the same 500 `Transaction receipt or block not found for <tx>` as in F-5.

Verification results for final code commit `b7ecb00`:

| Verification | Result |
| --- | --- |
| `cargo +1.98.1 fmt --all --check` | Passed |
| `cargo +1.98.1 clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo +1.98.1 test --workspace --locked` | 1079 passed, 0 failed, 15 ignored |
| `cargo +1.98.1 test -p pillar-runtime --locked postgres_audit -- --ignored --test-threads=1` (local PostgreSQL) | 11 passed, 0 failed |
| `node scripts/check-generated-config-integrity.mjs` | Passed |
| `cargo +1.94.1 check --workspace --locked --all-targets` | Passed |
| Run after `docker build` without configuration | Refused to start with `Missing required environment variable PILLAR_API_AUTH_TOKENS` |
| Run image (`LOCAL_MNEMONIC`, two BSC testnet providers, quorum 2) | Docker health `healthy`, `pillar healthcheck` exit 0, `/ready` 200, `/provider-health` `{"bsc":true}`, `pillar_provider_single_entity_chains 0`, unauthenticated `/signer-info` 401, no `curl` in image, uid 10001 |
| Hosted CI run `37946961465` (`ccf4c01`, main push) | 6/6 jobs passed. Workspace 1079 passed, 0 failed, 15 ignored |

### 2.6.1 Release, 2026-10-10

- This section's changes were released as 2.6.1. Tag is `v2.6.1`; GitHub release is `v2.6.1`.
- The release commit changes the workspace version and 10 workspace entries in `Cargo.lock` from 2.6.0 to 2.6.1, and names the CHANGELOG section 2.6.1. Executable logic and external dependencies are the same as in `b7ecb00`.
- When upgrading from 2.6.0, first apply the `Upgrade / Breaking` and `Operator action` sections for 2.6.1 in CHANGELOG.
- fmt, clippy `-D warnings`, workspace tests (1079 passed, 0 failed, 15 ignored), and MSRV 1.94.1 check all passed on the release tree.
- The mainnet image at release time is 2.6.0 code (`b7fc3ab`).

Evidence: fmt/clippy/test/PostgreSQL/integrity/MSRV output and image run records in `.full-review-20261009/evidence/round6-integration`, round-by-round reviewer reports and red/green output · 2026-10-09 23:48 KST. Hosted CI row: result for run `37946961465` · 2026-10-10 00:08 KST. 2.6.1 release section: local fmt/clippy/test/MSRV runs on the release tree · 2026-10-10 00:24 KST
