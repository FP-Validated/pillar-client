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
| GitOps | Changed one image-tag line in private GitOps commit `f9af3f9`. The helm render diff is also one Deployment image line. |
| Sync | Synced only the Deployment at revision `f9af3f9`. |
| Rollout | Deployment revision 18, 3/3 Ready, all three pods on the new digest, 0 restarts |
| Before/after deployment comparison | Responses from `/ready`, `/version`, `/environment`, `/available-chains`, and `/signer-info` (ethereum, solana) were unchanged from before deployment. Signer identity was retained. |

Rollback procedure: revert `f9af3f9` in the GitOps repository and sync only the Deployment in the same way. The previous image `ci-21b4955b00c0-r37891292805-a1@sha256:1fd4b09f…` is in the registry.

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
- TON BoC depth limit is the TON node cell-structure limit, `CellTraits::max_depth` (1,024, `ton-blockchain/ton` `crypto/vm/cells/CellTraits.h`). Config param 43's `max_vm_data_depth` (512) is a separate, narrower on-chain limit. The parser calculates the depth of every declared cell, reachable from the root or not, from the raw BoC reference graph and rejects the BoC before creating cell objects (§21, H-01); this calculation, like `ton_core`, skips hashes and depth bytes stored in cells. Exotic validation runs on each popped cell, and child refs are expanded once per cell node identity. The visited key is node identity, not the representation hash a provider can manipulate.
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

### 2.6.2 Hotfix Release, 2026-10-10

- 2.6.2 is a hotfix on 2.6.1. Tag is `v2.6.2`; GitHub release is `v2.6.2`.
- The only behavior change is `cbd1fa2`: Sui GraphQL and IotaL1 event pagination check every page for provider errors, so an error on an earlier page removes that provider's vote even when the last page is clean.
- Regression tests `sui_errors_on_an_earlier_event_page_lose_the_vote` and `iota_error_on_an_earlier_event_page_loses_the_vote` place the packet on page 2 and the error on page 1. Both fail on 2.6.1 code and pass on 2.6.2.
- No configuration or HTTP contract changes; upgrading from 2.6.1 needs no operator action.

Evidence: fmt/clippy/test/PostgreSQL/integrity/MSRV output and image run records in `.full-review-20261009/evidence/round6-integration`, round-by-round reviewer reports and red/green output · 2026-10-09 23:48 KST. Hosted CI row: result for run `37946961465` · 2026-10-10 00:08 KST. 2.6.1 release section: local fmt/clippy/test/MSRV runs on the release tree · 2026-10-10 00:24 KST. 2.6.2 section: `.full-review-20261009/evidence/sui-page-errors/{red-final,green-final,ws-tests}.txt` and hosted CI run `37956704504` · 2026-10-10 01:17 KST

## 17. Round 1 remediation — 2026-10-20

Baseline: `2f9305f0bd1644769169b50941ff5b72bab4be26`. One commit per finding,
`f30bb38`..`5a593e1`, then documentation `0cec86c`, on `main`; not a tagged release
or a production rollout. The per-finding response, with commit links and the
rationale wherever a recommendation was not followed, is
[round1-response.md](audit/round1-response.md). M-08 corrects the report's principal
interpretation rather than applying its proposed field substitution.

| ID | Implementation | Exercised evidence |
| --- | --- | --- |
| M-01 | Pre-allocation JSON cost limits (131,072 structural units; 524,288 for TON), one shared 131,072-unit budget for Sui/IotaL1 event pages kept across pagination, bounded ingress admission, estimated retained-candidate pool, streaming fingerprints and one representative per fingerprint; embedded Initia JSON and Canton OAuth use the same parse-cost checks | Real Reqwest broad-object response rejection, a 512-transaction TON trace resolving over loopback HTTP, IOTA and Sui pagination stopping at the third of 21 loopback pages, quota release/cancellation, cross-target parser E2E and negative control; standalone Initia resolver RSS comparison |
| M-02 | Checked Move timestamp/calendar arithmetic and TON head/seqno ranges | `source_events_move` overflow/calendar cases and `round1_ton_confirmation_arithmetic_rejects_negative_head_and_clamps_behind_head` |
| M-03 | Bounded numeric/signature input, linear decimal parsing, committee verification before expensive shape parsing, streaming canonical Keccak input | Canton boundary cases and the upstream sequencer transcript replay |
| M-04 | Trusted Solana program filter before data copying/Base58 decoding | Recorded packet plus synthetic one-million-character unrelated instruction; bounded child process still resolves nonce 3826 |
| M-05 | Bidirectional READ/version gate, 257-marker cap, exact command binding and deduplication | Both protocol mismatches and excess markers before source resolution; conflicting/extra/invalid markers before validation RPC; real CLI returns 400 with zero receipt RPCs |
| M-06 | Shared semantic Solana projection, with a trusted-program filter for source resolution and strict consumed-field checks | Original snapshot fails with two distinct successful fingerprints; fixed resolver agrees across two entities with different fees/logs/compute/index metadata |
| M-07 | Starknet evidence captures receipt/block/selected event and readiness rechecks canonical identity and status | Stable L2-to-L1 progression accepted; reorg, changed event, event placement and reverted execution refused; malformed observations remain non-votes |
| M-08 | Existing trace-root destination principal retained; address parsing and lookup-trace binding fail closed | Recorded wallet root and nested PacketSent remain valid; malformed principal or a trace for another transaction never reaches the policy |
| L-01 | Normalized 32-byte TON transaction hash included for every node, including null-message nodes; key/hash agreement and duplicate-alias checks; hex only for exactly 64 hex digits | Hash mutation, malformed hash, mismatched map key, nested request identity, hex/base64/base64url cases and base64 hashes beginning with `0x`/`0X`; resolved hashes logged with debug escaping |
| L-02 | Effective receive version reaches Aptos V301 payload-signed validation; source `V2` remains unchanged | Public signing path: unsigned V301 state returns 200 with one signer call; already-signed state returns 400 with zero signer calls |
| L-03 | Non-null `walletRestrictions` rejected in env/file loading and runtime conversion | `{}` and nonempty values refused, omitted/null configurations accepted; actual CLI with restrictions exits before listening |

### Verification and provenance

| Check | Observed result |
| --- | --- |
| `cargo +1.98.1 fmt --all --check` | Passed |
| `cargo +1.98.1 clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo +1.98.1 test --workspace --locked` | 1,118 passed, zero failed, 15 ignored at `5a593e1` (`test result:` totals, including three child harness runs); every intermediate commit was also formatted and passed clippy and the workspace suite |
| `cargo +1.94.1 check --workspace --all-targets --locked` | Passed |
| Actual `pillar` process with synthetic local mnemonic and loopback RPC | `GET /` 200 `HEALTHY`; both READ/version mismatches and 258 markers return 400 envelopes before any `eth_getTransactionReceipt`; graceful process exit and mock listener closure observed |
| Parser admission negative control | Temporarily bypassing fair parser admission makes target B time out while A occupies the four shared slots; E2E fails. Exact source restored, E2E/fmt/clippy pass again |
| Standalone Initia resolver, 1,500,304-byte outer response / 150,000 embedded objects | Maximum RSS before: 129,073,152 bytes; after: 21,381,120 bytes. Normal recorded packet resolves in both runs |
| Independent read-only reviews | Source/core and resource reviewers rechecked their findings; no blocking issue remained |

The RSS result is one macOS `/usr/bin/time -l` run per variant, not an OOM stress
test or a process-wide bound. Before-run metadata mistakenly counted escaping
inside `attribute_data_json_bytes`; its original output is retained. The decoded
inner JSON is 1,200,001 bytes, and the comparison artifact records that correction.
The Solana cost input is synthetic, not an on-chain attack transaction. No live
RPC/KMS, container image, cluster, PostgreSQL audit integration or production
capacity test was run for this task. The fifteen opt-in tests remain ignored.
The macOS test linker emitted the pre-existing compact-unwind `__eh_frame` size
warning; clippy's Rust diagnostics passed with warnings denied.

Raw evidence and reproducible sources are retained under
`local/reports/round1-remediation-20261020/` (gitignored), including
`workspace-tests-final-receipt.json`, `msrv-final-receipt.json`,
`clippy-restored.log`, `fmt-check-final.log`, `cli-smoke-final.json`,
`nested-json-comparison.json`, original-snapshot failures and per-run E2E JSON.
The directory also preserves the negative-control output, not only green runs.
The change was then split into one commit per finding and pushed to `main`; no
image was published and nothing was deployed.

### Remaining operating constraints

`SECURITY.md` defines the new cost limits and their compatibility tradeoffs.
The 64 MiB candidate pool is estimated, not a hard RSS ceiling; typed READ data,
consumer-owned values and SDK buffers are outside it. Several slow targets can
exhaust the shared slots, Lambda admission is three active plus two waiting per
target, and background probes can be deferred. Memory pressure can refuse an
additional agreeing vote if growing its lowest-index representative reservation
would exceed the pool. Starknet `PRE_CONFIRMED` is refused; selected event JSON
must still match exactly.

## 18. Round 2 remediation — 2026-10-21

The report's baseline is `3f39fbad972794e5a9c598ea46a310334a4a4415` (2.6.2). The work
branches from `7736ecb`, the Round 1 remediation. It lands as a dependency update
`677d676`, then one commit per finding, `4cbef24`..`d256797`, then documentation. The
per-finding response, with commit links and the rationale wherever a recommendation
was not followed, is [round2-response.md](audit/round2-response.md). The report's
M-08 is a Canton provider-health finding, distinct from Round 1 M-08 (TON).

| ID | Implementation | Exercised evidence |
| --- | --- | --- |
| M-11 | URL redaction in one linear pass; each redacted string in the health report is cut to 64 KiB afterwards | A 4 MiB `eth_chainId` answer of URL tokens over local HTTP takes 0.36 s and leaks no credential; with the fix reverted the same test runs 1,150 s |
| M-09 | Command, request and compute codec version must be 1; malformed READ commands are 400 | The pinned official vector, with only a version byte changed, is refused; over HTTP the answer is 400 after the source receipt alone, with no READ-target RPC and no sign stage |
| M-10 | Initia LegacyView `data` is read as upstream reads it (non-array → one element); Aptos `/view` still requires an array | Recorded Initia mainnet answers sign through the HTTP route; verified state and met confirmations are refused with no signature |
| M-08 (Canton) | `GET /v2/state/ledger-end` probe with the ledger's own OAuth2 token and rank key; failures stay per entry | Production composition: a working ledger makes a Canton-only roster ready and its sender read succeed; 503, 401, non-numeric offset and missing OAuth fail closed; a roster test, derived from the static table, holds every non-EVM chain to a probe of its own |

### Verification and provenance

| Check | Observed result |
| --- | --- |
| `cargo +1.98.1 fmt --all --check` | Passed |
| `cargo +1.98.1 clippy --workspace --all-targets --locked -- -D warnings` | Passed, on every commit |
| `cargo +1.98.1 test --workspace --locked` | 1,125 passed, zero failed, 15 ignored (`test result:` totals) |
| `cargo +1.94.1 check --workspace --all-targets --locked` | Passed |
| `cargo audit`, `cargo deny check` | Passed after `677d676` |
| Fix-reverted runs | Each finding's new tests fail with only its fix reverted (M-08: the `CANTON` dispatch arm removed) |

The intermediate commits were checked with fmt and clippy only; the workspace suite and
the E2E tests ran once, on the final tree, at the operator's request. Raw output, E2E
artifacts and fix-reverted logs are under
`local/reports/round2-remediation-20261021/` (gitignored). No live Canton ledger was
used. The Initia responses are recorded, not live, in the tests.

### 2.7.0 Release, 2026-10-21

- Release 2.7.0 contains the Round 1 remediation (`f30bb38`..`7736ecb`), the
  dependency update `677d676`, and the Round 2 remediation (`4cbef24`..`f7a84ad`).
  The tag is `v2.7.0`, and the GitHub release is `v2.7.0`.
- The release commit changes the workspace version from 2.6.2 to 2.7.0, along with
  the 10 workspace entries in `Cargo.lock`, and names the CHANGELOG section 2.7.0.
  Executable logic and external dependencies are the same as in `f7a84ad`.
- Upgrade from 2.6.x as the CHANGELOG "Upgrade / Breaking" section describes. A
  wallet with a non-null `walletRestrictions` now fails startup, and malformed READ
  commands answer 400 instead of 500.

## 19. Round 2 follow-up — 2026-10-21

Baseline: release `v2.7.0`, source `637921ac0891d15df68dec320e4d9a3a70eb70f7`.
Executing that published image with a public test mnemonic exposed credentials
in punctuated/uppercase URLs and accepted the zero-request READ command
`0x000100010000` with a signature. The initial Round 2 closure language did not
cover those boundaries. This follow-up is version 2.7.1.

| Area | Follow-up | Exercised evidence |
| --- | --- | --- |
| M-11 | Case-insensitive linear HTTP(S) scanning, complete userinfo boundaries, redact-before-truncate; URL-keyed objects become one bounded diagnostic string without map collisions | Real HTTP 4 MiB response, punctuation/case/UTF-8 boundaries, direct/nested/uppercase URL keys and an observation marker; the URL-key regression fails before the fix |
| M-09 | Zero requests and compute-only commands are refused, in addition to all three version guards | Valid V1 signs; invalid versions, a later invalid request, zero requests and compute-only inputs return 400 after only the source receipt, without READ-target RPC or a sign stage |
| M-08 | One Canton auth instance/cache, configured from the same environment map, serves health and sender lookup | Actual TCP signing route through production runtime assembly, quorum-2 sequencer verification, nonzero confirmations, ledger sender, policy and local signer; one startup token yields one signature; startup 401 and sender-time 401 fail closed |
| M-10 | Per-view Initia arity and consumer type checks; full Move ULN-config layout and exact length | Registered Initia receiver exchanges 006/007 return `[ULN302, false]` and a complete 78-byte config; valid scalar flow signs, verified/confirmed payloads and malformed views do not; independent BCS arguments and two-provider agreement are checked |

### Verification checkpoint

| Check | Observed result |
| --- | --- |
| Rust 1.98.1 workspace suite | 1,133 passed, zero failed, 15 ignored, summing `test result:` rows including three child harnesses |
| Final review-only test strengthening | Aptos two-provider positive/refusal controls passed separately after the workspace run; no executable product code changed |
| `cargo +1.98.1 clippy --workspace --all-targets --locked -- -D warnings` | Passed after final review |
| `cargo +1.98.1 fmt --all --check` | Passed |
| `RUSTFLAGS="-D warnings" cargo +1.94.1 check --workspace --all-targets --locked` | Passed |
| Controlled regressions | Separate Canton caches turn the successful-signing test into HTTP 500; prefix-only Move config decoding turns the malformed-config refusal into HTTP 200; URL keys expose dummy credentials before the key fix |
| Restoration | Both temporarily changed product files have the exact SHA-256 they had before the controlled regressions |
| Independent read-only review | Input/redaction and runtime-contract reviews closed their findings; reviewers did not claim to run the tests |

The local macOS debug test linker still emits the previously recorded
compact-unwind size warning. Rust/clippy diagnostics and the MSRV check pass with
warnings denied. The fifteen external-input tests remain ignored.

Raw results, failed attempts, successful E2E artifacts, review receipts and
negative controls are retained in
`local/reports/round2-completion-20261021/`. The earlier published-image
counterexamples are in `local/reports/round2-adversarial-review-20261021/`.
`scripts/generate-canton-http-confirmations.mjs` reproduces the synthetic,
clock-adjusted sequencer transcript
`crates/pillar-runtime/tests/synthetic/canton_http_confirmations.json` byte for byte.
It uses the existing public test seeds and signing contract, and it checks
signature parity against upstream's `canton_sequencer.json`. The transcript sits
outside `tests/gasolina_parity/` because it is not upstream output.

The Canton transcript is not a live ledger observation. Initia exchanges 003/004
use synthetic packet inputs, and the state-2/confirmation-15 refusals are controlled
cases, not a recorded delivered packet. No synthetic production-KMS signing
request was generated. Local source checks do not establish a published image or
a production rollout; those require separate provenance and operational receipts.

### Published image and mainnet rollout

- Source `811178d3a9f39be2654e622bd98dd5bf134cfb81` is tagged `v2.7.1`.
  Main CI [39541443681](https://github.com/FP-Validated/pillar-client/actions/runs/39541443681)
  and tag CI [39541443922](https://github.com/FP-Validated/pillar-client/actions/runs/39541443922)
  each passed all six jobs, including supply-chain, container and macOS TON checks.
- The attested tag-build tar was pushed without rebuilding. Its SHA-256 is
  `af41ec1ac2363b0d3f8fb3796b0c342c505c71b2dc8b355a1251a24b3ec25ca0`.
  The original tar, checksum, Sigstore bundle and byte-exact original CI diagnostics
  archive are attached to the [release](https://github.com/FP-Validated/pillar-client/releases/tag/v2.7.1).
  GitHub's uploaded tar digest and size match the verified CI artifact.
- Published image:
  `ghcr.io/fp-validated/pillar-dvn-client:ci-811178d3a9f3-r39541443922-a1@sha256:d4733afe62e39a73c8eb2e01d2a08ced1f0770e036ae80ce6a6fc79931b7a86c`.
  The remote config SHA-256 equals CI image ID
  `65e54190fc5bcfc509a8bd30ac201a4925f805be0f8e5276e93fa8682696212b`;
  revision, `v2.7.1` label and `linux/amd64` platform match.
- The actual published digest signed the valid V1 control and refused five invalid
  READ cases with HTTP 400, no READ-target RPC and no signature. Source-receipt
  lookup still occurs; this is not a claim of zero total RPC calls.
  A 4,194,276-byte hostile wire response completed its report request in 0.129 s
  in this run. Punctuated/uppercase URL and nested URL-key credentials were absent
  from the report and captured container logs. This is one smoke observation,
  not a latency guarantee or load test.
- Before the rollout, an isolated, non-serving instance of the exact digest started
  with the production signer configuration and reached Ready with zero restarts.
  It was removed after the check. No signing request was sent to it.
- Private GitOps commit `ef46438` changes only the image tag, `PILLAR_IMAGE_VERSION`
  and the config-revision annotation. Only the Deployment was synced, without
  pruning. The rolling update completed with all three Pods Ready on the new digest
  and zero restarts.
- Post-rollout GETs to `/`, `/ready`, `/version`, `/provider-health` and
  `/signer-info?chainName=ethereum` returned 200. Version is `v2.7.1`; the Ethereum
  address and public key exactly match the pre-rollout observation:
  `0x06bb41FE76F41429f55aC8C355ac8669769A1ba1`.
  The captured new-pod logs contain no ERROR-level lines.
- One signing request, sent on 2026-10-21 to one production Pod over a Pod-level
  port-forward, exercised the live KMS path on this digest. The packet was a real
  Ethereum→BSC `V302` packet (`0xf0940f45…f30cf30c`, nonce 1435). It was finalized
  and still `Verifying`, and this DVN is not in its receiver's ULN config. The
  answer was HTTP 200 with one signature. It recovers to
  `0x06bb41FE76F41429f55aC8C355ac8669769A1ba1` over a digest rebuilt independently
  from chain data: vId 102, `ReceiveUln302`, 15 confirmations, EIP-191. All four
  sign stages recorded `ok`. Because this DVN is not configured for that receiver,
  the attestation cannot count toward the packet's verification. Signature bytes
  were not retained. A delivered Ethereum→Base packet sent first was refused with
  `Payload already signed` before the sign stage.
- No configuration other than the image changed.
- Rollback is a narrow revert of `ef46438` followed by the same Deployment-only
  sync. The prior image digest is
  `sha256:744309ed6274dce919054969d51064578e423dd0a315cc8763f2c9016e1692d0`.
  Operational receipts and original logs remain in the completion evidence directory.

## 20. Round 3 remediation — 2026-10-22

The report's baseline is `3f39fbad972794e5a9c598ea46a310334a4a4415` (2.6.2); all four
findings were still present on `main` at `201430d`. The work branches from `201430d`
with one commit per finding, `12c2d87`..`76eb188`, then `dd02252` for the same class as
M-12 outside the reported findings, then documentation. It is not
released. The per-finding response, including why M-14 reuses the existing refresh
rather than adding a coordinator, is [round3-response.md](audit/round3-response.md).

| ID | Implementation | Exercised evidence |
| --- | --- | --- |
| M-12 | Aptos-family transaction and block reads agree on, and keep, only the consumed fields; Initia event attributes keep only `key` and `value`, dropping the node-local `index` flag | Two providers at quorum 2 on different node releases or indexer settings resolve the archived V301 send and a ULNv2 send; two Initia providers with different `index-events` agree on the source event and the sender; a different event, attribute value, `success`, `version` or `hash` still refuses |
| M-13 | TON readiness, timestamps and extra context plan, count and dial only `v3-endpoint` providers; too few v3 entities fail before RPC | v2-only providers ranked first add no delay and are never dialled; one v3 provider, or two v3 URIs of one entity, are refused with zero RPC |
| M-14 | `/provider-health/report` returns the retained report of the health round; the newest round wins; the health cache never probes inside a caller, so abandoning a request cannot cancel a round | Five abandoned requests within the TTL probe nothing, past it share one round that is then served; three abandoned reads with an empty cache or a new generation cause one round; an older round cannot overwrite a newer one; a pinned `/ready` still probes its own generation |
| L-04 | Indexer and TronWeb probe entries are `diagnostic` and outside chain health; an Initia indexer admission refusal no longer fails the round | Aptos and Tron stay healthy with the auxiliary endpoint at 503; an Aptos-only roster stays `Ready`; a primary outage still fails |
| Same class as M-12 | The EVM ULNv2 refresh's `eth_getLogs`, Starknet source receipts and IOTA source events agree on the fields the resolver reads; Starknet agrees on acceptance rather than on L1 versus L2 | Two providers at quorum 2 refresh a reorged ULNv2 send with log `blockTimestamp` `0x0`, absent or real (as `arb1.arbitrum.io` and other Arbitrum providers answer on mainnet); resolve a Starknet send with one receipt `ACCEPTED_ON_L1` in another spec shape; resolve an IOTA send across `bcs` encodings; a different log `data`/`logIndex`/`blockHash`, execution status, non-accepted finality, event, `type` or `parsedJson` still refuses |

### Verification

| Check | Observed result |
| --- | --- |
| `cargo +1.98.1 fmt --all --check` | Passed |
| `cargo +1.98.1 clippy --workspace --all-targets --locked -- -D warnings` | Passed, on each of the four commits |
| `cargo +1.98.1 test --workspace --locked` | 1,157 passed, zero failed, 15 ignored (`test result:` totals) on the final tree |
| `RUSTFLAGS="-D warnings" cargo +1.94.1 check --workspace --all-targets --locked` | Passed |
| `round3_` tests per commit | 3, 10, 12 and 17 passed at the four commits; the two Initia M-12 tests from the re-review add 2 on the final tree |
| Fix-reverted runs | Each finding's new tests fail with only its production change restored to the parent; the tests that must hold either way still pass. Restoring the inline cache refresh, removing the M-14 ordering guard, dropping the pin carry or removing the Initia attribute normalization each fails its test |

The first regression tests were written before the fixes and failed on `201430d`; the
ones added later fail with their fix reverted. Implementation was delegated per finding;
every line was reviewed and partly rewritten before commit.
An independent read-only review then found three defects, fixed in the same commits:
the cache still probed inside a caller whenever a REMOTE configuration refresh bumped the
generation (every 60 s), the Initia indexer probe could fail the whole round on
admission, and moving the refresh to a task dropped the `/ready` generation pin, which
the existing readiness test caught. The tests drive handler and cache futures, not a TCP
socket; hyper's disconnect behaviour was confirmed from its 1.10.1 source. A later
re-review found that Initia event attributes still split the quorum on the node-local
`index` flag, in the source read and in the sender read; the attribute normalization in
the M-12 row fixes both. A review of every other whole-answer quorum read then measured
the same divergence live on Arbitrum `eth_getLogs`; that row and Starknet and IOTA were
changed alike. Sui already compared only `type` and `parsedJson`. Aptos account
resources and table items still compare their small whole answers. TON v3 dispatch ranked
by the v2 probe until §22. No image was built and nothing was deployed.

## 21. H-01, M-15 and M-16 remediation — 2026-10-22

The report's baseline is `3f39fbad972794e5a9c598ea46a310334a4a4415` (2.6.2). H-01 and
M-16 were still present at `201430d` and on the Round 3 branch; M-15 was already fixed
by `677d676`, released in 2.7.0 and 2.7.1. The work branches from `fc8d9e9`, the Round
3 remediation, with `de722d6` (H-01), `7a1a226` (M-16), then documentation. It is not
released. The TON BOC ingress stages, the measurements and the upstream difference are
in [h01-m15-m16-response.md](audit/h01-m15-m16-response.md).

| ID | Implementation | Exercised evidence |
| --- | --- | --- |
| H-01 | Every declared cell of a provider's BOC, reachable or not, is at most 1,024 deep before any cell is built | One of three providers at quorum 2 returns an unreachable chain filling the message (trace) or account (storage) cell limit; on a 2 MiB tokio worker the two honest providers resolve and sign-validate as without it. Before the fix the child process aborted with a stack overflow |
| M-15 | Already fixed: `rustls` 0.23.46, `rustls-webpki` 0.103.16, `webpki-roots`/`webpki-root-certs` 1.0.10 | `cargo audit` and `cargo deny check` clean; `rustls-webpki` refuses the eight eMudhra intermediate keys whatever store the anchor came from |
| M-16 | `ton_core` 0.3.7: one stored pruned-branch hash per set level-mask bit, node-equivalent cell verification, CRC32C and exact length on every BOC, deferred deep drops; Pillar's own trace-body CRC check is removed | All seven pruned-branch masks parse, six to pytoniq-core's hashes; two providers resolve the recorded TON send with a level-0 Merkle-proof body holding a mask-`0b010` pruned branch. Upstream `@ton/core` 0.63.1 refuses that body, so Pillar now attests traces the upstream DVN cannot |

### Verification

| Check | Observed result |
| --- | --- |
| `cargo +1.98.1 fmt --all --check` | Passed, on both commits |
| `cargo +1.98.1 clippy --workspace --all-targets --locked -- -D warnings` | Passed, on both commits |
| `cargo +1.98.1 test --workspace --locked` | 1,159 passed at `de722d6` and 1,164 at `7a1a226`, zero failed, 15 ignored (`test result:` totals; child processes' own summaries are captured, not counted) |
| `RUSTFLAGS="-D warnings" cargo +1.94.1 check --workspace --all-targets --locked` | Passed, on both commits |
| `cargo test --release` for the new H-01 and M-16 tests | Passed |
| `cargo audit`, `cargo deny check` | Passed; the second `darling` is a duplicate warning, as `deny.toml` configures |
| Fix-reverted runs | With `Some(depths[root])` restored, the four H-01 tests fail, three by SIGABRT in their child; on `ton_core` 0.1.3 the two `pillar-layerzero` M-16 tests fail with `failed to fill whole buffer` and the runtime M-16 test with no trace quorum |

The DVN payload and codec fixtures recorded from upstream pass unchanged on `ton_core`
0.3.7, so the signed bytes did not change. Stack use was measured on macOS arm64
only. No image was built and nothing was deployed.

The re-review parsed 19,715 mainnet BOCs (7,768 recent message bodies and 11,947
LayerZero storage, code and message BOCs read from toncenter) with `ton_core` 0.1.3 and
0.3.7: every one parsed under both, to the same representation hash, and Pillar's ingress
accepted all of them before and after. It also found that `ton_core`'s BOC serializer,
in both versions, ordered shared cells by `HashMap` iteration, so about 1,700 of those
BOCs re-serialized to different bytes from one run to the next. `boc_to_hex` and
`boc_to_base64` now order cells as `@ton/core` `toBoc` does; the two storage fixtures
this crate produces were regenerated with `@ton/core` 0.63.1 bytes.

## 22. H-02 and M-18 to M-21 remediation — 2026-10-24

The report is Sentry Code Round 1 of 2026-10-23. All five findings were present at
`87bbbda` (`public/main`, the H-01/M-16 remediation), where the work branches: one
commit for H-02, one for M-18 to M-20, which share the provider-health path and its
tests, one for M-21, then documentation. It is not released. The per-finding response,
including why the READ limit is 1 MiB, is
[h02-m18-m21-response.md](audit/h02-m18-m21-response.md).

| ID | Implementation | Exercised evidence |
| --- | --- | --- |
| H-02 | 1 MiB of READ returned data per request result, per decoded lzMap/lzReduce result and per command phase (request results, lzMap results), as an agreed vote or a phase charge; READ calls in flight capped at 4 per target chain and per command phase and 16 per process, chain permits granted in arrival order, all held until a call's quorum resolves; digest fingerprints; streamed `resolvedPayloadHash`; payload moved, not copied, into the response | 256 legal results refused with `UNRESOLVABLE_COMMAND` after at most four calls past the cap; the audit's shape at quorum 2 of 3 peaks far below the audit's 1.75 GiB RSS in a child process; exactly 1 MiB signs over the production HTTP route, 1 MiB + 1 is 400 without a sign stage; a decoded lzMap or lzReduce result of exactly 1 MiB resolves, 1 MiB + 1 refuses; one hostile oversized provider is outvoted; one command peaks at four calls, eight commands over four chains at sixteen with every chain at four; three chains stalling every call for 50 s do not delay a fourth chain's READ; a small command behind three large ones on one chain waits at most four call delays; a 256-request map-reduce command at 200 ms per call resolves inside the 58 s deadline |
| M-18 | Diagnostic probe entries never write rank; TON v3 probes write, and v3 dispatch reads, `ton_v3_rank_key` | An Aptos indexer at the RPC's own base failing leaves the RPC dispatchable; a failing RPC with a healthy colliding indexer is still excluded, on Aptos and Initia; a dead TON v3 endpoint behind a live v2 one is refused for v3 reads and kept for v2 |
| M-19 | `provider_rank_key`: dial URL plus a SHA-256 digest of the headers, one function for every voting probe and for dispatch | A dead header credential listed after or before the live one leaves the live entry dispatched first; Aptos `?auth=` and header forms agree; the key and credentials never reach `/provider-health` |
| M-20 | The IOTA/Sui sender vote binds digest, sender, checkpoint and status | A fullnode-rendered and an indexer-rendered answer agree on the sender; a different sender or checkpoint still splits |
| M-21 | Move V302 (Aptos, Movement, Initia) and Aptos V301 count confirmations only when positive; Sui/IotaL1 `EConfirmationsNotFound` is no record, unsigned, and `get_confirmations` takes `keccak256(packetHeader)`, not the raw header | With the recorded configs set to require 0, a count of 0 signs at VERIFYING and VERIFIABLE; VERIFIED or a positive count at the requirement is `Payload already signed`; on Sui at a required 0 a missing record signs, a stored 0 or 1 is already signed, and the hashed header is sent; on IotaL1 a missing record signs |

### Verification

| Check | Observed result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked` | Passed; one pre-existing warning in `gasolina_parity_tests.rs:89` |
| `cargo test --workspace --locked` (1.98.1) | 1,181 passed, zero failed, 15 ignored (`test result:` totals, child processes' own summaries not counted), on the final tree; artifacts in `local/e2e-runs/h02-m21-*` |

Failure modes were written down before the code and each is a scenario of the tests
above. An independent read-only review found no correctness defect and three wording
errors, corrected before the first final run; Initia drops its query without moving it
to a header, and a test comment still said headers were stripped. The first full run
failed on `plan_dispatch_uses_aptos_canonical_url_for_rank_lookup`, which pinned the
URL-only key M-19 replaces; it was removed. The review's residuals were then fixed as
well, diverging from upstream where needed: Sui/IotaL1 absence, TON v3 ranking, READ
fairness across commands and chains, and the decoded lzMap/lzReduce boundary. The test
`runtime_rpc_validation_checks_fail_closed_when_sui_confirmations_are_zero_and_required_is_zero`,
which pinned upstream's reading of the abort as 0, was replaced. A second review of
that work found three defects, fixed before the last run: a per-command limit of two
stretched a lone 256-request map-reduce command past the 58 s deadline at about 0.23 s
per call; two stalled chains filled the eight process permits; and the Sui read passed
the raw packet header to `bytes32::from_bytes`, whose length abort shares code 1 with
`EConfirmationsNotFound`, so no DVN confirmation was ever read there. The upstream
IOTA, LayerZero-v2 (Aptos, Initia, Sui) and LayerZero-Aptos-Contract sources and
upstream `lz-v2-sdk/src/uln/sui/index.ts` were read; neither IOTA backend and no live
Sui `devInspect` was run. Fix-reverted runs were not performed. No image was built and
nothing was deployed.

## 23. M-22 to M-25 remediation — 2026-10-26

The report is Sentry Code Round 1 of 2026-10-23. All four findings were present at
`201430d` (`main`). The work branches from the H-02 to M-21 branch (`b2bb67d`), which
had already restructured the READ permits M-24 names: one commit per finding, then
documentation. It is not released. The per-finding response is
[m22-m25-response.md](audit/m22-m25-response.md).

| ID | Implementation | Exercised evidence |
| --- | --- | --- |
| M-22 | TON `dvn_attestation` counts an attestation only at `confirmations >= required`, the requirement resolved as `UlnReceiveConfig::utils::resolveConfirmations`; a TON MESSAGE request below the requirement is a 400 before any source read | The deployed `UlnConnection` code run in `@ton/sandbox` (`tests/ton_contract_semantics/confirmations.json`, eight cases); the already-signed verdict equals the contract's `verifiedView` in each; one below the requirement is refused after two TON storage reads and no source read |
| M-23 | `scan` hands the verified body to its shape function by value; events are moved | A 3 MiB committee-less scan ends in the ordinary refusal within the time bound |
| M-24 | READ chain and process permit waits end at the signing request's deadline | With the only permit held, a second call returns `Admission(Deadline)` at its 300 ms deadline |
| M-25 | `pillar_core::json` refuses the private `RawValue`/`Number` keys at any depth; every outside-input parse uses it; `clippy.toml` disallows direct `serde_json` parse calls | The report's 14-level body is a 400 on tokio's default 2 MiB worker stack; every key spelling and position, the envelope and provider responses are refused; every committed JSON file parses identically to `serde_json` |

### Verification

| Check | Observed result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked` | Passed with the new `clippy.toml`; one pre-existing warning in `gasolina_parity_tests.rs:89` |
| `cargo test --workspace --locked` (rustc 1.96.0) | 1,188 passed, zero failed, 15 ignored (`test result:` totals), on the final tree; artifacts in `local/reports/m22-m25-remediation-20261026/` |
| Same, after the residual fixes | 1,193 passed, zero failed, 15 ignored, on the final tree; artifacts in `local/reports/m22-m25-residuals-20261026/`. Two earlier runs failed on test configurations that still used a committee-less Canton sequencer and on a wrong expected `srcEid` felt (30101 is `0x7595`); both were corrected and the whole suite rerun |
| `cargo audit`, `cargo deny check` (second residual pass) | Both exit 0 after the dependency upgrades; before them `cargo audit` reported RUSTSEC-2026-0387, -0385 and -0386 |
| `cargo test --workspace --locked`, second residual pass | 1,198 passed, zero failed, 15 ignored, on the final tree; artifacts in `local/reports/residuals-round2-20261026/`. Three earlier runs failed and each was fixed and the whole suite rerun: Starknet fixtures assumed the requirement was read first and Move tests signed at `blockConfirmation` 1 below their recorded requirement of 15 (both test-side); an Azure test assertion was inverted while porting `normalize_s` to k256 0.14; a tracing callsite interest cached `never` by a parallel test thread |

Failure modes were written down before the code and each is a scenario of
`m22_m25_remediation_e2e.rs`. The TON semantics were taken from the deployed code, not
from source: `verifiedView` counts the attestation at `stored >= required` and not below,
and with the OApp's `confirmationsNull` set the default's value is used even when the
default's own flag is set (`default_null_flag_ignored`). Eight emulated cases; Pillar's
already-signed verdict equals `verifiedView` in all eight, and the confirmation floor
refuses one below the requirement after two TON storage reads in all seven cases with a
positive requirement. The report's M-25 body (69,776 bytes, 14 re-parses) is a 400 naming
the key; 97 committed JSON files parse identically to `serde_json`.

An independent read-only review found no material defect. The first full run failed four
tests, all fixed before the run above: the depth case assumed `serde_json` accepts 128
levels (it accepts 127); a 256 KiB worker stack overflowed inside axum's request path
before the body was read, so the M-25 child now uses tokio's default 2 MiB stack, which
production uses; the Canton sequencer fixture lacked the required `authorization` header;
and `h02_stalled_chains_do_not_delay_another_chains_reads` showed that bounding READ
permit waits by a fixed 58 s outside a request context failed callers with no deadline,
so the wait is now bounded only by the request's own deadline. The residuals left by
that run were then closed - Starknet's already-signed check (`has_payload_signed` ignores
confirmations, confirmed in the Cairo source and against mainnet storage), READ
starvation by four stalled chains, and the committee-less Canton sequencer - and each
defect's old behaviour is shown in the final run itself rather than by reverting
commits; see [m22-m25-response.md](audit/m22-m25-response.md). No image was built and
nothing was deployed.

## 24. Full findings list remediation — 2026-10-27

The report is the Main Review CSV of 100 findings. The work branches from `87bbbda`
(`public/main`) and carries the H-02 to M-25 branch forward. 67 findings were changed
here and 33 were confirmed by earlier work; the per-finding response is
[full-csv-response.md](audit/full-csv-response.md).

### Verification

| Check | Observed result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked` (`-D warnings`) | Passed; the earlier `gasolina_parity_tests.rs:89` warning is gone |
| `node scripts/check-generated-config-integrity.mjs`, `build-acceptance-matrix.mjs --check` | Passed |
| `cargo test --workspace --locked -- --include-ignored` with synthetic PostgreSQL and TLS, plus the CLI process scenarios | 1,249 passed, zero failed (`test result:` totals, child-process summaries not counted), on the final 2.7.2 tree; artifacts in `local/reports/full-audit-20261027/runs/20261027T020737.459978Z/` |

Four earlier full runs failed and each was fixed and the whole suite rerun. Most failures
were tests pinning the old behaviour (lowercase EVM addresses, hosts in reports, bare TON
endpoints, two errors after an impossible quorum). Four were regressions in this work:
health rounds launched every chain at once and serialized each chain's probes; the
413 size check ran before Express's header-only answers; the early quorum exit hid the
zero-success signal readiness reports as "not found"; and Sui GraphQL byte decoding
changed upstream's `Uint8Array.from` errors. A PostgreSQL audit scenario overflowed the
test thread stack by starting several runtimes in one future and now boxes them.
`cargo audit` and `cargo deny` were not run locally (tools absent); CI runs both. Live
providers were not exercised. No image was built and nothing was deployed.
