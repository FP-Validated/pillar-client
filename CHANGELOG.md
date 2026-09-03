# Changelog

All notable changes to this project are documented here. This project follows
semantic versioning for the HTTP surface, the environment-variable contract and
the Prometheus metric names.

## 2.2.0 - 2026-09-03

### Added
- `PILLAR_PUBLIC_SIGN_ROUTES=true` serves `POST /` and `POST /v2/resolve-and-sign`
  without a bearer token. LayerZero calls a registered DVN endpoint with no
  credential of ours, so a deployment meant to receive that traffic could not
  demand one and answered every call with 401. The switch is opt-in, takes the
  exact string `true`, and is scoped to those two routes: `/signer-info`,
  `/provider-health/report` and `/metrics` stay authenticated in every mode, and
  `PILLAR_API_AUTH_TOKENS` stays required, so forgetting to configure tokens
  still fails the boot rather than silently opening the service. The startup
  report prints `sign_routes:` on every boot so the posture cannot change
  unobserved.

### Fixed
- `pillar_sign_stage_duration_seconds` now records. The production composition
  injected `NoopSignStageObserver`, so the family rendered its `HELP` and `TYPE`
  lines with no samples beneath them — indistinguishable, to an operator, from a
  service that had signed nothing. `PillarMetricsStageObserver` existed but was
  never constructed anywhere outside unit tests, which is why no test caught it:
  they exercised the observer directly rather than the assembler. A test now
  drives the real assembler and reads the registry the HTTP surface serves.
- A malformed protocol field is a 400, not a 500. `ulnSendVersion` and the
  pathway extras deserialise as `serde_json::Value`, and the HTTP boundary
  checked presence only, so a non-string version reached the core, which could
  only classify it as an internal fault. The boundary now type-checks the
  protocol fields against the closed version set, matching where upstream puts
  its Zod schema, and the core reports caller input as `BadRequest` on both the
  v1 and v2 routes — v1 copies its `ulnVersion` straight through.
- `pillar_provider_request_errors_total` covers every quorum path. The Move and
  TON resolvers built their own accumulators and called `finish` directly, so
  those chain families could fail quorum on every provider while the counter an
  operator alerts on stayed at zero. All three paths now end in one
  `finish_quorum` helper. The metric's `HELP` text no longer claims to count
  provider failures generally; validation-stage provider failures surface as
  `pillar_sign_stage_duration_seconds{status="error"}` instead, which is now
  a real signal rather than an empty family.

### Changed
- `SECURITY.md` and the builder-selection comment in `pillar-core` now cite the
  upstream call chain rather than asserting parity, and identify the exact tree
  they were read from by the `chainNames/*.ts` content hashes already recorded in
  the generated environment table's provenance header. Two independent reviews
  reported that upstream runs an entity/category provider trust model and a
  V2-to-V3 receive-library builder override. Neither is on the runtime path in
  that tree, and the dormant scaffolding that prompted both readings is now named
  explicitly along with the reason it is dormant. One review's source was a
  differently-rooted archive that has not been obtained, so its claims are
  recorded as not reproducing against the identified tree rather than as
  refuted — a distinction worth keeping, since only one of those two statements
  is something this workspace can establish.

- The server no longer speaks HTTP/2. It was serving h2 prior-knowledge
  connections, which nothing here asked for: `hyper`'s `http2` feature is
  enabled process-wide by `aws-smithy-http-client` and `tonic` for the KMS and
  storage clients, and the `hyper-util` `auto` builder then negotiated it. The
  accept loop holds one semaphore permit per connection, so a single h2
  connection multiplexed up to 200 concurrent streams - the SETTINGS frame
  advertised `MAX_CONCURRENT_STREAMS=200` - behind one permit, and
  `PILLAR_MAX_CONNECTIONS` bounded sockets rather than work. Connections are now
  served by `hyper::server::conn::http1`, and a test writes the h2 preface and
  fails if it is answered. The `server-auto` feature is also dropped, but that
  alone would not prevent a regression: `hyper_util::server::conn::auto` is
  gated on `any(http1, http2)`, both of which the reqwest client stack enables,
  so the module stays compiled regardless of what this workspace declares.
  `auto::Builder::http1_only()` could not express this: hyper-util documents it
  as a no-op under `serve_connection_with_upgrades`.

### Changed
- The payload-already-signed check now asks the destination endpoint which
  receive library the receiver OApp actually uses, instead of deriving it from
  `dstEid`. Deriving it reads the wrong contract for an OApp on a non-default
  receive library, so a message already attested there looks unsigned. A receive
  library that is not one of `ReceiveUln302`, `ReceiveUln301` or `ReadLib1002`,
  or a non-default one the endpoint itself rejects, is now refused rather than
  guessed at. The resolution runs per provider and the quorum agrees on the
  library, not only on the verdict.

  On the exploitability of the old behaviour: a second signature was **not**
  reachable in practice, because the same code path was blocked earlier by the
  address-width defect below - the check never dialled at all and failed
  closed. Verified by running the pre-fix image against the same request: it
  answered `Payload-signed validation unavailable` with zero `eth_call`s. The
  derivation was still wrong, and fixing the width alone would have made the
  second signature reachable.
- The generated EVM deployment table now also carries the V1 `Endpoint`
  address, needed for pathways whose destination endpoint id is a V1 one.
  Pre-existing rows are unchanged.

### Fixed
- `pillar_provider_config_age_seconds` no longer reports a frozen configuration
  as fresh. The gauge was written from inside the refresh loop, and its accepting
  branch wrote `0`, so a loop that died right after a success left the metric
  pinned at zero for the life of the process - the one value meaning "nothing is
  stale". Both this age and the new heartbeats are now computed when `/metrics`
  is scraped, from a timestamp their owner stamps, so a loop that stopped for any
  reason reads as growing. It also means a scrape taken before the first refresh
  interval carries a sample at all; previously the metric was absent for the
  first sixty seconds of every process.
- The provider-rank and provider-health-cache loops are now aborted when the
  runtime app is dropped. Dropping a tokio `JoinHandle` detaches the task rather
  than stopping it, so the previous `_provider_rank_refresh` field controlled
  nothing and both loops kept issuing provider RPC after the server stopped
  serving. `RemoteProviderConfigOwner` already did this for the config loop;
  this is the same contract for the other two. They are also spawned after every
  fallible initialisation step, because `Drop` cannot run on a value that was
  never constructed: a failure in `StartupReport::from_parts` used to return past
  two live loops and leave them detached with no owner able to stop them.

### Added
- `pillar_background_task_heartbeat_age_seconds{task}` — one sample per
  background loop (`provider_config_refresh`, `provider_rank_refresh`,
  `provider_health_cache_refresh`). Nothing awaited these tasks' handles, so a
  loop that panicked or wedged left no trace on any surface; a panic reached
  stderr through the default panic hook only, bypassing the `tracing` pipeline,
  and no metric moved. Alert above roughly three times the interval. **Add this
  to dashboards and alerts in the same rollout**, alongside the age metric that
  can now actually fire.

  It reports *that* a loop stopped, never *why*: a panic, a hung RPC and a task
  that never started all read as a growing age, deliberately, because the
  operator's next step is the same for all three. A loop that runs and fails is a
  different fact with its own metrics - the heartbeat stays healthy while
  `pillar_provider_config_refresh_total{result}` carries the failure.

### Fixed
- The EVM payload-already-signed check now works on a real packet at all. A V3
  pathway names the receiver as `bytes32`, and every `address` argument the
  check encodes rejected anything but 20 bytes, so the first call failed with
  `invalid address length: 32`. That error was swallowed into "validation
  unavailable", which fails closed - no wrong signature was ever issued - but
  the check itself had never run. EVM `address` arguments are now narrowed from
  the pathway value at the lookup input, and refused when the padding is not
  zero. The packet header keeps the padded form, so what gets signed is
  unchanged.

- **The signing path now follows an accepted provider-configuration refresh.**
  Every request-time consumer - the packet resolver, the read payload resolver,
  the TON and ULN V2 builders, the validator - held a provider map cloned at
  startup, so a refresh moved `/provider-health` and left signing dispatching
  to the endpoints the process booted with, with nothing reporting that the two
  disagreed. All of them now read one shared generation. An operator who
  rotates an RPC endpoint no longer has to restart for signing to use it.
- `GET /available-chains` and the signing gate now read the same object - the
  generation now serving - instead of each holding a roster copied at startup.
  The advertised set is unchanged in practice, because the chain set is fixed
  for the process lifetime; what this removes is a second copy that could drift
  from the configuration actually in use.
- A refresh may not add a chain. Signing capability - wallets, signer backends,
  chain types, contract tables, builders - is assembled once at startup, so a
  chain appearing in a later remote write is dropped from the configuration
  rather than advertised as something this process could sign for. This is a
  deliberate divergence from upstream, which builds its chain SDKs per request
  and can therefore serve a chain that appears in a later write. Adding a chain
  here requires a restart.
- **Provider ranking now actually applies.** The health report publishes a
  redacted URL - it is a public payload and an RPC key lives in the path or
  query - and rank was being keyed off that redacted string, while dispatch
  looks providers up by the URL it dials. For every provider carrying its
  credential in the path or query, which is every realistic one, the two never
  matched: an unhealthy provider was never excluded and latency ordering never
  applied. Two URLs on one host also collapsed to the same redacted key. The
  entry now carries the dialled URL in a never-serialized field and ranking
  keys off that; the published payload is byte-for-byte unchanged.
  Tron needed a second half of the same fix. Its probe deliberately dials a
  different URL from the configured one - userinfo moves into an
  `Authorization` header and the `tron-api-key`/`tron-web-url` parameters are
  stripped - while Tron reaches the signing path as an EVM-shaped chain and
  dispatches on the configured URI verbatim, so ranking has to be keyed by the
  latter. It now is. Every other family's primary probe already dials what
  dispatch dials.
- Provider rank is not seeded from a health probe that straddled a refresh. Rank
  is keyed by `(chain, url)` with headers stripped, so an operator rotating
  credentials on an endpoint would otherwise have the failures observed under
  the old ones recorded against the fixed one, and dispatch would keep excluding
  it until the entry aged out - failing requests closed for a chain whose quorum
  could then not be met, minutes after the configuration was fixed. Such
  observations are discarded; the endpoints stay unranked, which dispatch reads
  as the normal pre-ranking default.
- The signing gate refuses a chain that is no longer served, naming what is
  served now. `PillarApp` held the roster it was constructed with, so a chain
  removed by a refresh was admitted and then failed deeper with an error about
  provider configuration instead of about the chain.
- `GET /ready` decides from one generation. It reads provider state twice - the
  health snapshot, then the chain roster - so a refresh landing between them
  could report on a combination of one generation's health and another's chain
  set that never served.
- One sign request now reads exactly one provider generation. Previously each
  consumer read the shared map when it happened to need it, so a refresh
  landing mid-request could have the event resolved against one provider set
  and the payload-already-signed check run against another.
- The provider-health cache is now keyed by configuration generation. It serves
  a value for up to two minutes, and `/provider-health` and `/ready` are
  computed from it, so a refresh inside that window could previously report on
  endpoints that were no longer configured. A refresh now expires it.

  The generation is read *before* each probe, not after. A refresh can be
  published while a probe is in flight, and that probe already read the
  endpoints of the generation it started under, so labelling it with whatever
  is serving when it returns would present an observation of the replaced
  provider set as describing the new one - and then serve it for the whole
  TTL. The same rule covers a probe that fails mid-refresh, which is retried
  against the configuration now serving rather than falling back to the value
  from before the replacement, and the startup seed, which is labelled with the
  generation the composition root probed rather than the one live when it hands
  the report over. If the configuration is replaced under every attempt, the
  cache reports failure rather than answering with an observation of a
  configuration that is not serving.

- The four provider-backed validations of a sign request - message hash,
  readiness, expiration and payload-already-signed - now run concurrently
  instead of one after another, matching upstream's `Promise.all`
  (`apps/gasolina/src/app/app.ts:495-510`). A valid request waited for the sum
  of those round trips and now waits for the longest. Extra-context validation
  still runs only after the others pass, and the errors are still reported in
  the previous order, so which error a caller sees is unchanged; an invalid
  request now issues the later checks before failing, which is the same trade
  upstream makes.

### Documented

- `SECURITY.md` now states what a provider quorum proves. A quorum of N is N
  URIs returning the same value; the configuration has no notion of who
  operates an endpoint, so two URIs from one provider satisfy a quorum of 2
  while sharing one failure domain. Upstream's consumed provider entry is the
  same shape, so this is a property of the trust model to arrange operationally,
  not a regression against upstream.
- Recorded that on EVM the destination receive ULN version is derived from the
  endpoint id rather than read from the receiver's actual receive library as
  upstream does, that the two agree for receivers on the default library, and
  that for a receiver with a non-default library the payload-already-signed
  check can miss an existing verification and permit a second signature.
- Recorded that the generated LayerZero tables are pinned snapshots with no
  automated upstream comparison, and why public CI cannot perform one.
- `provider_validation` now says in the module documentation that no runtime
  path calls it, and that the same split exists upstream, so its presence is not
  read as an entity-aware quorum the signing path enforces.

### Security

- A remote provider-configuration refresh is now admitted by the same gate as
  startup. `StaticProviderConfig::new` only restricts the map to the requested
  chains, so a snapshot with no URIs or a zero quorum loaded happily and
  replaced the active one every 60 seconds. That map is what
  `/provider-health` and `/ready` are computed from, so the readiness false
  positive closed at startup could come back from S3 or GCS. A rejected
  snapshot leaves the previous one serving and counts under
  `pillar_provider_config_refresh_total{result="rejected"}`, distinct from
  `error` for a failed fetch. Signing was not affected: request-time
  validation reads the configuration captured at startup, not this map.
- The refresh loop now records into the registry `/metrics` renders. It built
  its own `PillarMetrics`, so `pillar_provider_config_refresh_total` and
  `pillar_provider_config_age_seconds` were never served and a bucket that
  had been failing for hours was invisible to alerting. The counter claim in
  the entry above was true of the code and false of the endpoint until this
  change; an end-to-end test now drives the real loop and asserts all three
  outcomes appear on the app's rendered `/metrics`.
- `pillar_provider_config_age_seconds` is measured from the last accepted
  snapshot. It was measured from process start, so a run that refreshed
  cleanly for ten minutes and then failed once reported ten and a half
  minutes of staleness instead of thirty seconds. A rejected snapshot is not
  a success and does not reset it.

- Bumped `h2` to 0.4.19 for RUSTSEC-2026-0258 (unbounded empty DATA frames).
  This is reachable from ingress, not only from outbound clients: the server
  negotiates h2c, so the advisory applied to the signing endpoints themselves.
- Resolved RUSTSEC-2026-0253 instead of ignoring it. `aws-sdk-s3` 1.144.0 is
  the first release to accept `lru` 0.18.2, so the advisory is now fixable;
  `aws-config` 1.11.0 and the sibling AWS SDK crates moved with it to keep a
  single `aws-smithy-schema` generation in the graph. The `.cargo/audit.toml`
  ignore entry is gone and `cargo audit` passes with no suppressions. The
  manifest floors were raised to the resolved versions, so a fresh dependency
  resolution cannot select a version that requires the vulnerable `lru`.

  Operators should smoke-test against staging before rolling this out: the AWS
  SDK clients for KMS, S3, Lambda and Secrets Manager all moved, and the unit
  tests exercise them through fakes rather than live endpoints.
- Documented the Stellar deployment-address caveat in
  [SECURITY.md](SECURITY.md#known-caveats). Every pinned Stellar address —
  including the trusted endpoint address used for source-event filtering —
  disagrees with LayerZero's live deployment metadata on both `mainnet` and
  `testnet`. Starknet, pinned from the same generation, agrees on all
  equivalent values. Confirm on-chain before enabling Stellar. No addresses
  were changed; this is a disclosure, not a fix.
- **`HEAD` no longer bypasses authentication.** axum dispatches `HEAD` to the
  registered `GET` handler, and the credential check matched on the raw method
  string, so `HEAD /metrics` ran the handler and returned 200 while
  `GET /metrics` returned 401. The body was stripped but `Content-Length` was
  set from the real body first, so the size leaked, and the handler's side
  effects still ran — `HEAD /provider-health/report` probed every provider of
  every chain, bypassing the 15s cache. `HEAD` now inherits the `GET` route's
  requirement.
- Fixed a truncation in the constant-time token comparison: the length
  mismatch was folded in as `(a ^ b) as u8`, so a difference that is an exact
  multiple of 256 became zero and the byte loop then compared the absent bytes
  against an implicit zero. Header parsing rejects NUL bytes, so this was not
  reachable over HTTP; the comparator no longer depends on that.
- Added deny-path coverage for authentication. Every `(method, path)` in the
  authenticated set is now asserted to return 401 with no credential, a wrong
  token, a non-`Bearer` scheme and a token prefix — `HEAD` included. There was
  previously no test for a rejection at all, which is how the `HEAD` gap
  survived.

### Changed

- Startup now refuses a provider configuration that request time would reject
  anyway: a selected chain with no provider URI, `quorum` of 0, or `quorum`
  greater than the number of configured URIs. It also refuses to start when
  `LAYERZERO_AVAILABLE_CHAIN_NAMES` selects nothing present in the provider
  configuration. Previously such a chain reported `GET /ready` as `READY` and
  `GET /provider-health` as healthy while every sign request for it failed with
  `No provider URI for chain ...`. The readiness snapshot's treatment of an
  empty provider list as healthy is upstream behaviour and is unchanged; the
  configuration that makes it observable is now rejected. The gate reuses
  `required_provider_quorum`, so it cannot drift from the request-time check.
- Startup now names entries that were silently dropped. Upstream matches
  `LAYERZERO_AVAILABLE_CHAIN_NAMES` verbatim with no trimming, so
  `ethereum, bsc` loses ` bsc`; that parsing is unchanged for parity, but the
  dropped entries are logged. Likewise `LAYERZERO_SUPPORTED_ULN_VERSIONS`
  entries other than `V2` and `V301` have no effect — the variable gates only
  those two builders — and are now logged instead of being ignored in silence.

### Documentation

- Added `CONTRIBUTING.md`, covering the fail-closed rule, the upstream-citation
  requirement for protocol and address claims, the prohibition on hand-editing
  generated tables, and the fixture-naming rule that recorded values must not
  be presented as upstream-reproduced.
- Corrected four README claims. Not every response is enveloped: `GET /`
  returns a bare `HEALTHY` and `GET /metrics` returns Prometheus text. Stellar
  is described as rollout-blocked on both environments rather than "confirm
  before enabling", because listing it in `LAYERZERO_AVAILABLE_CHAIN_NAMES`
  does not enable it. The destination-family table is labelled a builder
  capability matrix, since a builder existing implies neither a deployment
  entry nor an operationally enabled chain. And `ULN V2` is distinguished from
  `Endpoint V2`, which both read as "V2" but are different axes.
- Documented that readiness is service-level — ready while at least one
  configured chain is healthy — and that both readiness and provider health are
  served from a cache that is fresh for 15s and can serve a stale value for up
  to 120s when a refresh fails. Also documented that a Kubernetes readiness
  probe belongs on `/ready`, not `/`, which is a constant liveness string.
- Recorded the remaining known gaps in `SECURITY.md`: the TON DVN verify
  fixtures are recorded rather than reproduced from the upstream
  implementation, `movement` currently resolves to the same Move addresses as
  `aptos` and will keep doing so until the tables are regenerated, and ULN
  `ReadV1002` is EVM-only.

### Internal

- The provider-config refresh decision and its write live in one function,
  `apply_refreshed_snapshot`, so the active map cannot be replaced on a path
  that skipped validation. Three tests drive it with a candidate carrying no
  URIs, a zero quorum and a quorum above the URI count, and assert through
  `RemoteProviderConfigOwner::snapshot()` that the previous configuration is
  still the one serving - the loop's own sixty-second sleep and live bucket
  read stay out of the test. Moving the write above the check fails them.
- Renamed the TON vector tests to describe what they assert
  (`*_matches_recorded_vector`, `boc_round_trip_is_byte_identical`,
  `repr_hash_matches_recorded_execute_params_cell`); the constants and
  assertions are unchanged.
- Restricted the CI workflow's `GITHUB_TOKEN` to `contents: read`.
- The runtime image now records the commit it was built from. `Dockerfile`
  accepts a `VCS_REVISION` build argument and writes the OCI
  `org.opencontainers.image.*` labels; CI passes the commit SHA and then asserts
  the label matches it. Previously a pulled image carried no link to its source:
  `PILLAR_IMAGE_VERSION` fell back to `unknown` whenever the builder omitted the
  argument, and a tag can be moved after the fact. Operators verifying a rollout
  can now read the revision off the image itself rather than trusting the tag.
- Vulnerability reports now go through GitHub private vulnerability reporting
  instead of an email address.
- Every crate declares `publish = false` and inherits `repository` from the
  workspace, so the workspace cannot be pushed to crates.io by accident and the
  generated SBOM carries the repository URL.

## 2.1.0

### Breaking

- **Environment variable renamed**: `GASOLINA_IMAGE_VERSION` is now
  `PILLAR_IMAGE_VERSION`. There is no fallback; the old name is ignored.
- **Prometheus families renamed**: `gasolina_http_requests_total`,
  `gasolina_http_request_duration_seconds`, `gasolina_build_info` and
  `gasolina_sign_stage_duration_seconds` are now the `pillar_*` equivalents.
  Label sets and bucket boundaries are unchanged. Dashboards, recording rules
  and alerts must be updated in the same rollout.
- **Authentication is now required.** `POST /`, `POST /v2/resolve-and-sign`,
  `GET /signer-info`, `GET /provider-health/report` and `GET /metrics` require
  `Authorization: Bearer <token>` matching one of `PILLAR_API_AUTH_TOKENS`.
  The service refuses to start if that variable is missing or holds a token
  shorter than 32 characters. Prometheus scrape jobs need the token configured.
- **Container health check target changed** from `GET /` to `GET /ready`.
  `GET /` remains a constant liveness string; `GET /ready` reflects signer and
  provider state and turns 503 as soon as shutdown is signalled.

### Added

- `GET /ready` readiness endpoint (200 `READY` / 503 `NOT_READY`).
- Graceful shutdown on SIGTERM/SIGINT: the listener stops accepting, readiness
  flips to 503, in-flight requests drain for up to
  `PILLAR_SHUTDOWN_GRACE_SECONDS` (default 25), then the process exits 0.
- Connection admission cap via `PILLAR_MAX_CONNECTIONS` (default 1024).
- Metrics for operator alerting: `pillar_provider_config_refresh_total{result}`,
  `pillar_provider_config_age_seconds`, `pillar_signer_errors_total{backend}`,
  `pillar_provider_request_errors_total{chain,kind}`.
- Starknet and Stellar destinations now work on `testnet` as well as `mainnet`;
  the destination ULN address is resolved per environment and the testnet
  Stellar endpoint id (40600) was added.
- `stellar_contract_id_from_strkey` derives Soroban contract ids from strkeys
  (base32 + CRC16-XModem), replacing a hardcoded byte constant.
- Root `LICENSE`, `README.md`, `SECURITY.md` and this changelog; per-crate
  package descriptions; declared MSRV; `overflow-checks` enabled in release.

### Changed

- The HTTP method metric label is normalised to a fixed allowlist, so unknown
  request methods can no longer create unbounded Prometheus series.
- Remote provider-configuration refresh failures are now logged at `error` and
  counted; the configuration age gauge keeps climbing while refreshes fail.
- Error responses redact cloud key identifiers (AWS ARNs, GCP key-ring resource
  names) in addition to URLs.
- `skipVId` is now rejected on the legacy `POST /` path as well as on
  `POST /v2/resolve-and-sign`.
- The startup report shows the effective quorum per chain and flags chains whose
  quorum is 1 as a single-provider trust root.
- Generated LayerZero and TON configuration headers carry only publishable
  provenance (upstream package, version, input hashes, entry counts).

### Removed

- Operator-specific deployment tooling (`scripts/deploy-pillar-testnet.sh`,
  `scripts/post-rollout-smoke.mjs`). Deployment is owned outside this
  repository.
- The CLI has no subcommands; the binary only serves HTTP.

### Migration from the previous naming

1. Set `PILLAR_IMAGE_VERSION` wherever `GASOLINA_IMAGE_VERSION` was set.
2. Generate a token (≥32 characters), set `PILLAR_API_AUTH_TOKENS`, and add the
   bearer header to every caller and to the Prometheus scrape job.
3. Point liveness at `GET /` and readiness at `GET /ready`.
4. Rename `gasolina_*` to `pillar_*` in dashboards, recording rules and alerts.
5. Set an explicit `quorum` ≥ 2 per chain in the provider configuration.
