# Pillar Client

A LayerZero DVN (Decentralized Verifier Network) client in Rust. It resolves a
`PacketSent` event from a source chain, validates the message against the
configured providers, builds the destination ULN verify call data, and signs it
with a local mnemonic or a cloud KMS key.

The service exposes a small HTTP API and Prometheus metrics, and runs the same
binary against LayerZero `mainnet` and `testnet`.

## Status

- Supported LayerZero environments: `mainnet`, `testnet` (`sandbox`/`localnet`
  are accepted for local experimentation).
- ULN version handling has two levels, and they are easy to confuse:
  - `ulnSendVersion` on the request picks the **builder**: `V2` selects the
    legacy packet builder, `V301` and `V302` both select the V3 builder, and
    `ReadV1002` selects the read builder. The one exception is a `V2` send
    whose destination receiver has migrated off ULNv2: as upstream 1.2.66 does,
    the destination's receive library is read by provider quorum over the
    requested pathway before resolution, a ReceiveUln301/ULN302 answer selects
    the V3 builder over the packet rebuilt with its computed guid, and any other
    recognised library keeps the V2 builder. An unknown library is upstream's
    500 `Unsupported ULN version: undefined`, an endpoint-rejected override its
    500 `Invalid ULN version for lib: <address>`, and a provider disagreement
    refuses the request.
  - The **destination receive version** is then derived from the destination
    endpoint id, not from the request: endpoint ids below 30000 resolve to
    ULN301, everything else to ULN302 (`ReadV1002` passes through). So a
    request declaring `V301` against an endpoint id of 30000 or above still
    resolves to ULN302, and one declaring `V302` against an endpoint id below
    30000 resolves to ULN301 — that is upstream behaviour, not a fallback.
  - `ULN V2` and `Endpoint V2` are different axes that both read as "V2".
    `ulnSendVersion=V2` selects the legacy ULN builder; an Endpoint V2 endpoint
    id (30xxx on mainnet, 40xxx on testnet) identifies the destination endpoint
    namespace and is what the rule above compares against 30000.
- What actually differs per destination family is which of those builders
  exists. The table below is a **builder capability matrix** and nothing more:
  a builder existing is not the same as a deployment entry existing for a given
  environment, and neither implies the chain is operationally enabled — a
  rollout gate (testnet `ton`, testnet `moninet`) removes a chain even when
  both exist. "no" returns an explicit error rather than signing a guess, and
  so does any `(chain, environment)` pair with no deployment entry:

  | Destination family | Chain names | Legacy `V2` builder | V3 builder (`V301`/`V302`) | `ReadV1002` builder |
  | --- | --- | --- | --- | --- |
  | EVM, incl. Tron | EVM chain names, `tron` | yes | yes | yes |
  | Move | `aptos`, `initia`, `movement` | no (with a vId, upstream's 500 `VId is not supported on aptos yet`; with `skipVId`, 400: upstream would sign a utils-version-2 feather proof) | yes | no |
  | Sui | `sui`, `iotal1` | no | yes | no |
  | Solana | `solana` | no | yes | no |
  | TON | `ton` | no | yes | no |
  | Starknet | `starknet` | no | yes | no |
  | Stellar | `stellar` | no | yes | no |
  | Canton | `canton` | no | yes | no |

  The resolved receive version only changes an outcome where the family's
  builder consults it: EVM and Move select a different receive contract for
  ULN301 than for ULN302, and Solana rejects anything but ULN302. The Sui,
  TON, Starknet, Stellar and Canton builders never reference a ULN version. Every
  registered non-EVM endpoint id is an Endpoint V2 id (30000 or above), so
  those resolve to ULN302 in practice — but `dstEid` arrives in the request,
  so that is a property of the deployment tables, not a guarantee in the code.
  `ReadV1002` is EVM-only.

  The IOTA Move chain is named `iotal1`. `LAYERZERO_AVAILABLE_CHAIN_NAMES`
  drops names it does not recognise, so a misspelling silently removes a chain
  rather than failing loudly.
- **Stellar and Canton are in scope**, measured against upstream 1.2.66:
  - Stellar pins upstream 1.2.66's own contract getters (generation two:
    EndpointV2 `CCQLLRE5…`/`CALTBA5S…`, ULN302 `CCV4HEII…`/`CCMLPCAW…` on
    mainnet/testnet), which LayerZero's published deployment also names; a
    future disagreement between the two refuses per request rather than
    signing. Already-signed is upstream's `hasPayloadSigned` over Soroban
    `simulateTransaction`.
  - Canton builds and signs ULN302 verifies against
    `STATIC_VE3_CONTRACT_ADDRESSES.uln302` with upstream's raw-key signer
    identity. Canton as a source and its already-signed check go through the
    LayerZero sequencer the chain's `sequencer` provider entry names, as
    upstream does: signed `/scan` and `/vapp` reads, each verified against
    the entry's `sequencer-validators`/`sequencer-quorum` committee when one
    is configured and accepted unverified when not. The extra-context sender
    of a Canton source comes from a Canton ledger read, authenticated as
    upstream does with an OAuth2 client-credentials token: the `rpc` URI's
    `token-url`, `client-id`, optional `scope`/`audience`, and `client-secret`
    or, when the URI has none, `CANTON_CLIENT_SECRET`. Without those it
    refuses before any request. On `sandbox`/`localnet` upstream self-signs
    an admin JWT; that development auth is not enabled, so it refuses there.
    See [Known caveats](SECURITY.md#known-caveats).

Ask a running instance what it actually has enabled: `GET /available-chains`
and `GET /environment`.

## Workspace layout

| Crate | Role |
| --- | --- |
| `pillar-cli` | Binary entrypoint; loads configuration and serves the HTTP API. |
| `pillar-api` | Axum router, request middleware, error mapping, metrics endpoint. |
| `pillar-core` | Request/response models and the `PillarApp` sign workflow. |
| `pillar-runtime` | Composition root: config loading, provider health, LayerZero wiring, validation, signer. |
| `pillar-config` | Environment parsing, provider/wallet config, generated LayerZero static tables. |
| `pillar-layerzero` | Packet, proof and ULN call-data builders per destination family. |
| `pillar-signer` | Local mnemonic and AWS/GCP/Azure KMS signer backends, chain address derivation. |
| `pillar-metrics` | Prometheus text rendering. |
| `pillar-client` | Client library for talking to a running instance. |
| `pillar-bench` | Opt-in Criterion benchmarks (excluded from the default build). |

## Build and run

```bash
cargo build --release -p pillar-cli
SERVER_PORT=8080 \
LAYERZERO_ENVIRONMENT=testnet \
LAYERZERO_AVAILABLE_CHAIN_NAMES=bsc \
PROVIDER_CONFIG_TYPE=LOCAL \
LAYERZERO_PROVIDER_CONFIG='{"entities":["operator","provider-a"],"chains":{"bsc":{"rpc":[{"uri":"https://bsc-a.example","category":"internal","entity":"operator"},{"uri":"https://bsc-b.example","category":"dedicated_external","entity":"provider-a"}]}}}' \
LAYERZERO_QUORUM_STRATEGY_CONFIG='{"default":{"allOf":[{"any":2}]}}' \
SIGNER_TYPE=KMS KMS_CLOUD_TYPE=AWS LAYERZERO_KMS_IDS=arn:aws:kms:...:key/... \
PILLAR_API_AUTH_TOKENS="$(openssl rand -hex 24)" \
./target/release/pillar
```

Startup prints a redacted configuration report (provider URLs, headers and key
identifiers are masked, tokens are shown only as a count) and then binds
`0.0.0.0:$SERVER_PORT`. The process refuses to start if `PILLAR_API_AUTH_TOKENS`
is missing or holds a token shorter than 32 characters.

On `SIGTERM` or `SIGINT`, shutdown starts at T0. `GET /ready` returns 503 and
the two signing routes reject new work immediately; the listener continues
accepting connections until E = T0 + the withdrawal interval, then graceful
connection draining continues only until D = T0 +
`PILLAR_SHUTDOWN_GRACE_SECONDS`. The withdrawal interval is part of, not added
to, the grace period. Requests admitted before T0 may finish until D; at D the
budgets close and remaining connections are cancelled. Idle keep-alive connections
are closed at E. Configure the orchestrator's termination grace period longer
than `PILLAR_SHUTDOWN_GRACE_SECONDS` so the process can complete its own drain.
This behavior has not been exercised with Kubernetes SIGTERM/preStop; endpoint
withdrawal and client/load-balancer races are narrowed, not eliminated.

### Docker

```bash
docker build -t pillar-client:local .
docker run --rm -p 8080:8080 --env-file ./pillar.env pillar-client:local
```

The image runs as a non-root user, pins its base images by digest, defaults to
`SERVER_PORT=8080`, and health-checks `GET /ready`. Use `GET /` for liveness.

### Source and release images

This repository is the public source. The maintainers' own release images are
published to a private container package and are not distributed; build your own
image from this tree with the `Dockerfile` above. An image built from this tree
carries `org.opencontainers.image.source=https://github.com/FP-Validated/pillar-client`
and `org.opencontainers.image.revision=<commit>` (pass `--build-arg VCS_REVISION=...`),
so the commit an image was built from can be read from the image itself.

## Configuration

All configuration is environment based. Required:

| Variable | Meaning |
| --- | --- |
| `SERVER_PORT` | TCP port to bind. |
| `LAYERZERO_ENVIRONMENT` | `mainnet`, `testnet`, or `sandbox`/`localnet`. |
| `PROVIDER_CONFIG_TYPE` | `LOCAL`, `S3`, or `GCS`. |
| `SIGNER_TYPE` | `KMS`, `MNEMONIC`, or `LOCAL_MNEMONIC`. |
| `PILLAR_API_AUTH_TOKENS` | Comma-separated bearer tokens accepted on authenticated routes. Each must be at least 32 characters. |
| `PILLAR_PUBLIC_SIGN_ROUTES` | `true` serves `POST /` and `POST /v2/resolve-and-sign` without a bearer. Anything else, including unset, keeps them authenticated. Required for deployments that receive LayerZero DVN traffic, since LayerZero calls a registered endpoint with no credential of yours. Scoped to those two routes; the tokens above stay required either way. |
| `PILLAR_API_AUTH_ENABLED` | `false` serves **every** route without a bearer, including `/signer-info`, `/provider-health/report` and `/metrics`, and makes `PILLAR_API_AUTH_TOKENS` optional. Anything else, including unset, keeps authentication on. Only for deployments already restricted at the network edge — e.g. an ingress source-IP allowlist — because it exposes signer identity and internal state to any caller that reaches the port. |

Provider configuration is upstream's `providers-v2.json` plus `quorum-strategy.json`
(`gasolina-audit` `213cd500`), both required; the retired `{ uris, quorum }` map is
refused at startup with a message naming it. By `PROVIDER_CONFIG_TYPE`:

| Variable | Applies to | Meaning |
| --- | --- | --- |
| `LAYERZERO_PROVIDER_CONFIG` | `LOCAL` | Inline `providers-v2.json`: `{ "entities": [...], "chains": { "<chain>": { "rpc": [{ "uri", "category", "entity", "headers"? }] } } }`. Canton also needs a `sequencer` entry, `https://<sequencer>[?sequencer-validators=<0x keys>&sequencer-quorum=<n>]` with an `authorization` header, and its first `rpc` URI must carry `admin-api` and `wallet-url`, as upstream requires. |
| `LAYERZERO_QUORUM_STRATEGY_CONFIG` | `LOCAL` | Inline `quorum-strategy.json`, required with the inline providers: `{ "default": { "allOf"?, "oneOf"? }, "chains"?: { "<chain>": { "rpc": {...} } }, "restrictions"?: { "minimumMaxEntities" } }`. |
| `LAYERZERO_PROVIDER_CONFIG_FILE_PATH` | `LOCAL` | `providers-v2.json` from a file; wins over the inline form. |
| `LAYERZERO_QUORUM_STRATEGY_CONFIG_FILE_PATH` | `LOCAL` | `quorum-strategy.json` from a file, required with the providers file. |
| `CONFIG_BUCKET_NAME` | `S3`, `GCS` | Bucket holding `providers-v2.json` and `quorum-strategy.json`; both are read on every load. |
| `LAYERZERO_CDK_DEPLOY_REGION` | `S3` | AWS region (defaults to `us-east-1`). |
| `GCP_PROJECT_ID` | `GCS` | GCP project owning the bucket. |

`category` is `internal`, `dedicated_external` or `shared_external`; every `entity`
must be listed in `entities`. A strategy counts **distinct entities** among the
providers that returned the same answer: `{ "any": n }` needs `n` entities from any
category, `{ "internal": n }` needs `n` internal ones, `allOf` requirements must all
hold and one `oneOf` alternative must, one entity fills at most one *category* slot
(`any: n` is a separate threshold on distinct agreeing entities that overlaps them, so
`{ "allOf": [{ "internal": 1 }, { "any": 2 }] }` is met by two entities), and `"max"`
resolves to the pool's entity count. Two URIs of one entity are one vote. Only each
chain's `rpc` pool is dispatched; other endpoint types are validated and ignored, and a
roster chain without an `rpc` pool does not start. A pair is refused at load when an
entry or category is invalid, an entity is unregistered, a field is unknown, a
strategy is unsatisfiable by its pool or needs no agreement at all, or a `"max"` falls
below `minimumMaxEntities`. Agreement is still exact: if two different answers could
each meet the strategy, the call fails rather than picking one.

`cargo run -p pillar-config --example provider_config -- convert <legacy.json>
<labels.json> <out-dir>` rewrites a retired file, given a `{ "<host>": { "category",
"entity" } }` label per URI host, and refuses to write a pair that would not start;
`... -- validate <providers-v2.json> <quorum-strategy.json> [chains]` runs the startup
loader offline and prints a redacted summary. Examples are in
`crates/pillar-config/examples/provider-config/`.

On `S3` and `GCS` the bucket is re-read every 60 seconds and a usable
configuration replaces the one serving, atomically: providers, entities and strategy
are one generation. Every reader of provider configuration - the signing path,
`/provider-health`, `/available-chains` - moves to the new one together, and anything
that has to combine two reads of it pins one generation for the whole operation: a
sign request from start to finish, and `/ready`, which asks whether any advertised
chain is healthy. A read of either object that fails, or a pair that fails the load
checks above, leaves the previous configuration serving and is counted under
`pillar_provider_config_refresh_total{result="error"}`; `result="rejected"` counts a
loaded pair the publish gate still refuses.

What a refresh can change is the URIs, entities and strategies behind the chains this
instance was started for. The chain set itself is fixed for the process
lifetime. It cannot **add** a chain: wallets, signer
backends and contract tables are assembled once at startup, so a chain that
appears in a later write is dropped rather than advertised as signable. It
cannot **remove** one either: a file that no longer carries a chain named by
`LAYERZERO_AVAILABLE_CHAIN_NAMES` fails the read, so the previous configuration
keeps serving and the failure is counted under
`pillar_provider_config_refresh_total{result="error"}`. Note the cost of that:
until the file carries the chain again, or an operator changes the roster and
restarts, no URI change in the same file is applied either.

Signer configuration:

| Variable | Applies to | Meaning |
| --- | --- | --- |
| `KMS_CLOUD_TYPE` | `KMS` | `AWS`, `GCP`, or `AZURE`. |
| `LAYERZERO_KMS_IDS` | `KMS` | Comma-separated key identifiers. |
| `AZURE_KEY_VAULT_URL` | `KMS` + `AZURE` | Key Vault base URL. |
| `GCP_PROJECT_ID`, `GCP_KEY_RING_ID` | `KMS` + `GCP` | Key ring location. |
| `LAYERZERO_WALLETS` / `LAYERZERO_WALLETS_FILE_PATH` | all | Wallet definitions per chain type. |
| `LAYERZERO_WALLET_MNEMONIC_MAPPING` / `..._FILE_PATH` | `LOCAL_MNEMONIC` | Mnemonic and derivation path per wallet. |

Optional:

| Variable | Meaning |
| --- | --- |
| `LAYERZERO_AVAILABLE_CHAIN_NAMES` | Restrict the environment's non-deprecated V2/V302 chain union (comma-separated). Unknown names are excluded; selected chains require provider config. |
| `LAYERZERO_DEBUG_MODE` | Include `debugInfo` in sign responses. |
| `EXTRA_CONTEXT_REQUEST_URL` / `EXTRA_CONTEXT_REQUEST_AUTH_TOKEN` | External extra-context check over HTTPS. |
| `EXTRA_CONTEXT_AWS_LAMBDA_NAME` | External extra-context check over Lambda (mutually exclusive with the URL form). |
| `PILLAR_IMAGE_VERSION` | Version string reported by `GET /version` and `pillar_build_info`. |
| `PILLAR_MAX_CONNECTIONS` | Concurrent connection cap (default 1024). The server speaks HTTP/1.1 only, so a connection carries one request at a time and this is also the in-flight request bound. |
| `PILLAR_SHUTDOWN_GRACE_SECONDS` | Total shutdown grace G (default 25 seconds); connection draining and in-flight work are bounded by absolute deadline D = T0 + G. The orchestrator termination grace period must exceed this value. |
| `PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS` | Withdrawal interval W (integer seconds when explicitly set; default `min(5 seconds, G/5)` with `Duration` precision; `0` is allowed; must be less than G). At shutdown T0, `POST /` and `POST /v2/resolve-and-sign` are rejected after authentication with HTTP 500 `{"statusCode":500,"body":"resource_draining"}`, and `/ready` returns 503; `GET /` remains 200 `HEALTHY`. The listener keeps accepting until E = T0 + W to allow endpoint withdrawal. W is carved out of G, not added: in-flight work admitted before T0 can finish until D = T0 + G, then budgets close and remaining connections are cancelled; idle keep-alive connections close at E. Draining responses carry `Connection: close`. Kubernetes SIGTERM/preStop has not been exercised, and load-balancer/client races are narrowed, not removed. |
| `PILLAR_ADMISSION_WAIT_MS` | Bounded resource wait (default 2000); capped by the original absolute request deadline. |
| `PILLAR_{SIGN,RPC,KMS}_CONCURRENCY` | Global active caps: 64 / 64 / 16. |
| `PILLAR_{SIGN,RPC,KMS}_CHAIN_CONCURRENCY` | Source-lane active caps: 8 / 8 / 4. RPC also shares a target-chain cap; KMS shares the per-key-reference cap below. |
| `PILLAR_{SIGN,RPC,KMS}_QUEUE_CAPACITY` | Shared waiting allowances: 128 / 512 / 128, plus at most one reserved first waiter per fixed lane when waiting is enabled. |
| `PILLAR_{SIGN,RPC,KMS}_CHAIN_QUEUE_CAPACITY` | Per-lane waiting caps: 16 / 64 / 16. |
| `PILLAR_KMS_KEY_CONCURRENCY` | Shared active cap per supplied KMS key reference string (default 4); see the note below the table for which string each provider supplies. |
| `PILLAR_KMS_CHAIN_KEY_CONCURRENCY` | Per-lane cap on active KMS permits for each supplied resource string in this process. Default is `min(PILLAR_KMS_KEY_CONCURRENCY - 1, PILLAR_KMS_CHAIN_CONCURRENCY)` when key cap is above 1 (defaults 4/4 → 3); with key cap 1 the limit is 1 and startup warns that headroom is impossible. Explicit 0 or a value above the key cap is rejected; a value equal to the key cap is also rejected when that cap exceeds 1. Values above `PILLAR_KMS_CHAIN_CONCURRENCY` but no greater than the key cap are accepted; the source-lane cap remains an independent bound. With default key cap 4, a single saturated source's maximum occupancy of one resource string falls from 4 permits to 3; this is an occupancy limit, not measured throughput. It counts supplied resource strings, not physical keys, remote KMS quota or fleet-wide usage; multiple saturated sources can still fill the shared resource cap. The supported production guarantee is the resolved-key Azure signing path; the configured resource string is not normalized into provider or physical-key identity. |
| `PILLAR_AUDIT_ENABLED` | Optional synchronous durable signing audit; default `false`. No database connection or completion-worker pool when disabled. |
| `PILLAR_AUDIT_DATABASE_URL` | Required when audit is enabled; remote PostgreSQL uses `sslmode=require` with rustls/WebPKI certificate and hostname checks (not `verify-full`/`verify-ca`); plaintext is limited to literal loopback/Unix sockets. |
| `PILLAR_AUDIT_NAMESPACE` | Required audit scope, 1–128 characters of `[A-Za-z0-9._-]`; replicas must share it and the same quota. |
| `PILLAR_AUDIT_TIMEOUT_MS` | Database operation deadline, including connection/lock/COMMIT (default 2000, maximum 5000), bounded by the caller deadline. |
| `PILLAR_AUDIT_MAX_ATTEMPTS` | Retained-attempt quota per namespace (default 100000, maximum 1000000); no TTL or automatic deletion. |

KMS resource strings are not normalized across key spellings. Azure charges the one-time public-key fetch to the configured key id and every signature (including hedges) to the resolved key reference the fetch returns; GCP charges both to the configured version name; AWS charges a public-key lookup to the configured key id (or to an id already resolved for the other key type) and ECDSA signing to the immutable key id that lookup returns, resolved on first use, while Ed25519 signing without audit is charged to the configured key id until a public-key lookup for that key type has populated the cache and to the resolved key id afterwards (`crates/pillar-signer/src/{azure/adapter.rs,gcp.rs,aws.rs}`). Resolutions are cached for the process lifetime without invalidation. The budget is therefore not a physical-key or remote-quota guarantee.

Resource waits and SDK calls inherit one absolute deadline. Local admission failures
remain legacy 500 envelopes; the CLI's 58s deadline closes the socket without a
timeout envelope, and a failed wallet batch never returns partial signatures.
Successful GET/HEAD terminal logs are debug-level; failures remain visible.

The caps are per process, not fleet-wide rate limits. Background RPC rounds have
their own 10s deadline and reduced lane capacity; speculative Azure hedges never
wait for a permit. These defaults have synthetic load evidence, **not live peak
calibration**. Do not treat them as a production sizing recommendation.

Audit-on commits validated intent and immutable effective signing identity before
each wallet effect, then signature fingerprints before 200. It is not a queue,
signature cache, recovery engine, or exactly-once guarantee. Unknown attempts are
retained; a retry revalidates and appends a new attempt. See the durable signing
section in [SECURITY.md](SECURITY.md) before enabling it.

Production guidance: use `SIGNER_TYPE=KMS`. Mnemonic backends exist for local
development and tests; they keep key material in the process environment.

## HTTP API

JSON responses use a `{ "statusCode": ..., "body": ... }` envelope. Two routes
are not JSON and carry no envelope: `GET /` returns the bare string `HEALTHY`,
and `GET /metrics` returns Prometheus text. Framework-level responses for
unmatched routes are not enveloped either.

READ의 pinned `NoCode` 또는 execution revert가 유일한 entity quorum을 얻으면 API는 다음 domain refusal 형식을 사용한다.

```json
{
  "statusCode": 400,
  "body": "ReadV1002 command is unresolvable: target has no code at the pinned block",
  "code": "UNRESOLVABLE_COMMAND",
  "retryable": false
}
```

Execution revert의 `body`는 `ReadV1002 command is unresolvable: execution reverted at the pinned block`이다.
API는 두 거절 모두 signer 호출 전에 반환한다. 단일 부정 관측은 quorum을 대신하지 않는다.
Timeout, transport 장애, malformed DATA와 일반 RPC 오류는 기존 internal/quorum 오류이며 이 domain refusal로 분류하지 않는다.
Strict-schema 오류 consumer는 `code`와 `retryable` 필드를 허용해야 한다. 다른 오류와 정상 응답의 envelope는 바꾸지 않는다.

As upstream does, an EVM, Starknet or Stellar source transaction with no trusted
`PacketSent` matching the request (another nonce or sender, an untrusted
emitter, or a reverted EVM transaction) returns HTTP 400 with `statusCode: 400`
and a `body` of `cannot find packet event for srcTxHash <srcTxHash> on pathway
<pathway JSON>`. This is a typed `BadRequest` classification; unrelated
provider/internal failures remain HTTP 500 even if their diagnostic text
contains the same suffix.
Implementation and response tests: `crates/pillar-runtime/src/layerzero_runtime/packet_resolver.rs`,
`crates/pillar-core/src/lib.rs`, and
`crates/pillar-runtime/src/tests/packet_identity_http_tests.rs`.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/` | public | Liveness; always `HEALTHY` while the process runs. |
| `GET` | `/ready` | public | Readiness: 200 `READY`, or 503 `NOT_READY` while draining or when no configured chain is healthy. |
| `POST` | `/v2/resolve-and-sign` | **bearer**, or public with `PILLAR_PUBLIC_SIGN_ROUTES=true` | Resolve the source event and return DVN signatures. |
| `POST` | `/` | **bearer**, or public with `PILLAR_PUBLIC_SIGN_ROUTES=true` | Legacy V1 sign entrypoint. |
| `GET` | `/signer-info?chainName=<chain>` | **bearer**, or public with `PILLAR_API_AUTH_ENABLED=false` | Signer addresses and public keys for a chain. |
| `GET` | `/available-chains` | public | Chain names this instance serves. Fixed for the process lifetime; a refresh changes only the URIs and quorums behind them. |
| `GET` | `/environment` | public | Configured LayerZero environment. |
| `GET` | `/provider-health` | public | Per-chain boolean health. |
| `GET` | `/provider-health/report` | **bearer**, or public with `PILLAR_API_AUTH_ENABLED=false` | Per-provider detail with a check timestamp. |
| `GET` | `/metrics` | **bearer**, or public with `PILLAR_API_AUTH_ENABLED=false` | Prometheus text format. |
| `GET` | `/version` | public | Configured image version. |

Authenticated routes require `Authorization: Bearer <token>` where the token is
one of `PILLAR_API_AUTH_TOKENS`; tokens are compared in constant time and every
rejection returns the same `401 Unauthorized` envelope regardless of cause.
Configure the token in your Prometheus scrape job as well.

`PILLAR_PUBLIC_SIGN_ROUTES=true` drops that requirement from the two signing
routes and nothing else: `/signer-info`, `/provider-health/report` and
`/metrics` stay authenticated, so the tokens remain required to boot. The
startup report prints `sign_routes:` on every boot, so an instance cannot end up
serving signatures without a credential unobserved.

`PILLAR_API_AUTH_ENABLED=false` drops it from every route and makes the tokens
optional. Use it only where callers are already restricted before the port —
the mainnet deployment gates them with an ingress source-IP allowlist, which a
shared bearer token does not improve on. Without such an edge restriction this
publishes signer identity and internal provider state, so it must stay unset.
Both switches take one exact string and default to the closed state, and the
startup report prints `api_auth:` next to `sign_routes:` on every boot.

Readiness is service-level, not per-chain: the instance is ready while **at
least one** configured chain is healthy, so read `/provider-health` for per-chain
availability rather than inferring it from `/ready`. Both are served from one
cache that treats a value as fresh for 15s and, if the refresh fails, keeps
serving the previous value for up to 120s in total — so neither flips the moment
an RPC endpoint dies. Point a Kubernetes readiness probe at `/ready`, not `/`:
`/` is a constant liveness string and cannot express draining or unhealthy
providers.

Clients may send `x-request-id`; it is recorded in server logs and attached to
error extensions, otherwise the server generates one. It is **not** returned as a
response header, so a caller cannot correlate a failure response with a server
log line on its own.

## Metrics

- `pillar_http_requests_total{method,path,status}` — the `method` label is
  normalised to a fixed allowlist so unknown request methods cannot create new
  series
- `pillar_http_request_duration_seconds{method,path,status}`
- `pillar_sign_stage_duration_seconds{stage,src_chain,dst_chain,status}` where
  `stage` is one of `get_sent_event`, `validate`, `build_hash_call_data`, `sign`
- `pillar_build_info{environment,version}`
- `pillar_provider_config_refresh_total{result}` — remote provider-config
  refresh outcomes: `ok` (a new snapshot is serving), `rejected` (the read
  succeeded but the snapshot could never sign, so the previous one still
  serves) and `error` (the read itself failed). Alert on `rejected` and
  `error`; both mean the configuration in the bucket is not the one in use.
- `pillar_provider_config_age_seconds` — seconds since the last *accepted*
  snapshot, computed when you scrape rather than written by the refresh loop, so
  a loop that has stopped reads as growing rather than as its last written
  value; alert above ~300. Absent under `PROVIDER_CONFIG_TYPE=LOCAL`, which runs
  no refresh loop.
- `pillar_background_task_heartbeat_age_seconds{task}` — seconds since each
  background loop last *completed* an iteration, for `provider_config_refresh`
  (60s interval, remote provider config only), `provider_rank_refresh` (150s)
  and `provider_health_cache_refresh` (15s). Also computed at scrape time, which
  is what makes a loop that panicked, hung or was never started visible at all:
  alert above roughly three times the interval. A value bounded under its
  interval is a loop keeping up. It does not tell you *why* a loop stopped — a
  panic, a hung RPC and a task that never started all read as a growing age,
  deliberately, because the operator's next step is the same for all three. A
  failing refresh is a different fact and has its own metrics: the loop stays
  healthy here while `pillar_provider_config_refresh_total{result}` and
  `pillar_provider_config_age_seconds` carry the failure.
- `pillar_signer_errors_total{backend}` — signing and key-fetch failures per
  signer backend
- `pillar_provider_request_errors_total{chain,kind}` — source-event resolution
  failures; `kind=quorum` means provider quorum was not reached for that chain,
  and every quorum path reports it, EVM and non-EVM alike. This family is
  deliberately not a catch-all: a provider failure during validation shows up as
  `pillar_sign_stage_duration_seconds{stage="validate",status="error"}`, and
  the stage a request died in is the more useful signal there.

## Development

CI (`.github/workflows/ci.yml`) runs on pushes to `main`, `v*` tags, pull requests
and a weekly schedule, in five jobs: fmt, Clippy, tests and the release build with
Rust 1.98.1; `cargo check` at the declared MSRV 1.94.1; the generated-config
integrity and acceptance-matrix checks; `cargo audit`, `cargo deny` and a CycloneDX
SBOM; and a container build that checks the revision label and that the binary
refuses to start without configuration. The image is not pushed. Warnings are
errors. Rust 1.99 reports `double_must_use` on `async_trait`-generated futures, so
stay on the pinned toolchain:
`rustup toolchain install 1.98.1 --component rustfmt --component clippy`.

```bash
cargo +1.98.1 fmt --all --check
cargo +1.98.1 clippy --workspace --all-targets
cargo +1.98.1 test --workspace --locked   # 13 tests are #[ignore], opt-in; see AUDIT.md
cargo audit && cargo deny check     # dependency and license policy
```

`crates/pillar-config/src/generated_layerzero_evm.rs`,
`generated_layerzero_environment.rs`, `generated_ton_layerzero.rs` and
`generated_layerzero_legacy_chain_ids.rs` are generated tables — never edit them by
hand. There is one generator per file; the first three read the upstream LayerZero
deployment configuration from the path given by `PILLAR_AUDIT_ROOT`, the last only
the lz-definitions package:

```bash
# gasolina-audit 213cd500 (1.2.66): the app root, not the repository root
export PILLAR_AUDIT_ROOT=/path/to/gasolina-audit/migrated/offchain-monorepo

# per-environment chain capability (1259 entries)
node scripts/generate-layerzero-environment-capability.mjs

# LayerZero endpoint ids and EVM deployments (874 endpoints, 4033 deployments)
LZ_DEFINITIONS_ROOT=/path/to/@layerzerolabs/lz-definitions \
  node scripts/generate-layerzero-static-config.mjs

# TON code cells and deployments (23 cells, 29 deployments)
LZ_TON_SDK_ROOT=/path/to/@layerzerolabs/lz-ton-sdk-v2 \
  node scripts/generate-ton-static-config.mjs

# v1 chain ids as lz-definitions' getNetworkForChainId resolves them (941 ids)
LZ_DEFINITIONS_ROOT=/path/to/@layerzerolabs/lz-definitions \
  node scripts/generate-layerzero-legacy-chain-ids.mjs
```

`LZ_DEFINITIONS_ROOT` and `LZ_TON_SDK_ROOT` accept any extracted copy of the
published npm packages at the versions that tree's lockfile pins, for example
`npm pack @layerzerolabs/lz-definitions@3.1.15` and `@layerzerolabs/lz-ton-sdk-v2@3.0.168`,
followed by `tar xzf`. No other install is needed. The TON generator needs a
*complete* package, artifacts directory included, so use the packed tarball rather
than a partial local copy.

The generated files record the package version and input hashes, so a regeneration
is checked by `git diff --stat crates/pillar-config/src/generated_*.rs` being empty.
That byte-for-byte comparison is the only check that catches an address value
changed in place: `scripts/check-generated-config-integrity.mjs`, which runs in CI,
needs no upstream source and therefore only reconciles each file against the row
counts in its own provenance header.

Benchmarks are opt-in: `cargo bench -p pillar-bench`.

## Security

- Signing a verification for the wrong contract is a security bug, not a
  configuration nit: unsupported `(chain, environment, ULN version)`
  combinations are rejected instead of being approximated.
- Every provider read is decided by the chain's quorum strategy over distinct
  entities. Differing answers never merge, and a read fails closed when the
  strategy is not met or two different answers could each meet it. Health
  reporting is a separate signal: `/provider-health` marks a chain healthy when its
  probed providers were observed healthy, and `/ready` needs only one advertised
  chain healthy. Neither proves that a quorum is reachable for a given request.
- A 5xx is not proof that nothing was signed; see the signing boundary in
  [AUDIT.md](AUDIT.md#4-threat-model).
- The startup report and error paths redact provider credentials, headers and
  key identifiers. Please do not add logging that reverses that.

Report a suspected vulnerability privately to the maintainers rather than in a
public issue. Reviewers start at [AUDIT.md](AUDIT.md): threat model, trust
boundaries, reproduction steps, acceptance evidence and opt-in E2E tests.

## License

MIT — see [LICENSE](LICENSE).
