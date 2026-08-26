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
    `ReadV1002` selects the read builder.
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
  rollout gate (Stellar, above) removes a chain even when both exist. "no"
  returns an explicit error rather than signing a guess, and so does any
  `(chain, environment)` pair with no deployment entry:

  | Destination family | Chain names | Legacy `V2` builder | V3 builder (`V301`/`V302`) | `ReadV1002` builder |
  | --- | --- | --- | --- | --- |
  | EVM, incl. Tron | EVM chain names, `tron` | yes | yes | yes |
  | Move | `aptos`, `initia`, `movement` | yes | yes | no |
  | Sui | `sui`, `iotal1` | no | yes | no |
  | Solana | `solana` | no | yes | no |
  | TON | `ton` | no | yes | no |
  | Starknet | `starknet` | no | yes | no |
  | Stellar | `stellar` | no | yes | no |

  The resolved receive version only changes an outcome where the family's
  builder consults it: EVM and Move select a different receive contract for
  ULN301 than for ULN302, and Solana rejects anything but ULN302. The Sui,
  TON, Starknet and Stellar builders never reference a ULN version. Every
  registered non-EVM endpoint id is an Endpoint V2 id (30000 or above), so
  those resolve to ULN302 in practice — but `dstEid` arrives in the request,
  so that is a property of the deployment tables, not a guarantee in the code.
  `ReadV1002` is EVM-only.

  The IOTA Move chain is named `iotal1`. `LAYERZERO_AVAILABLE_CHAIN_NAMES`
  drops names it does not recognise, so a misspelling silently removes a chain
  rather than failing loudly.
- **Stellar is rollout-blocked on `mainnet` and `testnet`.** Its pinned
  deployment addresses disagree with LayerZero's live metadata on both
  environments, including the trusted endpoint address used for source-event
  filtering, so the chain is excluded from the operational set regardless of
  `LAYERZERO_AVAILABLE_CHAIN_NAMES` — listing it does not enable it. Enabling it
  takes three steps: verify the current deployment on-chain, update the pinned
  data, then remove the gate in `layerzero_rollout_block_reason`. See
  [Known caveats](SECURITY.md#known-caveats).

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
LAYERZERO_SUPPORTED_ULN_VERSIONS='["V2","V301"]' \
PROVIDER_CONFIG_TYPE=LOCAL \
LAYERZERO_PROVIDER_CONFIG='{"bsc":{"uris":["https://bsc-a.example","https://bsc-b.example"],"quorum":2}}' \
SIGNER_TYPE=KMS KMS_CLOUD_TYPE=AWS LAYERZERO_KMS_IDS=arn:aws:kms:...:key/... \
PILLAR_API_AUTH_TOKENS="$(openssl rand -hex 24)" \
./target/release/pillar
```

Startup prints a redacted configuration report (provider URLs, headers and key
identifiers are masked, tokens are shown only as a count) and then binds
`0.0.0.0:$SERVER_PORT`. The process refuses to start if `PILLAR_API_AUTH_TOKENS`
is missing or holds a token shorter than 32 characters.

On `SIGTERM` or `SIGINT` the server stops accepting connections, `GET /ready`
starts answering 503 so the load balancer drops the instance, in-flight requests
drain for up to `PILLAR_SHUTDOWN_GRACE_SECONDS`, and the process exits 0.

### Docker

```bash
docker build -t pillar-client:local .
docker run --rm -p 8080:8080 --env-file ./pillar.env pillar-client:local
```

The image runs as a non-root user, pins its base images by digest, defaults to
`SERVER_PORT=8080`, and health-checks `GET /ready`. Use `GET /` for liveness.

## Configuration

All configuration is environment based. Required:

| Variable | Meaning |
| --- | --- |
| `SERVER_PORT` | TCP port to bind. |
| `LAYERZERO_ENVIRONMENT` | `mainnet`, `testnet`, or `sandbox`/`localnet`. |
| `LAYERZERO_SUPPORTED_ULN_VERSIONS` | Non-empty JSON array. Controls legacy EVM `V2`/`V301` builders only; `V302` and `ReadV1002` remain deployment/capability driven. |
| `PROVIDER_CONFIG_TYPE` | `LOCAL`, `S3`, or `GCS`. |
| `SIGNER_TYPE` | `KMS`, `MNEMONIC`, or `LOCAL_MNEMONIC`. |
| `PILLAR_API_AUTH_TOKENS` | Comma-separated bearer tokens accepted on authenticated routes. Each must be at least 32 characters. |

Provider configuration, by `PROVIDER_CONFIG_TYPE`:

| Variable | Applies to | Meaning |
| --- | --- | --- |
| `LAYERZERO_PROVIDER_CONFIG` | `LOCAL` | Inline JSON map of chain name to `{ uris, quorum }`. |
| `LAYERZERO_PROVIDER_CONFIG_FILE_PATH` | `LOCAL` | Same JSON, read from a file. |
| `CONFIG_BUCKET_NAME` | `S3`, `GCS` | Bucket holding `providers.json`; re-read every 60s. |
| `LAYERZERO_CDK_DEPLOY_REGION` | `S3` | AWS region (defaults to `us-east-1`). |
| `GCP_PROJECT_ID` | `GCS` | GCP project owning the bucket. |

On `S3` and `GCS` the bucket is re-read every 60 seconds and a usable
configuration replaces the one serving, atomically. Every reader of provider
configuration - the signing path, `/provider-health`, `/available-chains` -
moves to the new one together, and anything that has to combine two reads of it
pins one generation for the whole operation: a sign request from start to
finish, and `/ready`, which asks whether any advertised chain is healthy. A read that fails, or one that could
never sign (a chain with no URI, a zero quorum, a quorum above the URI count),
leaves the previous configuration serving and is counted under its own
`pillar_provider_config_refresh_total{result}` label.

What a refresh can change is the URIs and quorums behind the chains this
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
| `PILLAR_MAX_CONNECTIONS` | Concurrent connection cap (default 1024). |
| `PILLAR_SHUTDOWN_GRACE_SECONDS` | Drain budget after a shutdown signal (default 25). |

Production guidance: use `SIGNER_TYPE=KMS`. Mnemonic backends exist for local
development and tests; they keep key material in the process environment.

## HTTP API

JSON responses use a `{ "statusCode": ..., "body": ... }` envelope. Two routes
are not JSON and carry no envelope: `GET /` returns the bare string `HEALTHY`,
and `GET /metrics` returns Prometheus text. Framework-level responses for
unmatched routes are not enveloped either.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/` | public | Liveness; always `HEALTHY` while the process runs. |
| `GET` | `/ready` | public | Readiness: 200 `READY`, or 503 `NOT_READY` while draining or when no configured chain is healthy. |
| `POST` | `/v2/resolve-and-sign` | **bearer** | Resolve the source event and return DVN signatures. |
| `POST` | `/` | **bearer** | Legacy V1 sign entrypoint. |
| `GET` | `/signer-info?chainName=<chain>` | **bearer** | Signer addresses and public keys for a chain. |
| `GET` | `/available-chains` | public | Chain names this instance serves. Fixed for the process lifetime; a refresh changes only the URIs and quorums behind them. |
| `GET` | `/environment` | public | Configured LayerZero environment. |
| `GET` | `/provider-health` | public | Per-chain boolean health. |
| `GET` | `/provider-health/report` | **bearer** | Per-provider detail with a check timestamp. |
| `GET` | `/metrics` | **bearer** | Prometheus text format. |
| `GET` | `/version` | public | Configured image version. |

Authenticated routes require `Authorization: Bearer <token>` where the token is
one of `PILLAR_API_AUTH_TOKENS`; tokens are compared in constant time and every
rejection returns the same `401 Unauthorized` envelope regardless of cause.
Configure the token in your Prometheus scrape job as well.

Readiness is service-level, not per-chain: the instance is ready while **at
least one** configured chain is healthy, so read `/provider-health` for per-chain
availability rather than inferring it from `/ready`. Both are served from one
cache that treats a value as fresh for 15s and, if the refresh fails, keeps
serving the previous value for up to 120s in total — so neither flips the moment
an RPC endpoint dies. Point a Kubernetes readiness probe at `/ready`, not `/`:
`/` is a constant liveness string and cannot express draining or unhealthy
providers.

Clients may send `x-request-id`; it is recorded in server logs and attached to
error extensions, otherwise the server generates one. Note that it is **not**
returned as a response header today, so a caller cannot correlate a failure
response with a server log line on its own.

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
- `pillar_provider_request_errors_total{chain,kind}` — provider RPC failures;
  `kind=quorum` means quorum was not reached for that chain

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo audit && cargo deny check     # dependency and license policy
```

`crates/pillar-config/src/generated_layerzero_evm.rs` and
`generated_ton_layerzero.rs` are generated tables — never edit them by hand.
Regenerate them with the scripts in `scripts/`; they read the upstream
LayerZero deployment configuration from the path given by `PILLAR_AUDIT_ROOT`:

```bash
# LayerZero endpoint ids and EVM deployments
PILLAR_AUDIT_ROOT=/path/to/upstream/source \
LZ_DEFINITIONS_ROOT=/path/to/@layerzerolabs/lz-definitions \
  node scripts/generate-layerzero-static-config.mjs

# TON code cells and deployments
LZ_TON_SDK_ROOT=/path/to/@layerzerolabs/lz-ton-sdk-v2 \
  node scripts/generate-ton-static-config.mjs
```

`LZ_DEFINITIONS_ROOT` and `LZ_TON_SDK_ROOT` accept any extracted copy of the
published npm packages, for example `npm pack @layerzerolabs/lz-definitions@3.1.2`
followed by `tar xzf` — the generated files record the package version and input
hashes so a regeneration can be checked byte for byte.

Benchmarks are opt-in: `cargo bench -p pillar-bench`.

## Security

- Signing a verification for the wrong contract is a security bug, not a
  configuration nit: unsupported `(chain, environment, ULN version)`
  combinations are rejected instead of being approximated.
- Provider quorum is enforced per chain; a chain is only healthy when every
  configured provider answers.
- The startup report and error paths redact provider credentials, headers and
  key identifiers. Please do not add logging that reverses that.

Report a suspected vulnerability privately to the maintainers rather than in a
public issue.

## License

MIT — see [LICENSE](LICENSE).
