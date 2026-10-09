# Security Policy

## Scope

This repository contains a LayerZero DVN client that holds signing authority.
A defect here can produce a valid signature over an attestation the operator did
not intend, so we treat correctness bugs in the following areas as security
issues, not ordinary bugs:

- source-event resolution and trusted-emitter filtering
  (`crates/pillar-runtime/src/layerzero_runtime/packet_resolver.rs`)
- request-to-packet binding and chain/environment resolution
  (`crates/pillar-runtime/src/layerzero_runtime/**`, `crates/pillar-core/src/lib.rs`)
- destination ULN call-data construction, per chain family
  (`crates/pillar-layerzero/src/**`)
- signer backends, key selection and signature normalisation
  (`crates/pillar-signer/src/**`)
- provider quorum accounting (`crates/pillar-runtime/src/provider_health/**`)
- anything that causes provider configuration, deployment addresses or endpoint
  ids to be selected for the wrong environment

## Reporting a vulnerability

Report privately. Do not open a public issue, and do not include a working
exploit against a production deployment.

Use GitHub's private vulnerability reporting for this repository:
**[Security → Report a vulnerability](../../security/advisories/new)**. The
report stays private to the maintainers until an advisory is published, and it
gives us a place to coordinate a fix and a CVE with you.

- Include: affected version or commit, configuration needed to reproduce, the
  observable impact, and whether a signature can be produced or forced
- Acknowledgement target: 2 business days; triage decision: 5 business days
- Credit: tell us the name or handle you want in the advisory, or that you
  prefer none

If you believe a production key or attestation is already affected, say so in
the first line of the report so it can be escalated before analysis.

## Operator responsibilities

The following are deployment-side controls the software cannot enforce for you:

- Keep `PILLAR_API_AUTH_TOKENS` secret and rotate it on staff changes. The
  signing endpoints authorise on that token alone, unless you set
  `PILLAR_PUBLIC_SIGN_ROUTES=true`, in which case they authorise no caller at
  all: anyone who can reach the port can spend your signer. Set it only where
  LayerZero DVN traffic must land, and keep the rate limiting and network
  controls in front of it accordingly. `/signer-info`,
  `/provider-health/report` and `/metrics` stay behind the token in both modes.
- Never expose the service directly to the public internet. Terminate TLS in
  front of it; the process speaks plain HTTP by design.
- Use `SIGNER_TYPE=KMS` in production and scope the KMS key policy to this
  workload only. Mnemonic backends keep key material in process environment.
- Require at least two distinct entities for every chain's `rpc` strategy, for
  example `{ "allOf": [{ "any": 2 }] }`. A strategy that one entity can satisfy
  makes that operator the trust root for the event you attest to; the startup
  report flags such chains as `single-provider-trust-root`.
- Label entities truthfully. Votes are counted per `(category, entity)` as
  upstream `gasolina-audit` `213cd500` counts them
  (`packages/common-utils/src/multiFallbackQuorum.ts:107-147`), so two URIs of one
  entity are one vote; but the labels are yours, and two URIs of one operator
  under two entity names are counted twice. Differing answers never merge: if two
  answers could each meet the strategy the call fails closed, which is stricter
  than upstream's first-satisfied resolution.
- Provider configuration differs from upstream `213cd500` where it would
  otherwise weaken or silently misread a quorum: unknown fields are refused, except
  the `_`-prefixed top-level documentation keys upstream passes through in
  `quorum-strategy.json` (`dynamic-config/src/providerConfig/index.ts:102-104`), so a
  misspelled `allOf` cannot become an empty requirement; a strategy that zero
  entities satisfy (`{}`, `{ "any": 0 }`) is refused (upstream treats the empty
  strategy as trivial); only the `rpc` pool is dispatched, so upstream's TON
  `v2`/`v3`, Aptos/Initia `eventIndexer`, Sui `grpc`/`graphql` and TRON `tronWeb`
  pools are still not used as secondary provider pools; for `sui`, operators must
  point each `rpc` URI at GraphQL instead of JSON-RPC. The GraphQL query path
  retains the configured provider quorum and exact-value fingerprint checks. This
  is a deliberate divergence from upstream gasolina, which still uses `sui_*` and
  `suix_*` JSON-RPC, forced by Sui Foundation's decommission of fullnode JSON-RPC.
  GraphQL errors, null data and JSON-RPC error envelopes are provider failures:
  they never vote on events, transactions or objects, and where readiness and
  timestamp checks record missing data they count as `Missing`, as any unavailable
  provider does. Providers observed unhealthy are dispatched last instead of
  dropped. A live mainnet capture showed that `simulateTransaction` still succeeds
  with a wrong shared `version`, so that field is advisory (fixture:
  `sui-mainnet-graphql-shared-version.json`).
  Event `vector<u8>` fields are read as GraphQL renders them, base64 (or an explicit
  `0x` hex string); upstream's JSON-RPC digit-string options form is not accepted on
  the Sui GraphQL path and fails that provider's answer.
  Configuration errors name the file, the JSON line and column, schema field names, and only
  chain, endpoint-type and category names this build defines; an unknown key, an
  entity, a header or any other value from the file appears as a placeholder or
  not at all, because a misplaced credential would otherwise reach startup errors
  and refresh logs.
- The signed `vId` is the destination's EndpointV1 id where one exists, otherwise its
  EndpointV2 id modulo 30000. Upstream `213cd500` folds the V2 id for every chain
  (`static-config/src/index.ts:191-195`), which differs on testnet `doma`, `lineasep`,
  `scroll` and `zksyncsep` (and on no mainnet chain). The deployed LayerZero Labs DVNs
  on `doma`, `lineasep` and `zksyncsep` return the EndpointV1 id from `vid()`
  (`crates/pillar-runtime/tests/onchain_provenance/dvn_vid.json`); `scroll` could not be
  read on chain and keeps its EndpointV1 id as an unconfirmed corrected input.
- Alert on `pillar_provider_config_age_seconds` (stale provider configuration),
  `pillar_provider_config_refresh_total{result!="ok"}`,
  `pillar_signer_errors_total` and `pillar_provider_request_errors_total`.
- Rate-limit signing routes upstream of the process. Fair signing/RPC/KMS budgets
  bound active work and waiting registrations, but are per process and are not
  fleet-wide rate limits. RPC permits account for the actual target chain rather
  than the source label; KMS permits are counted per supplied key reference
  string (for Azure signing, the resolved key reference), not per physical key.
  The CLI remains HTTP/1.1-only with `PILLAR_MAX_CONNECTIONS` (default 1024) and
  one 58s absolute request deadline. A deadline closes the connection without an
  HTTP timeout envelope. Local overload/wait failures retain legacy 500 envelopes
  and are admission outcomes, not provider-health/quorum or signer backend faults.
- Decide deliberately which routes your ingress publishes. `GET /`,
  `GET /ready`, `GET /environment`, `GET /available-chains`, `GET /version` and
  `GET /provider-health` require no credential by design. The chain roster and
  the per-chain health map tell a reader which pathways this DVN serves and
  which of them it currently cannot verify on.
- Point the readiness probe at `/ready`, not `/`. `/` remains a constant
  liveness response (`200 HEALTHY`) during drain, while `/ready` returns 503
  from T0. The listener continues accepting until E = T0 +
  `PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS`; this interval is carved out of, not
  added to, the total `PILLAR_SHUTDOWN_GRACE_SECONDS` ending at D = T0 + G. Set
  the orchestrator termination grace period longer than G. Kubernetes
  SIGTERM/preStop behavior has not been exercised, so withdrawal races are
  reduced rather than eliminated.
- Give the Prometheus scrape a token. `GET /metrics` is authenticated, so a
  scrape job without `Authorization` receives 401 and monitoring goes dark.
- Serve `ReadV1002` targets from providers that implement EIP-1898 block
  parameters with `requireCanonical`. Every READ `eth_call` is pinned to the
  block hash readiness validated and is never retried by number, so a provider
  that rejects the object form cannot vote, and a chain whose providers all
  reject it cannot be read. Probe every endpoint, and any proxy in front of it,
  before routing READ traffic: an `eth_call` with
  `{"blockHash": <a recent canonical hash>, "requireCanonical": true}` must
  return a result, and the same call with an unknown hash must return an error.
  Reth answers both ways as required; on public mainnet Reth endpoints the
  unknown hash returns `block not found: canonical hash ...`.

## Durable signing audit (default disabled)

`PILLAR_AUDIT_ENABLED=false` is the default. Enabling it preserves synchronous
`{statusCode, body}` responses: there is no 202, cached signature, replay,
exactly-once claim, recovery engine, or permanent generic nonce lock.

Each wallet attempt follows these gates:

1. Complete ordinary request validation and payload construction. Bind the
   canonical caller request hash, validated event/read-block-pin fingerprint,
   provider configuration generation, chains, expiry, immutable effective key
   reference/version and public-key fingerprint to the actual transformed
   32-byte signer input. Missing or conflicting identity fails closed.
2. COMMIT the retained attempt before the SDK signing future can be polled.
   Namespace quota and identity conflicts are checked transactionally; concurrent
   cold starts serialize schema setup. No database lock is held across signing.
3. COMMIT returned-signature fingerprints and result metadata before 200. Any
   wallet or evidence failure returns the legacy error envelope, never partial
   signatures. Store admission/connect/write failures never authorize an effect.

The store retains hashes and identity metadata, not raw signatures, READ command
bytes or debug payloads. `external_returned` fingerprints are Keccak256 of raw
SDK-returned bytes; `wallet_returned` fingerprints are Keccak256 of the UTF-8
rendered signature field. These are different domains and are not interchangeable.
SDK bytes returning is not proof of a valid attestation or HTTP delivery.

An attempt without positive completion evidence is unresolved, not proof that no
signature exists. Caller drop records `outcome_unknown`; a bounded, runtime-owned
worker can append late evidence while holding the physical KMS permit. Dropping
the runtime aborts unfinished workers without asserting remote failure. Audit-on
disables Azure hedging. A fresh retry repeats validation and appends a new attempt;
it neither deletes old uncertainty nor returns a retained signature. The same
caller request and immutable key identity cannot silently change its signing
input/public key; a different immutable key version has a distinct intent.

Configuration is listed in `README.md`. PostgreSQL operations have bounded
connect/lock/COMMIT deadlines and explicitly use `synchronous_commit=on`.
Session-queue timeout refuses only that waiter. After acquiring the mutex, an
operation timeout/unavailable response invalidates only its owned session generation
and aborts that driver; a subsequent operation reconnects.
Session startup sets server lock, statement and idle-transaction timeouts plus TCP
keepalive/user timeouts. Remote DSNs use `sslmode=require` with rustls hostname
and WebPKI-root certificate verification; tokio-postgres does not accept
`verify-full` or `verify-ca` DSN spellings here. Plaintext is limited to literal
loopback addresses or Unix sockets, and every `hostaddr`, which tokio-postgres
dials in place of `host`, must also be literal loopback. The DSN is redacted; credentials must not be
placed in logs or release artifacts. `PILLAR_AUDIT_MAX_ATTEMPTS` is a retained-row
quota, not a byte/disk quota. There is no TTL, automatic cleanup or reconciliation.
Unknown and partial attempts must survive any operator-approved retention plan.

Each process serializes audit writes through one session mutex. Readiness uses a
second, separate connection, so a probe never holds the write session; probes
queue for that one readiness connection, and the whole probe (waiting, connecting
and querying) shares one `PILLAR_AUDIT_TIMEOUT_MS` budget. A probe whose budget runs
out while it waits does not dial. A cancelled or timed-out probe drops its
connection. Participating
replicas also serialize namespace quota updates on one PostgreSQL row; KMS
execution holds no such row lock. There is no measured production TPS, capacity
calibration, pool, pruning or automatic quota reset. The permanent row cap is not
a sustainable retention policy: absent an approved archival/retention procedure,
audit-on eventually exhausts it and refuses signing/readiness. Keep audit off
until operators verify peak latency/throughput, lock contention, disk/WAL growth,
namespace quota lifetime and a retention plan preserving unknown attempts.

Startup refuses inaccessible stores or unresolved signing identities. Audit
capacity/connectivity also gates `/ready`; `pillar_signing_audit_enabled` and
`pillar_signing_audit_ready` expose the configured mode and last observed store
state. Readiness probes check reachability/capacity, not every write permission or
future COMMIT: a read probe can become healthy after a write-only failure, while
the actual sign still fails closed. Do not use readiness as a durability certificate.

Before any separately approved production activation, establish database
permissions/schema ownership, disk/WAL capacity, backups, failover durability and
retention; exercise write failures and immutable identity binding against that
deployment. A primary COMMIT does not prove synchronous replica failover safety,
and application append-only writes are not administrator-proof immutability.
Do not mark a rollout fully audited while old audit-off replicas still serve work.
To roll back, drain signing traffic and switch the mode off without deleting
evidence; subsequent audit-off effects will not have these guarantees.

Real PostgreSQL E2Es cover pre-COMMIT failure, post-effect evidence failure,
multi-wallet partial failure, same-namespace quota races, unresolved/conflicting
identity, process crashes, caller drop, late completion, and runtime-owner drop.
They run `RuntimeServerApp` validation/build/control/store and the API router on
a test `axum::serve` listener, not the CLI socket driver, with a synthetic
Azure SDK seam and local software ECDSA, not real cloud KMS. They are `#[ignore]`
and opt-in (`AUDIT.md` section 6); CI does not run them. Live peak calibration,
production database permissions/HA and live cloud-wire retry behavior remain
unverified.

### Admission accounting and bounded waiting

The three budget metric labels are `sign`, `rpc`, and `kms`; metric labels do not carry
chain/URI/key values. `pillar_admission_started_total` equals all terminal
`pillar_admission_total{outcome}` plus `pillar_admission_active` and
`pillar_admission_waiting` in a coherent snapshot. Started external work abandoned
by a caller, a losing hedge or shutdown is `outcome_unknown`, not cancellation.
An unstarted speculative hedge increments `pillar_kms_hedge_skipped_total` instead.

With shared waiting allowance Q and N fixed lanes, the global waiting bound is
Q + N: each quiet lane may reserve its first waiting registration beyond Q, while
its per-lane queue cap still applies. Q=0 disables both waiting and reservations.
There are source lanes plus one KMS background lane, or RPC background and
extra-context lanes. Background RPC rounds own a finite 10s deadline independent
of the caller that noticed staleness; stale/failed admission does not overwrite
cached healthy reports. Custom target/key caps of one cannot reserve a second
physical foreground slot; calibrate all caps together. SDK retries are disabled;
the optional audit-off Azure hedge is an explicitly budgeted second attempt.

Both successful GET/HEAD terminal records use debug level. Error records remain
visible and use fixed classifications, never caller-controlled message hashes.

## Where responses still differ from upstream

Requests are answered as `gasolina-audit` 1.2.66 (manifest sha256 `8ad87eb6…`)
answers them - status, body and order - except in these cases, each kept because
it protects credentials, authentication, signing keys or the payload being signed,
because the input cannot be represented, because a dependency is unavailable, or
because it is HTTP-framework behaviour of Express and Node that this service does
not reproduce:

- Authentication is available and on by default; the mainnet deployment turns it
  off (`PILLAR_API_AUTH_ENABLED=false`, ingress allowlist), where no route differs.
- A `srcTxHash` outside `[0-9a-zA-Z_-]{1,128}` (optional `0x`) is a 400 just before
  the source read, after every RPC-free check upstream makes except its V1-sdk
  factory errors for a `V2` request (`Unknown ULN version`, `Unsupported chain
  type`), because Move and TON splice it into a provider URL path. Every chain's
  real transaction id passes; upstream sends such a value to its provider and
  returns whatever it answers.
- Fields the typed request cannot hold are a serde 400 where upstream carries on:
  a non-integer number in any v2 integer field (`nonce`, `expiration`,
  `blockConfirmation`, time-marker fields), a negative `nonce`, an out-of-range
  number; on the v1 route a `nonce` JavaScript reads as NaN, negative or past
  2^64 (`lzMessageId.nonce ... is not a uint64`), and a wrong JSON type for
  `srcTxHash`, `expiration`, `blockConfirmation`, `messageHash`, `dvnAddress` or
  `skipVId`. Numbers are otherwise read as `JSON.parse` reads them (`7.0` is 7,
  integers past 2^53 round), and v1 chain ids, nonce and addresses take
  upstream's own `parseInt`/`toString` coercions. An unknown v1 chain id is
  refused as HTTP 400 with the unchanged `Invariant failed: Invalid endpointId: <n>`
  message, rather than upstream's 500, during request conversion and before any
  provider RPC; an object-valued v1 sender or receiver is echoed in error bodies
  with sorted keys, where `JSON.stringify` keeps insertion order.
- `skipVId: true` is refused with HTTP 400 on both signing routes (`POST /`,
  `POST /v2/resolve-and-sign`) before any provider read, except on the v2 route
  for a `V2` send to `aptos`; upstream signs a digest without the vId everywhere.
  The DVN source in `lz-evm-sdk-v2` always hashes the vid and skips a mismatching
  one, so on that verifier such a signature is void; other verifiers are
  unverified. The builders refuse it again on every route but that one.
- A `V2` send from an EVM source to an `aptos` receiver still on ULN V2 is signed
  as upstream signs it, with `skipVId`: `hashPropose(sha3_256(packet), confirmations,
  expiration)` for the V1 oracle, the bare V1 packet being Aptos's feather proof of
  utils version 2. Served only for the two pinned oracles (mainnet
  `0xc2846ea0…94eb`, testnet `0x8ab85d94…6c63`) with the packet naming that oracle's
  EndpointV1 id (108 / 10108), a 32-byte receiver and a 20-byte EVM sender; anything else
  is a 400 before the signer. Routing reads `endpoint_view::get_receive_msglib` as
  upstream does (`(2, 0)` is ULN301, otherwise ULN V2). The digest layout agrees
  with a static decoding of the deployed oracle module; that the oracle accepts
  the signature on chain has not been observed, and it verifies secp256k1 only,
  so a local-mnemonic (Ed25519) signature could not pass it.
- The Solana signer address equals upstream 1.2.66 for a mnemonic, AWS or GCP key:
  `base58` of the first 32 bytes of SEC1 `04‖X‖Y`. For an Azure key this service
  answers `base58(X)` (`signer_address_for_provider`,
  `crates/pillar-signer/src/chain_address/chains.rs`). Upstream 1.2.66 has no Azure
  adapter, so there is no upstream value to compare. On 2026-10-08, a read-only
  probe matched the immutable Azure key version public key, the operating Pillar
  signer public key and the finalized Solana DVN config signer as 64-byte `X||Y`.
  The config slot was `454395711`; its owner is executable and upgradeable, with
  program-data deployment slot `432734589`. The deployed program has not been
  reproducibly linked to source, and no live Azure KMS signature or on-chain
  signature verification has been observed. Audit closure of Azure-backed Solana
  binding requires these three evidence classes. The address is a response label,
  not the Solana DVN config account address; public-key and signature bytes are unchanged.
- Error bodies also mask AWS ARNs and GCP key-ring paths; URL masking is upstream's.
- Extra-context policies must answer the boolean `true` (only when configured).
- ReadV1002 reads are pinned to the validated block hash, source receipts are
  re-bound at readiness, and the EVM receive library is checked even without a
  `dvnAddress`. Outputs differ on a reorg, an unsupported receive library, an RPC
  failure inside those extra reads, or a READ provider without EIP-1898.
- A `V2` send's receive library is read before resolution over the requested
  pathway, as 1.2.66 does, but by exact provider quorum over the library address;
  a provider disagreement is a 500. Unknown libraries and endpoint-rejected
  overrides are upstream's own 500s, and every recognised non-V3 library keeps the
  V2 builder.
- A ULNv2 feather proof is signed only when the destination proof library's
  `getUtilsVersion()` is 1, and then as `bytes32(packetEmitAddress) || packet`.
  Every `FPValidator` deployment in `@layerzerolabs/lz-evm-sdk-v1` 3.1.15 that
  ships source (414 of 429, three source variants) hard-codes
  `utilsVersion = 1` with no setter and reads the first 32 bytes of the proof as
  the `ulnAddress` that `UltraLightNodeV2.validateTransactionProof` requires to
  equal `ulnLookup[srcChainId]`; the 15 zkSync-family deployments ship none. Any
  other value is a 400 before anything is signed. Upstream's `getFeatherProof`
  signs the bare packet for 2 and throws for anything else; 2 has no deployed
  verifier source, so its meaning cannot be checked and it is not imitated.
- A trusted `PacketSent` whose destination EID this deployment cannot name is a
  non-match, so a later event in the same transaction can still resolve. Move,
  Sui, IotaL1, Starknet and Stellar consult the chain-name map and then the legacy
  cross-stage table, where upstream raises a 500 `Invariant failed: Invalid
  endpointId`; EVM, Solana and TON consult the map only, as before. No pathway to
  such a destination can be signed here, so skipping it never admits a packet the
  request did not name. A missing source EID, or a Move/Sui event whose source maps
  to another chain, stays an `Internal` fault but is reported only when no event
  matches; on EVM this was a 400 miss before, and on TON it aborted the scan. EVM
  `ReadV1002` applies the source rule to the emitting chain after the endpoint
  flip. Move, Sui, IotaL1, Starknet and Stellar still convert every event before
  matching, so any other conversion error fails the read as upstream does. TON's
  decoder still drops destination-unmapped events before the source check, so a
  source-EID gap on such an event shows as a miss. The Aptos V1 `OutboundEvent`
  path (`resolve_aptos_v1_packet`) keeps upstream's behaviour unchanged.
- A resolved packet must also agree with the request's destination chain name,
  and, except on Aptos, Movement and Initia sources, with its `ulnSendVersion`
  and source chain name; upstream's `lzMessageIdMatches` compares only eids,
  sender, receiver and nonce. On Aptos, Movement and Initia sources the
  requested version already picks the event token, and the event's version is
  read from its `send_library` as upstream reads it
  (`lz-v2-sdk/src/endpoint/aptos/decoders/index.ts:123`); a Movement `V301` send
  is refused before any read, Movement having no V301 capability. On Sui and
  IotaL1 a version disagreement (a `V301` request, or an event without
  `send_library`) and a packet version other than 1 are refused where upstream
  resolves; on Starknet and Stellar a `V301` request for their always-`V302`
  packet is too, and on Stellar only a `CONTRACT` event is read where upstream
  also reads a host `SYSTEM` event.
  On an EVM source a `V301`/`V302` mismatch answers the same either way:
  upstream searches the logs of the send contract the requested version names
  (`SendUln301` for `V2`/`V301`, `EndpointV2` for `V302`/`ReadV1002`;
  `lz-v2-sdk/src/endpoint/evm/index.ts:200-209`), so a `V301` request for a
  `V302` packet is its 400 `cannot find packet event ...` too. Outputs differ
  where upstream finds the event anyway and builds with the requested version:
  `V302` and `ReadV1002` swapped on an EVM source (both `EndpointV2` logs), and a
  `V301` label on a Solana source, whose sdk ignores the label and whose `V301`
  and `V302` builders are one object, so upstream signs what the `V302` request
  would. A `dstChainName` other than the packet's destination is refused because
  upstream builds call data for the packet's chain but picks the signer, the
  expiration check and the duplicate-signature query by the request's name
  (`apps/gasolina/src/app/app.ts:498-507,525`).
- Sender and receiver are compared with `===` against upstream's own rendering
  of the packet's addresses (`getAddressEncodedByChain`), except that an EVM- or
  TRON-rendered address whose upper 12 bytes are not zero is refused, where
  upstream keeps only its last 20 bytes. This is a policy choice, not a protocol
  requirement; see the receiver-narrowing entry below.
- An EndpointV2 `PacketSent` whose send library is a receive library
  (`ReceiveUln302`) is a 400 here: EndpointV2 events are bound to send libraries
  only. Upstream's `MESSAGE_LIB_GETTERS` also lists receive libraries
  (`lz-v2-sdk/src/endpoint/evm/decoders/index.ts:49-74`), so it resolves the
  event as `V302`. Not expected from an honest send, since EndpointV2 sets only
  send-capable libraries (inferred, not executed).
- The extra-context request body is built with `serde_json::json!` without
  `preserve_order`, so its object keys are sorted; upstream sends them in
  insertion order. The replays compare content, not key order. A policy that
  compares the raw body text would see a difference.
- Solana `PacketSent` events from a send library other than the configured ULN are
  skipped; upstream has no such filter. Upstream also re-reads the block (failing
  with `Block not found` when the node has no such block); this service does not.
- Stellar and Canton: Stellar pins upstream's generation-two contracts and refuses
  per request should LayerZero's published deployment ever disagree; its
  already-signed reads follow the contract source with stellar-sdk 16.0.1
  encodings, because upstream's own Stellar bindings are not generated in the
  1.2.66 snapshot and could not be run. Canton's sequencer path (provider entry,
  committee verification, source resolution, readiness, already-signed) replays
  upstream's own run of it (`tests/gasolina_parity/canton_sequencer.json`), except:
  the extra-context sender of a Canton source follows the published `common-canton`
  1.2.66 source (ledger read, `createTokenProvider`, OAuth2 client credentials with
  its in-memory cache), tested only with a synthetic ledger, identity provider and
  token. It refuses (500) before any request when the `rpc` URI lacks `token-url`
  or `client-id`, or no `client-secret`/`CANTON_CLIENT_SECRET` is set, and always
  on `sandbox`/`localnet`, where upstream would self-sign an admin JWT. A token
  response without `access_token` is refused, where upstream would send the ledger
  request with no token. Prefer `CANTON_CLIENT_SECRET` to a URI `client-secret`. A
  scan event's
  `options` are kept as given, so a malformed blob upstream's `Options.fromOptions`
  rejects resolves here, and a malformed `encodedPayload` fails with this service's
  packet-decoder text; a sequencer body `JSON.parse` accepts but serde does not
  (lone-surrogate escapes, nesting past 128, numbers beyond a double) is the
  `HTTP <method> failed` error; the request deadline is this service's, not
  upstream's 30 s; and Canton's provider health is not measured. On the Move family,
  ULN V2 is refused as a destination except as described above for `aptos`
  (movement and initia have no V2 upstream; with a vId upstream answers its 500
  `VId is not supported on aptos yet`, as this service does), and a `V301` source on Initia or
  Movement is refused (no EndpointV1 id). Aptos `V301` resolves as a source and,
  through EndpointV1 id 108/10108, as an EVM `V301` destination whose already-signed
  check matches upstream's own chain read for read over offline scenarios. Its reads
  use the argument types the public Aptos fullnodes accept and decode responses recorded
  from them; no signing request has run against a live node, and the recorded
  verification-state answers are for a synthetic packet header. A non-ULN301 receive
  library on that path is a 400 where upstream throws. None of them is in the mainnet
  roster. An Initia event whose `data` is not JSON is a 500 on both sides, but the
  text here is `Invalid JSON in event data: ...`, not V8's `JSON.parse` message.
- Solana source reads ask for transaction version 1; upstream's default (0)
  makes its provider reject a v1 transaction.
- `GET /ready`, HTTP/1.1-only connections, deadlines, the shutdown drain and the
  KMS same-source limit act only during shutdown, overload or misuse.
- The roster is `LAYERZERO_AVAILABLE_CHAIN_NAMES` at startup; upstream uses every
  key of the provider configuration as it refreshes.
- HTTP framework errors keep upstream's status but not its body: a malformed or
  non-object JSON body, an unsupported charset or content encoding and a body
  over 100 KiB get a JSON envelope instead of Express's HTML stack-trace page, and
  a `{ "body": "..." }` envelope whose string is not JSON is a 500 carrying serde's
  message, not V8's.
- Body reading follows Express 5.1's `express.json()` (body-parser 2.2.2, iconv-lite
  0.7.2) in order and outcome (`crates/pillar-api/fixtures/http_framework_golden.json`:
  an unparsed body leaving `req.body` undefined, gzip, deflate, multi-member and
  corrupt streams, the 100 KiB limit on inflated bytes, every iconv-lite `utf-*`
  decoder, BOMs, charset and encoding refusals) except: a `br` body is always a 400,
  because no brotli decoder is available here, where upstream inflates a valid one; the
  compressed bytes themselves are also capped at 100 KiB, which upstream does
  not do (a body that only gzip header padding makes larger is a 413 here); a
  gzip `FNAME` or `FCOMMENT` over 65,535 bytes is a 400 (flate2's header bound)
  where upstream accepts it; a stream that inflates past 100 KiB and then fails
  its checksum is a 413 here, where upstream answers 400 when the failure falls
  in the 16 KiB zlib output round that crosses the limit;
  `utf-16` without a BOM is told apart on the first 64 bytes of the whole body,
  where upstream uses its first network chunk of at least 16 bytes; a lone UTF-16
  surrogate becomes U+FFFD, and a lone-surrogate `\u` escape or nesting past 128
  levels, which `JSON.parse` accepts, is a 400 (serde's recursion bound);
  a UTF-7 body is decoded as one chunk, where upstream's per-chunk base64
  carry and BOM stripping follow network chunk boundaries;
  `Content-Type` parameters are not held to media-typer's grammar
  (`application/json;` is parsed here, ignored upstream; obs-text there makes the
  header absent here); and only the two signing routes read a body at all, where
  upstream parses every route's body before routing (a malformed body on
  `GET /signer-info` is a 400 upstream).
- Routing is axum's, not Express's: paths are exact and case-sensitive (Express
  also matches `/V2/Resolve-And-Sign` and a trailing `/`), a known path with
  another method is a 405 instead of Express's 404, there is no automatic
  `OPTIONS` answer, and responses carry no `ETag` nor answer a conditional
  request with 304; an unknown path is a 404 without Express's HTML page.
- `/metrics` exposes this service's `pillar_*` families, not upstream's `gasolina_*`
  (`CHANGELOG.md`, 2.1.0), and response headers differ: no `X-Powered-By: Express`,
  no Node `Keep-Alive: timeout=60`, and a 405 carries `Allow`.
- [unverified] Upstream's V1-sdk constructor also loads ULN V2 and Endpoint V1
  deployment artifacts for a `V2` request's EVM or TRON source; a roster chain
  without them would fail there before RPC, where this service reads the source.

## Known caveats

These are known, unresolved weaknesses. They are documented here rather than in
an issue tracker because each one can change whether a signature is correct.

### Which upstream tree the `TS:` citations refer to

This workspace ports an upstream TypeScript service, and its source carries 39
citations of the form `TS: <path>:<lines>`. They all refer to one tree: the one
whose `packages/static-config/src/chainNames/{mainnet,testnet,sandbox}.ts` hash
to the three `sha256` values in the provenance header of
`crates/pillar-config/src/generated_layerzero_environment.rs`. The upstream
source is not a published package, so content hashes are the identity — quoting
those three values is how you confirm you are reading the bytes these citations
were written against.

This matters because a claim about "upstream" is only as good as the tree it was
read from. Two behaviours are absent from the tree identified above and present
in the later snapshot `gasolina-audit` `213cd500`
(`apps/gasolina/src/app/app.ts:254-273`,
`packages/dynamic-config/src/providerConfig/index.ts:21-95`): the entity/category
provider trust model, and the switch of the hash-call-data builder from V2 to V3
when a ULN V2-sent packet's destination receiver has migrated. This service
implements both: the builder switch (see the `V2` send bullet under "Where
responses still differ from upstream") and the entity/category trust model of
`providers-v2.json`.

### Stellar deployment addresses

The pinned Stellar contracts are generation two: the values upstream 1.2.66's own
contract getters name, which are also the values LayerZero's deployment metadata
publishes. Older upstream packages named generation one, which disagrees with that
metadata.

| Value | mainnet | testnet |
| --- | --- | --- |
| ULN302 | `CCV4HEII3UC65THWGSRM2DVIJLB6HS6YMUHDTTHUECX2RHTP5FA2GOBA` | `CCMLPCAWCPIIMXOHJJKU3NZLOFTT2O6QTB2UUFPN6SEHLK35QRHVKKMB` |
| EndpointV2 (trusted emitter) | `CCQLLRE5JBAWYCW3KTWOIWLMFDUOKROQVZNSALQMGOSXNW3ERUOWTZGK` | `CALTBA5S6GRJEHAXFP45LGGLKWWAF7HTZCPNUBUJF2HWWRRLQNV35AIV` |
| LayerZeroViews | `CBCH6XLCAVY2KPWGJYDY4ATDHMJCNLISINKB5JAOHPAAXZXLTBMU43ZB` | `CAWX6SA2NX7HD2IBAARR5KP65C47N4GCCTWXTPZ7KH2WIGUOFQGS3ZHO` |

The ULN302 id is hashed into the attestation, so a guard remains: should the
published deployment and the pinned table disagree, the destination builder
refuses per request (`stellar_pins_equal_the_published_deployment_where_one_exists`
checks that they agree). `layerzero_rollout_block_reason` does not block Stellar;
it blocks only `moninet` and `ton`, both on `testnet`. For TON testnet, a delivered
packet on a `UlnConnection` was read with a `VERIFIED` verdict and offline tests
replay it; the gate stays until the operator decides the rollout.
Confirm with:

```bash
curl -s https://metadata.layerzero-api.com/v1/metadata/deployments \
  | jq '."stellar-mainnet".deployments[] | {version, eid, endpointV2, sendUln302, receiveUln302}'
```

Addresses live in `stellar_uln_302_for_environment`,
`stellar_endpoint_v2_for_environment` and `stellar_layerzero_views_for_environment`
(`crates/pillar-runtime/src/layerzero_runtime/config/evm.rs`).

### Other known gaps

- The TON DVN verify fixtures **are** reproduced from upstream's own
  implementation:
  `crates/pillar-layerzero/tests/gasolina_parity/ton_dvn_verify.json` holds the
  output of upstream's `buildDvnVerifyCallData`, `buildULNCallData` and its two
  address constructors, regenerated by
  `scripts/gasolina-parity/emit-ton-dvn-verify.ts`. What is still not covered is
  a run against a live upstream *service* over live RPC, and the TON quorum
  fetch's own consensus rule, because both sides are fed the same recorded proxy
  state.
- `movement` currently resolves to the same Move addresses as `aptos` on both
  environments. That is what the pinned upstream deployment artifacts publish,
  and the tables deliberately keep separate rows so a future Movement
  deployment cannot silently alias Aptos
  (`crates/pillar-runtime/src/layerzero_runtime/config/non_evm.rs`). If
  Movement redeploys, this repository will keep signing against the Aptos
  addresses until the tables are regenerated.
- ULN `ReadV1002` is EVM-only. TON and Starknet read paths return an explicit
  error rather than a signature
  (`crates/pillar-layerzero/src/other_non_evm/ton/mod.rs`,
  `crates/pillar-layerzero/src/other_non_evm/starknet.rs`).
- On EVM the *signing target* is derived from the destination endpoint id -
  below `30000` means ULN301, otherwise ULN302
  (`evm_receive_version_from_dst_eid`, `crates/pillar-layerzero/src/evm.rs`).
  That matches upstream, which derives it the same way
  (`apps/gasolina/src/app/sdks/gasolinaSdk/evm/index.ts:137-145`).
  The payload-already-signed check does not derive it: it reads the receiver's
  actual receive library from the destination endpoint, and refuses when that
  library is not `ReceiveUln302`, `ReceiveUln301` or `ReadLib1002`, or when a
  non-default one fails `isValidReceiveLibrary`. Each provider resolves the
  library itself and the quorum agrees on the library as well as on the
  verdict, so one compromised RPC cannot redirect the check to a contract of
  its choosing.
  The derived version alone would read the wrong contract for an OApp on a
  non-default library, which is why the check reads the actual library.
  Two consequences to know before deploying:
  - A receiver on a message library outside those three is refused, not signed.
    That is deliberate - the service cannot tell whether such a payload is
    already verified - but an OApp on a custom library will get errors rather
    than signatures. The exception is a `V2` send to a receiver still on
    UltraLightNodeV2: the routing lookup has already agreed on that library, and
    the event has no guid, so the check is skipped as upstream skips it for V1
    events (`app.ts:399-407`). No already-signed refusal exists on that path,
    even with a `dvnAddress`.
  - The check costs one extra `eth_call` per provider, two when the receiver
    overrides the default library. A `V2` send pays one more lookup round
    before validation, so a migrated one reads the receive library twice.
- A pathway names the receiver as `bytes32`, and the packet header that gets
  signed keeps that padded form, so EVM `address` arguments are narrowed at the
  lookup input instead (`evm_address_from_pathway_value`). Upstream narrows with
  `hexZeroPad(address, 32).slice(-40)`
  (`packages/static-config/src/index.ts:723-727`), which silently discards the
  leading 12 bytes. This repository refuses when they are non-zero. That is
  stricter than the destination itself: LayerZero's EVM
  `ReceiveUln302.commitVerification` takes the receiver as `receiverB20()`,
  i.e. `address(uint160(...))` (`AddressCast.toAddress`), so the chain also
  resolves such a receiver to its last 20 bytes, and the signed header carries
  all 32 bytes either way. This was read from LayerZero-v2 `main` source, not
  verified against the bytecode deployed on each roster chain. Only a packet whose
  sending OApp encoded its peer with non-zero upper bytes reaches it - an EVM
  source always zero-pads its sender (`PacketV1Codec.encode`) - and such a
  pathway, which upstream accepts by truncation, is rejected here.
- The generated LayerZero tables are pinned snapshots of a private upstream
  checkout, and no automated check compares them against upstream. Public CI
  cannot: the generators need `PILLAR_AUDIT_ROOT` plus the pinned npm packages,
  and the upstream service is not public. The pinned provenance is recorded in
  each generated file's header (`@layerzerolabs/lz-definitions` and
  `@layerzerolabs/lz-ton-sdk-v2` versions with input sha256s) and nowhere else.
  Treat a chain, deployment or status that changed upstream as unsupported here
  until a maintainer regenerates and the diff is reviewed.
- EVM source resolution은 receipt와 모든 log의 transaction hash를 요청한 source transaction에 결속한다.
  Log의 block hash와 number도 receipt와 같아야 한다. `removed` 생략은 false로 정규화한다.
  true, null과 잘못된 타입은 거부한다. 정규화한 log index는 중복될 수 없다.
  Quorum은 정규화한 typed receipt와 log를 비교한다. `l1Fee` 같은 추가 metadata는 비교하지 않는다.
  Resolution은 `EvmSourceEvidence`에 transaction hash, block hash와 number, execution status,
  PacketSent log의 index, address, topics와 data를 보관한다.
  Readiness와 ULNv2 MPT builder의 재조회는 이 evidence와 일치해야 한다.
  따라서 같은 transaction이 다른 log로 재포함된 경우에도 서명하지 않는다.
  `polygon`과 `tron`은 latest confirmation 수와 finalized 높이를 모두 만족해야 한다.
  Receipt 높이의 canonical header number와 hash도 일치해야 한다.
  Finalized RPC 실패, null과 canonical header number 불일치는 표를 얻지 못한다.
  Canonical hash 불일치는 SourceChanged 표가 되며 quorum이 성립하면 서명을 거부한다.
  Latest-only fallback은 없다.
  다른 EVM chain과 `amoy`에는 이 finalized 정책을 추가하지 않는다.
  Canonical header 결속은 upstream보다 엄격한 fail-closed 정책이다.
  Transaction hash 비교는 optional `0x` prefix와 대소문자를 정규화한다. RPC 요청 값은 바꾸지 않는다.
  Evidence 필드 확장으로 validation audit hash는 이전 버전과 byte 단위로 비교할 수 없다.
- TON 전용 decoder는 4 MiB 응답과 512 JSON container nesting을 허용한다.
  Trace 변환은 transaction hash 중복과 잘못된 topology를 조립 전에 거부한다.
  변환된 tree는 node 512개와 JSON container depth 512개를 넘을 수 없다.
  Projection은 서명과 confirmation에 필요한 scalar 필드만 유지한다.
  깊은 미사용 metadata는 복제하거나 재직렬화하지 않는다.
  생략된 leaf children은 빈 배열로 정규화한다. 원본 JSON 해제는 반복형이다.
  이 정규화는 children 누락에서 오류가 나는 upstream quorum 함수와 의도적으로 다르다.
  Legacy `/transactionTrace`도 중복 hash와 문자열이 아닌 hash를 거부한다.
  Container 비용은 node cap으로 별도 제한한다. Projected string byte cap은 4 MiB다.
- TON block confirmations count from the masterchain seqno of the `PacketSent`
  transaction itself, found by hash inside the provider's trace, and readiness
  refuses when that transaction is absent from the trace. Upstream reads the
  trace root's `mc_block_seqno`
  (`packages/sdks/rpc-sdk/src/ton/index.ts:175-187`), which can be an earlier
  block than the emission and so overstates the depth. This is a deliberate
  fail-closed divergence. The comparison is an exact string match against the
  hash the same provider returned during resolution. Public toncenter v3 mainnet
  and testnet `/events` and `/traces` were observed on 2026-10-06 to return every
  transaction hash as canonical padded standard base64, whatever form the request
  used, and the request hash is percent-encoded so `+`, `/` and `=` survive.
  Other TON v3 hosts were not checked; one that returns another encoding fails
  readiness closed rather than passing.
- A `ReadV1002` read is pinned to the block readiness validated, which
  upstream does not do. Upstream agrees on a time marker's block through a
  quorum and then fetches the payload with `eth_call` against the block
  *number* alone
  (`packages/sdks/lz-v2-sdk/src/read/cmdResolver/chain/evm/base.ts:22-28`), so
  a reorg between the two phases can answer the read from a different block at
  the same height, and the exact-value quorum over the returned bytes cannot
  see it because every honest provider follows the reorg. Readiness here
  returns the hash it agreed on for every marker - timestamp markers and the
  command's own block-number markers, which upstream only checks for depth and
  never looks up (`ReadBlockPin`, `crates/pillar-core/src/lib.rs`;
  `crates/pillar-runtime/src/layerzero_runtime/validation_read_markers.rs`) -
  and every `eth_call` for that marker is issued as EIP-1898
  `{"blockHash": ..., "requireCanonical": true}`
  (`crates/pillar-runtime/src/layerzero_runtime/read_payload.rs`). A provider
  whose canonical chain no longer holds that block errors and loses its vote,
  and there is no number-tagged fallback. A marker readiness did not pin is
  refused before any RPC, and two reads of one height that disagree during
  readiness are refused rather than resolved by picking one. What this does
  not change: the read is still only as final as the marker's
  `blockConfirmation` makes it, and a reorg deeper than that *after* signing is
  a finality question this service cannot answer.
- READ는 `eth_call`과 `eth_getCode`에서 정확한 `0x` prefix와 짝수 길이의 hex octets를 가진 JSON string만 DATA로 허용한다.
  `eth_call`이 `0x`이면 같은 provider와 headers로 `eth_getCode`를 조회한다.
  두 요청은 readiness가 검증한 같은 EIP-1898 block hash와 `requireCanonical:true`를 사용한다.
  Code가 정확한 `0x`이면 runtime은 `NoCode` 관측을 entity quorum의 표로 기록한다.
  `0x00` 등 byte가 있는 code는 정상 empty return을 허용한다. 별도 call/code quorum은 없다.
  Runtime은 numeric error code `3`, 또는 code `-32000`과 정확한 `execution reverted` 메시지의 조합만 `ExecutionRevert`로 분류한다.
  Runtime은 제공된 revert DATA의 타입과 hex octet을 검증하고 대소문자를 정규화한다.
  생략된 DATA와 유효한 `0x`는 반환 byte가 없다는 같은 관측이다. 서로 다른 nonempty DATA는 같은 표가 아니다.
  Runtime은 `NoCode` 또는 `ExecutionRevert`의 유일한 entity quorum만 non-retryable domain refusal로 변환한다.
  API는 이 거절에 HTTP 400, `code=UNRESOLVABLE_COMMAND`, `retryable=false`를 반환하며 signer에 진입하지 않는다.
  Timeout, transport 장애, malformed DATA와 일반 RPC 오류는 표를 얻지 못한다. Quorum 부족은 domain refusal이 아니라 기존 internal 오류다.
  불량 provider 하나가 있어도 서로 다른 정상 entity 두 개는 quorum 2로 정상 서명한다.
  정상과 부정 관측이 각각 quorum을 만족하면 runtime은 모호한 결과를 거부한다.
  운영자는 hash pin을 준수하는 provider만 READ route에 구성하고 미준수 provider로의 failover를 차단해야 한다. EIP-1898 파라미터 전송만으로 provider의 준수를 입증하지 않는다.
- Extra-context의 HTTP와 Lambda 요청은 `sentEvent`, `from`, typed `signingContext`를 포함한다.
  MESSAGE와 READ의 기존 Serde 형식과 optional omission을 유지한다.
  Closed-schema policy handler는 새 필드를 허용해야 한다.
  이 전달은 on-chain state 검증을 대신하지 않으며 policy를 설정하지 않은 경로는 바꾸지 않는다.
- An external extra-context policy must answer `true`, and the two transports
  wrap that verdict differently. **The shapes are not interchangeable** - a
  policy service migrated from one form to the other will be refused.
  - `EXTRA_CONTEXT_REQUEST_URL`: the HTTP response body *is* the verdict and
    must be the JSON literal `true`.
  - `EXTRA_CONTEXT_AWS_LAMBDA_NAME`: the function must return a JSON **object**
    carrying the verdict under `body`, so `{"body":true}` or
    `{"statusCode":200,"body":true}`. A bare `true` is refused because the
    envelope is what upstream reads (`parsedResponse.body`,
    `apps/gasolina/src/app/app.ts:724`); that requirement is not new. When
    `statusCode` is present it must be 2xx, and an SDK function error or a
    non-success SDK status is a refusal before the payload is examined
    (`crates/pillar-runtime/src/provider_health/transport.rs`).

  On both paths the verdict must be the JSON boolean `true` and nothing else.
  The strings `"true"` and `"false"`, `{}`, `[]`, `{"allow":false}`, numbers and
  `null` are all refusals
  (`crates/pillar-runtime/src/layerzero_runtime/validation_extra_context.rs`).
  Upstream decides both paths with JavaScript truthiness (`app.ts:707`,
  `:724`), where `{"statusCode":403,"body":"false"}` approves the request and a
  string body of any content approves it too - this is a deliberate
  fail-closed divergence. **A Lambda that returns `body` as a JSON-encoded
  string is a common shape and is refused**; confirm the returned type, not
  just the value, before deploying.
- The receiver's receive-library check does not depend on caller input. Library
  resolution and the refusal of an unsupported or invalid receive library run for
  every EVM sign request; only the `hashLookup` duplicate query is conditional on
  the caller supplying `dvnAddress`
  (`crates/pillar-runtime/src/layerzero_runtime/validation_payload.rs`). A
  request that omits `dvnAddress` therefore cannot reach a receiver on a
  library this service does not support.

  **The duplicate-signature refusal itself remains caller-selected, and that is
  an accepted operational assumption rather than an oversight.** The query asks
  whether *this* DVN has already attested the payload, which has no subject
  without an address; a caller may also name a different DVN's address and so
  read a different verification slot. This service holds no per-chain DVN
  contract identity to substitute - the signer's public-key address is a
  different object from the DVN contract the ULN records against - so enforcing
  it server-side means new configuration and a new trust model, not a bug fix.
  Upstream gates the same call the same way
  (`signingContext.dvnAddress && this.validatePayloadSigned(...)`,
  `apps/gasolina/src/app/app.ts:494`). Note that a global verification state of
  `Verified` can still refuse the request, so omitting the address does not
  remove every duplicate defence. If your requirement is "never sign a message
  this DVN already attested, whatever the caller sends", that is a change
  request against the configuration surface - file it rather than assuming the
  current behaviour covers it.

  On a chain-native destination with no address the check is skipped, matching
  upstream. Solana, Stellar and TON hash the address into what they sign and
  so refuse the request in their builders regardless; like upstream, Solana and
  Stellar report a missing or empty address as a `500` at the build stage, after
  resolution and validation.
- The connection lifetime ceiling is checked before each read and write rather
  than only when the underlying socket returns `Pending`
  (`IdleTimeoutIo`, `crates/pillar-cli/src/main.rs`), so a client that keeps the
  socket continuously readable cannot renew the sliding idle window past the
  300s ceiling. `poll_flush` and `poll_shutdown` delegate straight to the
  socket, so the guarantee is that no application-level read or write is
  serviced after the ceiling, not that every syscall stops.
- `srcChainName` and `dstChainName` are checked at the HTTP boundary, before
  anything logs them, against the roster and the shape 1-128 characters of
  `[0-9a-zA-Z_-]` (`crates/pillar-api/src/lib.rs`), and a caller-supplied
  `x-request-id` carrying control characters is replaced with a generated id.
  The installed `tracing-subscriber` formatter does not escape control characters
  in ordinary Display-formatted fields, so an unvalidated name containing a
  newline could forge a log record. Any name that fails either check gets
  upstream's unavailable-chain `500`, source first. All 272 chain names in the
  generated roster satisfy the shape.

## Supported versions

Only the latest released tag receives fixes. Security fixes are published as a
new patch tag with an entry in `CHANGELOG.md`.
