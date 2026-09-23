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
- Set an explicit `quorum` of at least 2 for every chain in the provider
  configuration. A quorum of 1 makes a single RPC endpoint the trust root for
  the event you attest to; the startup report flags such chains.
- Supply endpoints that are actually independent. A quorum of N is satisfied by
  N configured URIs returning the **same** value, and nothing more: the
  configuration carries no notion of who operates an endpoint, so two URIs
  belonging to one provider satisfy a quorum of 2 while sharing one failure,
  one compromise and one wrong archive state. Differing answers never merge —
  a split result fails closed rather than taking a majority — but agreement
  only proves the answers match, not that they were reached independently.
  Provider independence is yours to arrange and audit. This matches the
  upstream service as pinned below, whose provider entry is likewise
  `{ uris, quorum }` (`packages/common-model/src/provider.ts:6-9`) and whose
  quorum likewise counts matching responses
  (`packages/common-utils/src/multiFallbackQuorum.ts:35-48`).

  Two separate reviews have read an upstream tree and reported that an
  entity/category/endpoint-type trust model is already live there, so the
  evidence is spelled out. Everything here was checked against the single
  upstream tree identified under "Which upstream tree the `TS:` citations refer
  to" below, which also records why one of those reviews is answered with "does
  not reproduce" rather than "is false". That tree contains the scaffolding —
  `ProviderCategory` and `QuorumStrategy` declarations at
  `packages/common-model/src/provider.ts:120-152`, the v2 entry shape
  `{ uri, category, entity, headers? }` at
  `packages/common-utils/src/providerValidate.ts:13-25`, and strategy evaluation
  in `packages/common-utils/src/quorumStrategy.ts` — but **none of it has a
  caller outside its own file and its tests**. The live path is
  `apps/gasolina/src/index.ts:361-363` -> `runGasolina:327-335` ->
  `apps/gasolina/src/bootstrap.ts:206-213` ->
  `apps/gasolina/src/app/bootstrap.ts:123-124` (`new App(...)`), with providers
  built at `packages/dynamic-config/src/boostrapConfig/index.ts:103-159`, whose
  S3 and GCS object key defaults to `providers.json`. No `providers-v2.json` or
  `quorum-strategy.json` exists anywhere in the tree, and
  `packages/common-aptos/src/provider.ts:19` carries
  `// TODO(providers-v2): drop`, which is upstream describing a migration it has
  not made. If you point this service at an upstream deployment that has since
  migrated, this paragraph is what to re-check first.
- Alert on `pillar_provider_config_age_seconds` (stale provider configuration),
  `pillar_signer_errors_total` and `pillar_provider_request_errors_total`.
- Rate-limit the signing routes upstream of the process. There is no rate
  limiting in this workspace; the only throughput controls are
  `PILLAR_MAX_CONNECTIONS` (default 1024) and the 58s request timeout. That cap
  bounds in-flight requests, not just sockets, because the server speaks
  HTTP/1.1 only and a connection carries one request at a time. The protocol
  surface is pinned by a test: hyper's `http2` feature is enabled process-wide
  by the AWS and GCP client stacks, and an HTTP/2 connection would multiplex up
  to 200 concurrent streams behind a single connection permit. One
  sign request fans out to every configured provider URI for the source chain
  before any expensive validation, and a request that proceeds adds several
  more quorum'd reads, so an unthrottled caller amplifies load onto your own
  RPC endpoints at roughly the URI count per request.
- Decide deliberately which routes your ingress publishes. `GET /`,
  `GET /ready`, `GET /environment`, `GET /available-chains`, `GET /version` and
  `GET /provider-health` require no credential by design. The chain roster and
  the per-chain health map tell a reader which pathways this DVN serves and
  which of them it currently cannot verify on.
- Point the readiness probe at `/ready`, not `/`. `/` is a constant liveness
  string, so a probe on it never observes draining or unhealthy providers and
  the graceful-drain sequence cannot remove the pod from the endpoint set.
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
  Reth answers both ways as required (checked on public mainnet endpoints on
  2026-09-23: `block not found: canonical hash ...` for the unknown hash).

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
read from, and that has already gone wrong twice. Two independent reviews
reported that upstream runs an entity/category/endpoint-type provider trust
model, and that it switches the hash-call-data builder from V2 to V3 when a
packet was sent on ULN V2 but the destination receive library has migrated.
Neither is on the runtime path in the tree identified above. One of those reviews
named its source as a differently-rooted archive that is not that tree and that
has not been obtained here, so the accurate statement is that its claims **do not
reproduce against the identified tree** — not that they are false of whatever it
read. Those are different claims and only the first is established. If that
archive is produced, re-run the comparison before trusting either account.

If you point this service at an upstream deployment built from a newer tree,
this section and the provider-independence bullet above are what to re-check
first. The behaviour under discussion is load-bearing for signature
correctness: `hashCallDataBuilders[lzMessageId.ulnSendVersion]` selecting a V2
builder for a migrated pathway would sign call data the destination rejects,
and a quorum that counts URIs rather than operators can be satisfied by one
operator twice.

### Stellar deployment addresses disagree with LayerZero's live metadata

Every Stellar address in this repository comes from the pinned upstream
TypeScript packages, and every one of them disagrees with LayerZero's live
deployment metadata, on both `mainnet` and `testnet`:

| Value | This repository | `metadata.layerzero-api.com` |
| --- | --- | --- |
| mainnet ULN302 | `CA5R2JQYRJXFLWHE3XLLIO32HMF4MIDYY2NLWMGYYQDWKU6BTXL7URJI` | `CCV4HEII3UC65THWGSRM2DVIJLB6HS6YMUHDTTHUECX2RHTP5FA2GOBA` |
| testnet ULN302 | `CAWCTJDDZZEWYARYCY6IP7LJ5WAR5XHNDBNDNRFYNS5ZX22MH3RPSJSH` | `CCMLPCAWCPIIMXOHJJKU3NZLOFTT2O6QTB2UUFPN6SEHLK35QRHVKKMB` |
| mainnet trusted endpoint | `CAA4ZB7DNJ7KIZDEVDQRAZOQHYOV6U42LGBW375ZG7HIMUILA5FPXKQH` | `CCQLLRE5JBAWYCW3KTWOIWLMFDUOKROQVZNSALQMGOSXNW3ERUOWTZGK` |
| testnet trusted endpoint | `CBQOTWFU4N4DWFWYIU7EY62DXNCZH5N3U3XHKQW326CGY4CI6GT6Q5AF` | `CALTBA5S6GRJEHAXFP45LGGLKWWAF7HTZCPNUBUJF2HWWRRLQNV35AIV` |

The trusted endpoint address is what source-event filtering trusts, so a wrong
value there is not a cosmetic mismatch. Starknet, pinned from the same upstream
generation, matches the live metadata on all four equivalent values, which is
why the most likely explanation is that Stellar was redeployed after the pinned
package version.

**Stellar is refused structurally, not merely discouraged.**
`layerzero_rollout_block_reason` (`crates/pillar-config/src/lib.rs:297-301`)
drops `stellar` from the operational roster on both `mainnet` and `testnet`, so
listing it in `LAYERZERO_AVAILABLE_CHAIN_NAMES` does not enable it and the
destination builder refuses per request. The same function blocks `moninet` on
`testnet`, and `ton` on `testnet` only — TON testnet has no `UlnConnection`, so
no delivered packet exists whose verdict a payload-signed check could read, and
it stays fail-closed until one does. Re-pinning the table below to a deployment
you have confirmed on-chain is what reopens a blocked chain. Confirm with:

```bash
curl -s https://metadata.layerzero-api.com/v1/metadata/deployments \
  | jq '."stellar-mainnet".deployments[] | {version, eid, endpointV2, sendUln302, receiveUln302}'
```

Addresses live in `stellar_uln_302_for_environment` and
`trusted_stellar_endpoint_addresses_for_environment`
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
  Before this was implemented the version was derived, which reads the wrong
  contract for an OApp on a non-default library. That did not permit a second
  signature in practice: the address-width defect in the next entry blocked the
  same path earlier and failed closed. Both were fixed together, so neither was
  ever reachable on its own in a released build.
  Two consequences to know before deploying:
  - A receiver on a message library outside those three is refused, not signed.
    That is deliberate - the service cannot tell whether such a payload is
    already verified - but an OApp on a custom library will get errors rather
    than signatures.
  - The check costs one extra `eth_call` per provider, two when the receiver
    overrides the default library.
- A pathway names the receiver as `bytes32`, and the packet header that gets
  signed keeps that padded form, so EVM `address` arguments are narrowed at the
  lookup input instead (`evm_address_from_pathway_value`). Upstream narrows with
  `hexZeroPad(address, 32).slice(-40)`
  (`packages/static-config/src/index.ts:723-727`), which silently discards the
  leading 12 bytes. This repository refuses when they are non-zero: truncating
  an address that was never a zero-padded EVM address means attesting for a
  different OApp than the packet names. A pathway upstream would have accepted
  by truncation is rejected here.
- The generated LayerZero tables are pinned snapshots of a private upstream
  checkout, and no automated check compares them against upstream. Public CI
  cannot: the generators need `PILLAR_AUDIT_ROOT` plus the pinned npm packages,
  and the upstream service is not public. The pinned provenance is recorded in
  each generated file's header (`@layerzerolabs/lz-definitions` and
  `@layerzerolabs/lz-ton-sdk-v2` versions with input sha256s) and nowhere else.
  Treat a chain, deployment or status that changed upstream as unsupported here
  until a maintainer regenerates and the diff is reviewed.
- The EVM source event is bound to the receipt it was extracted from, which
  upstream does not do. Resolution keeps the receipt's block hash, block number,
  execution status and the `PacketSent` log index on the event
  (`EvmSourceEvidence`, `crates/pillar-core/src/lib.rs`), and readiness refuses
  when its own later read of the same transaction hash disagrees on any of them,
  or when the transaction is no longer mined
  (`crates/pillar-runtime/src/provider_health/evm_observations.rs`). A provider
  quorum only proves the providers agreed within one round; it says nothing
  about whether two rounds observed the same chain state, so a reorg that
  re-included the same transaction with different logs, or reverted it, would
  otherwise leave the packet captured in round one being signed against a
  round-two confirmation count. A receipt whose execution status is not success
  is refused at resolution. This is a deliberate fail-closed divergence from
  upstream, which performs the same two-phase read without binding it.
- A `ReadV1002` read is pinned to the block readiness validated, which
  upstream does not do. Upstream agrees on a time marker's block through a
  quorum and then fetches the payload with `eth_call` against the block
  *number* alone
  (`packages/sdks/lz-v2-sdk/src/read/cmdResolver/chain/evm/base.ts:22-28`), so
  a reorg between the two phases answered the read from a different block at
  the same height, and the exact-value quorum over the returned bytes could not
  see it because every honest provider had followed the reorg. Readiness now
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

  What changed is the verdict's type, on both paths: it must be the JSON
  boolean `true` and nothing else. The strings `"true"` and `"false"`, `{}`,
  `[]`, `{"allow":false}`, numbers and `null` are all refusals
  (`crates/pillar-runtime/src/layerzero_runtime/validation_extra_context.rs`).
  Upstream decides both paths with JavaScript truthiness (`app.ts:707`,
  `:724`), where `{"statusCode":403,"body":"false"}` approved the request and a
  string body of any content approved it too - this is a deliberate
  fail-closed divergence. **A Lambda that returns `body` as a JSON-encoded
  string is the common shape and is now refused**; confirm the returned type,
  not just the value, before deploying this version.
- The receiver's receive-library check no longer depends on caller input. It
  used to run only when the request supplied `dvnAddress`, which is
  caller-controlled JSON, so omitting that field skipped both the
  duplicate-signature query and the refusal of an unsupported or invalid
  receive library. The library resolution and refusal now run for every EVM
  sign request, and only the `hashLookup` duplicate query is conditional on an
  address being supplied
  (`crates/pillar-runtime/src/layerzero_runtime/validation_payload.rs`). A
  request that omits `dvnAddress` therefore still cannot reach a receiver on a
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
  so refuse the request in their builders regardless; that refusal is a `400`,
  because the combination is one the caller chose.
- The connection lifetime ceiling is checked before each read and write rather
  than only when the underlying socket returns `Pending`
  (`IdleTimeoutIo`, `crates/pillar-cli/src/main.rs`). A client that keeps the
  socket continuously readable previously renewed the sliding idle window
  without ever consulting the 300s ceiling. `poll_flush` and `poll_shutdown`
  still delegate straight to the socket, so the guarantee is that no
  application-level read or write is serviced after the ceiling, not that every
  syscall stops.
- `srcChainName` and `dstChainName` are shape-checked at the HTTP boundary to
  1-128 characters of `[0-9a-zA-Z_-]` before anything logs them
  (`crates/pillar-api/src/lib.rs`), and a caller-supplied `x-request-id`
  carrying control characters is replaced with a generated id. The installed
  `tracing-subscriber` formatter does not escape control characters in ordinary
  Display-formatted fields, so an unvalidated name containing a newline could
  forge a log record. Roster membership is still decided by the core, which
  reports an unknown chain as a caller error; the boundary check is shape only.
  All 272 chain names in the generated roster satisfy it.

## Supported versions

Only the latest released tag receives fixes. Security fixes are published as a
new patch tag with an entry in `CHANGELOG.md`.
