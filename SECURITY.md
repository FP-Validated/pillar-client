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
  signing endpoints authorise on that token alone.
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
  upstream service, whose provider entry is likewise `{ uris, quorum }`
  (`packages/common-model/src/provider.ts:6-9`) and whose quorum likewise
  counts matching responses (`packages/common-utils/src/multiFallbackQuorum.ts:35-48`).

  Two separate reviews have read the upstream tree and reported that an
  entity/category/endpoint-type trust model is already live there, so the
  evidence is spelled out. Upstream does contain that scaffolding —
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

## Known caveats

These are known, unresolved weaknesses. They are documented here rather than in
an issue tracker because each one can change whether a signature is correct.

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

**Do not enable Stellar without first confirming the addresses on-chain for the
environment you run.** Verify with:

```bash
curl -s https://metadata.layerzero-api.com/v1/metadata/deployments \
  | jq '."stellar-mainnet".deployments[] | {version, eid, endpointV2, sendUln302, receiveUln302}'
```

Addresses live in `stellar_uln_302_for_environment` and
`trusted_stellar_endpoint_addresses_for_environment`
(`crates/pillar-runtime/src/layerzero_runtime/config/evm.rs`).

### Other known gaps

- The TON DVN verify fixtures are recorded expected values whose byte parity and
  BOC round-trip are asserted, but they are not reproduced from an independent
  run of the upstream TypeScript. Only the Solana fixture is source-backed. A
  TON encoding divergence from upstream would therefore not be caught by the
  test suite.
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

## Supported versions

Only the latest released tag receives fixes. Security fixes are published as a
new patch tag with an entry in `CHANGELOG.md`.
