# Gasolina parity fixtures

These scripts produce the fixtures the parity tests read. They import the
upstream TypeScript service's own functions, so the fixtures are upstream's output
rather than this repository's opinion of it.

| emitter | fixture it produces |
|---|---|
| `emit-evm-signing-path.ts` | `crates/pillar-runtime/tests/gasolina_parity/evm_signing_path.json` |
| `emit-v-id-table.ts` | `crates/pillar-runtime/tests/gasolina_parity/v_id_by_chain_name.json` (gasolina-audit `213cd500`; see below) |
| `emit-ton-dvn-verify.ts` | `crates/pillar-layerzero/tests/gasolina_parity/ton_dvn_verify.json` (`vec-a`, `vec-b`; `vec-c` follows 1.2.66 `hexToCells` 1016-bit cells and is computed by the repository builder, see the fixture `_provenance`) |
| `emit-historical-smoke.ts` | `crates/pillar-runtime/tests/gasolina_parity/historical_smoke.json` |
| `emit-ton-proxy-target.ts` | `crates/pillar-layerzero/tests/gasolina_parity/ton_proxy_target.json` |
| `emit-zod-v2-golden.ts` | `crates/pillar-api/fixtures/zod_v2_golden.json` (wrap its output under `cases`, keep `_provenance`; re-run at `213cd500` with every case unchanged) |
| `emit-http-framework-golden.ts` | `crates/pillar-api/fixtures/http_framework_golden.json` (take the output after `@@GOLDEN@@`, wrap it under `cases`, keep `_provenance`) |
| `emit-legacy-message-id-golden.ts` | `crates/pillar-runtime/tests/gasolina_parity/legacy_message_id.json` (take the output after `@@GOLDEN@@`, wrap it under `cases`, keep `_provenance`) |
| `emit-v2-v3-route.ts` | `crates/pillar-runtime/tests/gasolina_parity/v2_v3_route.json` (gasolina-audit `213cd500`; see below) |
| `emit-evm-catalog-destination.ts` | `crates/pillar-runtime/tests/gasolina_parity/evm_catalog_destination.json` (`213cd500`-labelled snapshot; boundary loader; strip `dvnCallData`, one row per line) |
| `emit-nonevm-destination.ts` | `crates/pillar-runtime/tests/gasolina_parity/non_evm_destination.json` (non-EVM destination version/refusal matrix; TON provider uses offline `open` adapter) |
| `emit-ton-v302-destination.ts` | `crates/pillar-runtime/tests/gasolina_parity/ton_v302_destination.json` (TON V302 upstream payloads) |
| `emit-chain-bindings.ts` | `crates/pillar-runtime/tests/gasolina_parity/chain_bindings.json` (`213cd500`-labelled snapshot; boundary loader; needs `pillar-static-chain-names.json` beside it) |
| `emit-canton-signer-address.ts` | `crates/pillar-layerzero/tests/gasolina_parity/canton_signer_address.json` (1.2.66 snapshot; boundary loader with the Canton allowlist; see below) |
| `emit-canton-digest.ts` | `crates/pillar-layerzero/tests/gasolina_parity/canton_digest.json` (1.2.66 snapshot; boundary loader with the Canton allowlist; see below) |
| `emit-ton-trace-quorum.ts` | `crates/pillar-runtime/tests/gasolina_parity/source_replay/ton-trace-quorum.json` (1.2.66 snapshot; boundary loader; `TON_EVENTS_RESPONSE` names the recorded `ton-v3-events.response.json`; see below) |
| `emit-aptos-v301-payload-signed.ts` | `crates/pillar-runtime/tests/gasolina_parity/aptos_v301_payload_signed.json` (1.2.66 snapshot; boundary loader; see below) |
| `emit-aptos-transport-wire.ts` | `crates/pillar-runtime/tests/gasolina_parity/transport/upstream_aptos_transport.json` (real Aptos SDK/provider HTTP loopback; Aptos V301/V302 and Movement V302; see below) |

`emit-ton-v302-destination.ts` derives the mainnet and sandbox ULN/connection addresses from upstream TON constructors and builds V302 cells with upstream `buildDvnVerifyCallData`. From `apps/gasolina`, run it through `sandbox-exec -f /tmp/gasolina-run/sb/offline.sb bash boundary/run-emitter.sh parity-v18-ton-v302 emit-ton-v302-destination.ts ton-v302-destination.json` after copying the script into that subdirectory. Its supplied implementation models only `getImplementationContract`'s not-deployed/not-a-proxy fallback. It does not prove a live/on-chain result or the proxy branch.

`emit-ton-trace-quorum.ts` runs upstream
`tonTransactionTraceMessagesQuorumFn` over the recorded trace. Its fixture records
upstream's own projection and fingerprints, rather than this repository's projection.

`emit-aptos-v301-payload-signed.ts` runs upstream receive-details, destination
config and `hasPayloadSigned` calls against a stub Move provider for eleven scenarios
on mainnet and testnet. It records typed arguments and verdicts for the recorded V1
receivers and EndpointV1 source ids 101/10161; it does not contact a live node.

The boundary reports record one replaced Canton module for the TON emitter and
six replaced modules for the Aptos V301 emitter, including Canton and Stellar
definitions. Both report `reads: 0, calls: 0` for these replacements.

`emit-aptos-transport-wire.ts` runs the upstream Aptos SDK 1.39.0 and ULN calls
against a loopback server. It replays recorded Aptos/Movement responses, captures the
SDK's HTTP/BCS request and checks typed arguments against the Rust transport's
normalized JSON arguments. Recorded receive-library/configuration, Channels and table
responses are replayed; missing V301/V302 confirmation and `verifiable` responses
are explicitly synthetic zeroes. Other unrecorded requests are refused, and no live
RPC is used. This capture does not start at `App.validatePayloadSigned`: the
EndpointV2 `endpoint::get_effective_receive_library` lookup is not part of the
upstream capture, so the Rust test checks its order and arguments but does not claim
byte-level parity for that lookup.


All of them are read-only in the sense that matters: no external RPC, no writes to the
upstream checkout, and no network beyond the local loopback replay/emitter boundaries.
`emit-http-framework-golden.ts` serves upstream's Express bootstrap to itself on
`127.0.0.1:38417`. `emit-historical-smoke.ts` does run upstream's signer, with a
well-known test mnemonic that exists only in that file.

They have to run *inside* the upstream pnpm workspace, because they import
`@monorepo/*` packages that only resolve from a workspace member's directory.
Copying them in is the whole setup. Start inside this repository; every later path is
absolute, so the `cd`s below cannot break a copy:

```bash
PILLAR="$(git rev-parse --show-toplevel)"
UPSTREAM=/path/to/gasolina-audit            # the checkout PILLAR_AUDIT_ROOT points at
cd "$UPSTREAM"
pnpm install --frozen-lockfile --filter '@monorepo/gasolina...'

mkdir -p "$UPSTREAM/apps/gasolina/parity"
cp "$PILLAR"/scripts/gasolina-parity/*.ts "$UPSTREAM/apps/gasolina/parity/"

cd "$UPSTREAM/apps/gasolina"
RUN="node_modules/.bin/ts-node --transpile-only -P tsconfig.json"

$RUN parity/emit-evm-signing-path.ts > evm_signing_path.json
$RUN parity/emit-ton-dvn-verify.ts   > ton_dvn_verify.json
```

`emit-historical-smoke.ts` additionally needs `historical_pathways.json` beside it:

```bash
cp "$PILLAR/crates/pillar-runtime/tests/gasolina_parity/historical_pathways.json" \
   "$UPSTREAM/apps/gasolina/parity/"
$RUN parity/emit-historical-smoke.ts > historical_smoke.json
```

`emit-ton-dvn-verify.ts` writes a `bigint: Failed to load bindings` line to
**stderr**; redirect stdout separately or the JSON will not parse.

`emit-v2-v3-route.ts` targets the later `213cd500` tree, where the service lives under
`migrated/offchain-monorepo/apps/gasolina` and the packages are `@offchain-monorepo/*`.
That tree pins Node 24.15.0 and `pnpm@11.17.0`, and three contract packages generate
their typechain/wagmi sources at build time, so the setup differs. Point `UPSTREAM` at
that checkout and start from its root:

```bash
cd "$UPSTREAM"
pnpm install --frozen-lockfile --filter '@offchain-monorepo/gasolina...'
pnpm --filter @offchain-monorepo/lz-evm-sdk-v2-contracts --filter @offchain-monorepo/custom-contracts \
     --filter @offchain-monorepo/layerzero-core-contracts run build
mkdir -p "$UPSTREAM/migrated/offchain-monorepo/apps/gasolina/parity"
cp "$PILLAR/scripts/gasolina-parity/emit-v2-v3-route.ts" \
   "$UPSTREAM/migrated/offchain-monorepo/apps/gasolina/parity/"
cd "$UPSTREAM/migrated/offchain-monorepo/apps/gasolina"
node --import tsx parity/emit-v2-v3-route.ts > v2_v3_route.json
```

It needs no network once installed; the committed fixture was emitted with outbound
network denied by the sandbox.

`emit-v-id-table.ts` and `emit-zod-v2-golden.ts` also run in that `213cd500` setup
(copy them into the same `parity/` directory). The vId emitter asks upstream's
`getVId` about the chains in `PILLAR_V_ID_ROSTER`, a `{ "<environment>": [chains] }`
file holding `pillar_config::layerzero_available_chain_names` per environment; without
it the committed fixture's own chain names are re-asked.

```bash
PILLAR_V_ID_ROSTER=/path/to/v-id-roster.json \
  node --import tsx parity/emit-v-id-table.ts > v_id_by_chain_name.json
```

The Rust side asserts the table exhaustively in both directions, so a chain upstream
cannot resolve, or one the union gains or loses, fails there rather than vanishing
from the comparison. The other emitters still import the pre-migration
`@monorepo/*` packages; at `213cd500` their module graphs reach packages outside the
`gasolina...` install filter (`canton-sequencer-sdk`, `common-encoding-utils`) and
Stellar/Canton generated code that the snapshot does not ship.

`boundary/excluded-chain-boundary.mjs` makes those graphs load without touching
upstream source: it resolves workspace packages to their `src/`, and replaces every
workspace module whose path names an excluded chain (`stellar`, `soroban`, `canton`,
`daml`) with a generated module whose exports throw `EXCLUDED_CHAIN_ADAPTER` and whose
every property read is recorded. `boundary/run-emitter.sh <dir> <script> <out>` runs an
emitter under it and writes `boundary-report.json`; a run is only valid when that
report shows zero reads and zero calls. The two emitters above, and
`emit-historical-smoke.ts` adapted to the `213cd500` App constructor, were run this way
with outbound network denied.

Copy each emitted JSON to the path in the table above (relative to `$PILLAR`), keeping
its `_provenance` block, then run:

```bash
cd "$PILLAR"
cargo test -p pillar-runtime gasolina_parity
cargo test -p pillar-layerzero other_non_evm::ton
```

Remove the `parity/` directories from the upstream checkout afterwards; it is a
reference, not a workspace to leave litter in.

### Canton emitters

These two emitters pin the pure Canton helpers in `pillar_layerzero::other_non_evm::canton`:
the ULN302 verify digest and the signer address Gasolina publishes. For what the service
supports on Canton today, see the [README](../../README.md) and
[SECURITY.md](../../SECURITY.md#known-caveats). The two emitters reach four Canton source modules that are
pure functions, and `boundary/excluded-chain-boundary.mjs` lets exactly those load
(`CANTON_PURE_ALLOWLIST`): `apps/gasolina/src/app/sdks/gasolinaSdk/canton/hashes.ts`,
`packages/adapters/gasolina-signer-adapter/src/canton/index.ts`,
`packages/vms/canton/common/src/client/utils.ts` and `.../common/src/crypto.ts`. Every
other Canton module, including `canton-sequencer-sdk` (absent from the registry), stays
a throwing stub.

The boundary also stubs the *emitter* when its own path names Canton, so copy each one
to a directory and file name without `canton`, `stellar`, `soroban` or `daml`, and run
it from `migrated/offchain-monorepo/apps/gasolina` with outbound network denied:

```bash
cd "$UPSTREAM/migrated/offchain-monorepo/apps/gasolina"
mkdir -p parity-signer-addr parity-digest
cp "$PILLAR/scripts/gasolina-parity/emit-canton-signer-address.ts" parity-signer-addr/emit-signer-address.ts
cp "$PILLAR/scripts/gasolina-parity/emit-canton-digest.ts"         parity-digest/emit-digest.ts
sandbox-exec -f offline.sb boundary/run-emitter.sh parity-signer-addr emit-signer-address.ts out.json
sandbox-exec -f offline.sb boundary/run-emitter.sh parity-digest      emit-digest.ts         out.json
```

`offline.sb` is a macOS sandbox profile denying outbound network; `boundary/` is this
directory's `boundary/` copied beside the app. The emitters `require` the upstream
modules by absolute path under `/tmp/gasolina-run/work`, the root the boundary is pinned
to; edit both together if the tree lives elsewhere. A run is valid only when its
`boundary-report.json` shows `reads: 0`, `calls: 0` and `cantonAllowedModules` equal to
the four modules above. Copy `out.json` to the fixture path, then run
`cd "$PILLAR" && cargo test -p pillar-layerzero canton`.

What these fixtures do **not** establish: they pin a digest and an address, not a
signature. Canton verification recovers the signer's key from an ECDSA signature over
the *raw* keccak verify digest with an *untransformed* recovery id
(`gasolina-signer-adapter/src/canton/index.ts:6-14`). The signature bytes
`ChainType::Canton` produces are pinned against upstream's own signer by a separate
fixture (`crates/pillar-signer/tests/gasolina_parity/canton_sign.json`, from
`emit-ve3-sign.ts`), and the sequencer path (source resolution, readiness,
already-signed) by `canton_sequencer.json` (from `emit-ve3-sequencer.ts`). None of these
is a signature accepted by a live Canton ledger, nor production OAuth2/ledger acceptance.

## Why the fixtures are compared field by field

A single hash comparison passes for the wrong reason as soon as two errors cancel,
and it says nothing about *which* step diverged. The tests assert the normalized
event, the packet header, the payload hash, the target contract, the vId, the ULN
call data, the packed DVN call data, and only then the hash.

The vId fixture records what upstream's `getVId` returns. At `213cd500` it folds the V2
endpoint id for every chain, which disagrees with the EndpointV1 id this service signs on
four testnet chains; the deployed DVNs on two of them enforce the EndpointV1 id
(`crates/pillar-runtime/tests/onchain_provenance/dvn_vid.json`), so the Rust test
expects exactly those four divergences and upstream's value everywhere else.

## The historical smoke

`historical_pathways.json` holds real `PacketSent` transactions, discovered with
`eth_getLogs` on the EndpointV2 address and captured with
`eth_getTransactionReceipt`: one per destination chain family per environment. Both
services are driven from those recorded receipts, so the comparison is offline even
though the packets are real. Ten destination families are compared: EVM, TRON,
APTOS, INITIA, MOVEMENT, SUI, SOLANA, STARKNET, STELLAR and TON.

`emit-historical-smoke.ts` calls upstream's service entrypoint - `App.signRequestV2`,
the method the HTTP layer calls - and lets the whole orchestrator run: protocol-type
checks, message hash, readiness, expiration, already-signed, build, sign. The Rust
side calls its own entrypoint the same way, through the production composition
(`core_api_app_from_runtime_parts`), so the two things being compared are two
services rather than two libraries.

What each side is *given* rather than fetching, identically on both:

| supplied | why | upstream | this service |
|---|---|---|---|
| the source receipt | the packet is real, the read is not | provider stub | `ParityTransport` |
| the TON DVN proxy account state | recorded from toncenter, see below | provider stub | same bytes |
| block confirmations | readiness gate, no node | `rpcSdkFactory` stub | `ParityChecks` |
| block timestamp | expiration gate, no node | `rpcSdkFactory` stub | `ParityChecks` |
| already-signed | an on-chain question this cannot ask | `ulnSdkFactory` stub | `ParityChecks` |

Recomposing the stages was the earlier mistake, twice over.
`GasolinaEvmSdk.buildDvnCallData` derives the receive ULN version from the
destination endpoint id, which a harness that pins V302 skips; and a reject path only
means something if the thing rejecting it is the same orchestrator that would
otherwise have signed.

Both event resolvers are exercised, because upstream has two: the factory picks the
viem implementation for testnet and the ethers one for mainnet
(`endpoint/factory.ts:33-55`), while this service has a single resolver that has to
match both.

Each pathway is run four times: once normally, and once per reject scenario. Both
services count their own signer invocations, so *refused* means the signer never ran
rather than merely that an error came back.

| scenario | what changes | upstream refuses with |
|---|---|---|
| `foreignEmitter` | the `PacketSent` log is re-emitted from an address that is not the endpoint | `cannot find packet event for srcTxHash ...` |
| `alreadySigned` | the DVN has already verified this payload | `Payload already signed for message ...` |
| `unavailableChain` | the destination is not in the provider config | `Unsupported dst chain ...` |

Each is a different guard, and the fixture records upstream's own message and its own
signer count, so the reject arm is a comparison rather than an assumption.

Three things the fixture records rather than hides:

- `mainnet-ton` *is* compared, and needs one more recorded value than the others.
  Upstream's TON verify path resolves the DVN proxy's implementation through a
  quorum-backed storage read (`gasolinaSdk/ton/index.ts:144-159`) before it can name
  the contract the call targets, so `historical_pathways.json` carries that account
  state next to the receipt: the live LayerZero Labs DVN on TON mainnet
  (`0:0d122dec...`, from `toncenter getAddressInformation`), which is a `pfProxy`.
  Both services replay it rather than fetch it. `getTonV2QuorumProvider` returns a
  non-multiprovider unchanged (`multiprovider/src/quorumProvider.ts:101-109`), so the
  stub is a plain object. TON also keeps its two narrower fixtures:
  `ton_dvn_verify.json` for the cell encoders and `ton_proxy_target.json` for the
  decode branch a live Proxy cannot exercise - a cell that is *not* a proxy.
- The two Stellar pathways are Gate 0 blocked. They are compared and they match, but
  per the plan they are not a rollout signal until the deployment addresses are
  confirmed on-chain.
- `iotal1` has no pathway at all: 0 packets to it in 275,000 mainnet blocks. On
  testnet, `aptos`, `initia` and `iotal1` likewise had none in 500,000 sepolia
  blocks, and the other testnet source chains carry almost no traffic.

## Two divergences this comparison found

Both were in the signer stage, and neither is visible from a hash comparison:

- **Solana address.** Upstream takes the first 32 bytes of whatever public key the
  provider returned, with no prefix handling
  (`gasolina-signer-adapter/src/solana/index.ts:9-11`). Azure returns a bare 64-byte
  `x || y` (`azureKmsSignerAdapter.ts:170-172`), so there those bytes are X; a local
  mnemonic key is SEC1-uncompressed, so they are `04` followed by 31 bytes of X.
  This service normalized the two shapes together and so published a different
  Solana DVN address than the running service for every locally signed request.
- **Initia signing key.** Upstream's Initia adapter overrides neither
  `privateKeySignatureType` nor the address one, so it inherits ECDSA for both -
  Initia is the one Move-adjacent chain that does not override. This service derived
  an Ed25519 key for local signing, which produced a signature that did not
  correspond to the address it advertised.

## What is still not compared

- The TON quorum *fetch* machinery itself (`fetchQuorumedStorageCell`'s multiprovider
  agreement). Both services are handed the same recorded account state, so what is
  compared is everything downstream of the read, not the read's own agreement rule.
- The already-signed rejection, which is an on-chain read rather than an offline
  decision, and is covered by its own criterion.
- A testnet Move, IOTA or TON pathway, and mainnet IOTA. Not an omission: there is no
  such packet to record. Sepolia carries none in 1,000,000 blocks, and base-sepolia,
  bsc-testnet, amoy, arbitrum-sepolia, optimism-sepolia and avalanche-fuji carry none
  in 250,000 blocks each; `iotal1` has none in 275,000 mainnet blocks. What those
  testnets do carry - solana, sui, starknet, stellar - is in the fixture. Every one of
  these rows is written out in the test's `ACCEPTANCE` table with its reason, and the
  test fails if a row appears or vanishes without that table being edited.

Starknet's `ulnCallData` is compared as felt *values* rather than as a string:
starknet.js renders some felts as decimal and strips leading zeros, this service
zero-pads them, and reproducing another library's debug formatting would be brittle.
Every signed field is compared verbatim.

## Transport wire capture

`emit-source-replay-sol-tron-ton.ts` binds actual upstream `Connection`, `JsonRpcBatchProvider` and `TonV3Wrapper` clients to a harness-owned `127.0.0.1` server. The server serves only recorded response bodies, captures method, path+query, headers, raw body bytes (base64 and UTF-8), and returns 599 for an unrecorded request. Run it under `offline.sb` with network re-allowed only for `localhost` (`network-outbound` remote, `network-inbound` and `network-bind` local); the committed request capture is `crates/pillar-runtime/tests/gasolina_parity/transport/upstream_requests.json`.

`crates/pillar-runtime/src/tests/transport_wire_tests.rs` exercises the production `ReqwestJsonRpcTransport` against a temporary loopback server that replays recorded response bodies. It compares request method, path+query, JSON-RPC semantics and content type. Normalizations are limited to request id, JSON object member ordering, ephemeral host, and absent/default `Accept`/`User-Agent` headers. Solana intentionally differs by Pillar's `maxSupportedTransactionVersion: 1` option (`packet_resolver.rs:140-153`; upstream `packages/multiprovider/src/solana.ts`); JSON-RPC `id` is transport-local and not semantic.

| Surface | Upstream capture | Pillar request | Result |
|---|---|---|---|
| Solana `getTransaction` | `Connection` | `ReqwestJsonRpcTransport` | version-1 cap differs as documented above |
| TRON `eth_getTransactionReceipt` | `JsonRpcBatchProvider` | `ReqwestJsonRpcTransport` | same JSON-RPC operation after id/object-order normalization |
| TON trace `/events?tx_hash=` | `TonV3Wrapper` through `EndpointV2TonSdk` | `ReqwestJsonRpcTransport` | same method/path+query; no request body |
| Solana `getBlock` | `Connection` | no same source-path Pillar call | upstream-only capture |
| Aptos/Movement `/view`, resource, table item | `AptosMultiProvider` (BCS view payload) | `ReqwestJsonRpcTransport` (typed JSON) | same argument values and Move types; encoding differs by design, not byte-equal |

The Solana archived response is rejected by the current web3.js decoder after its real `getTransaction` request is sent, so the captured event is `null`; the wire request remains valid evidence. TON's captured source call is the `/events` success path; the `/traces` and `/transactionTrace` fallbacks are not traversed by this response.
