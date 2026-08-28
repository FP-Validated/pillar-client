# Gasolina parity fixtures

These four scripts produce the fixtures the parity tests read. They import the
upstream TypeScript service's own functions, so the fixtures are upstream's output
rather than this repository's opinion of it.

| emitter | fixture it produces |
|---|---|
| `emit-evm-signing-path.ts` | `crates/pillar-runtime/tests/gasolina_parity/evm_signing_path.json` |
| `emit-v-id-table.ts` | `crates/pillar-runtime/tests/gasolina_parity/v_id_by_chain_name.json` |
| `emit-ton-dvn-verify.ts` | `crates/pillar-layerzero/tests/gasolina_parity/ton_dvn_verify.json` |
| `emit-historical-smoke.ts` | `crates/pillar-runtime/tests/gasolina_parity/historical_smoke.json` |

All three are read-only: no RPC, no signer, no network, no writes to the upstream
checkout.

They have to run *inside* the upstream pnpm workspace, because they import
`@monorepo/*` packages that only resolve from a workspace member's directory.
Copying them in is the whole setup:

```bash
UPSTREAM=/path/to/gasolina-audit            # the checkout PILLAR_AUDIT_ROOT points at
cd "$UPSTREAM"
pnpm install --frozen-lockfile --filter '@monorepo/gasolina...'

mkdir -p apps/gasolina/parity
cp scripts/gasolina-parity/*.ts apps/gasolina/parity/

cd apps/gasolina
RUN="node_modules/.bin/ts-node --transpile-only -P tsconfig.json"

$RUN parity/emit-evm-signing-path.ts > evm_signing_path.json
$RUN parity/emit-ton-dvn-verify.ts   > ton_dvn_verify.json
```

`emit-historical-smoke.ts` additionally needs `historical_pathways.json` beside it:

```bash
cp crates/pillar-runtime/tests/gasolina_parity/historical_pathways.json \
   "$UPSTREAM/apps/gasolina/parity/"
$RUN parity/emit-historical-smoke.ts > historical_smoke.json
```

`emit-ton-dvn-verify.ts` writes a `bigint: Failed to load bindings` line to
**stderr**; redirect stdout separately or the JSON will not parse.

`emit-v-id-table.ts` additionally reads `roster.json` from its own directory: a
`{ environment: [chainName, ...] }` object. Produce it from this repository so both
sides are asked about the same chains:

```rust
pillar_config::layerzero_available_chain_names(environment)
```

```bash
$RUN parity/emit-v-id-table.ts > v_id_by_chain_name.json
```

Copy each emitted JSON to the path in the table above, keeping its `_provenance`
block, then run:

```bash
cargo test -p pillar-runtime gasolina_parity
cargo test -p pillar-layerzero other_non_evm::ton
```

Remove `apps/gasolina/parity/` afterwards; the upstream checkout is a reference,
not a workspace to leave litter in.

## Why the fixtures are compared field by field

A single hash comparison passes for the wrong reason as soon as two errors cancel,
and it says nothing about *which* step diverged. The tests assert the normalized
event, the packet header, the payload hash, the target contract, the vId, the ULN
call data, the packed DVN call data, and only then the hash.

The vId fixture exists because the two implementations derived it differently and
agreed almost everywhere: folding the V2 endpoint id matches the EndpointV1 id for
345 of 350 chains. The five exceptions were real, and the vId is signed.

## The historical smoke

`historical_pathways.json` holds real `PacketSent` transactions, discovered with
`eth_getLogs` on the EndpointV2 address and captured with
`eth_getTransactionReceipt`: one per destination chain family per environment. Both
services are driven from those recorded receipts, so the comparison is offline even
though the packets are real.

`emit-historical-smoke.ts` runs upstream's **public** entrypoint -
`GasolinaSdkFactory.getSdk(dstChainName).buildULNV3VerifyPayload(...)` - rather than
recomposing its steps, because `GasolinaEvmSdk.buildDvnCallData` derives the receive
ULN version from the destination endpoint id and a recomposed harness skips that.

Three things the fixture records rather than hides:

- `mainnet-ton` is not compared. Upstream's TON verify path resolves the DVN proxy's
  implementation through a quorum-backed storage read
  (`gasolinaSdk/ton/index.ts:144-159`), which no argument bypasses. TON's payload
  builders are compared through `ton_dvn_verify.json` instead.
- The two Stellar pathways are Gate 0 blocked. They are compared and they match, but
  per the plan they are not a rollout signal until the deployment addresses are
  confirmed on-chain.
- `iotal1` has no pathway at all: 0 packets to it in 275,000 mainnet blocks. On
  testnet, `aptos`, `initia` and `iotal1` likewise had none in 500,000 sepolia
  blocks, and the other testnet source chains carry almost no traffic.

Starknet's `ulnCallData` is compared as felt *values* rather than as a string:
starknet.js renders some felts as decimal and strips leading zeros, this service
zero-pads them, and reproducing another library's debug formatting would be brittle.
Every signed field is compared verbatim.
