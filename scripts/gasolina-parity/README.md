# Gasolina parity fixtures

These three scripts produce the fixtures the parity tests read. They import the
upstream TypeScript service's own functions, so the fixtures are upstream's output
rather than this repository's opinion of it.

| emitter | fixture it produces |
|---|---|
| `emit-evm-signing-path.ts` | `crates/pillar-runtime/tests/gasolina_parity/evm_signing_path.json` |
| `emit-v-id-table.ts` | `crates/pillar-runtime/tests/gasolina_parity/v_id_by_chain_name.json` |
| `emit-ton-dvn-verify.ts` | `crates/pillar-layerzero/tests/gasolina_parity/ton_dvn_verify.json` |

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

## What these fixtures do NOT cover

They are not the full read-only smoke that
`docs/plans/2026-08-24-gasolina-mainnet-testnet-parity-plan.md` Unit 6 describes.
That asks for known historical `PacketSent` transactions, one pathway per chain
family, on both `mainnet` and `testnet`, driven through each service's public sign
path up to the signer stage, plus the reject paths (untrusted emitter,
already-signed) refused on both sides without the signer being called.

What is covered today: the EVM destination family on `mainnet` for the `V302` and
`ReadV1002` arms, from a hand-built log; the TON cell encoders across three message
shapes; and the vId table for every available chain in all three environments.
