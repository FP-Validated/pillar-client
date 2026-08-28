# Gasolina parity fixtures

These two scripts produce the fixtures under
`crates/pillar-runtime/tests/gasolina_parity/`. They import the upstream
TypeScript service's own functions, so the fixtures are upstream's output rather
than this repository's opinion of it.

Both are read-only: no RPC, no signer, no network, no writes to the upstream
checkout.

They have to run *inside* the upstream pnpm workspace, because they import
`@monorepo/*` packages that only resolve from a workspace member's directory.
Copying them in is the whole setup:

```bash
UPSTREAM=/path/to/gasolina-audit            # the checkout PILLAR_AUDIT_ROOT points at
cd "$UPSTREAM"
pnpm install --frozen-lockfile --filter '@monorepo/gasolina...'

mkdir -p apps/gasolina/parity
cp scripts/gasolina-parity/emit-evm-signing-path.ts apps/gasolina/parity/
cp scripts/gasolina-parity/emit-v-id-table.ts       apps/gasolina/parity/

cd apps/gasolina
node_modules/.bin/ts-node --transpile-only -P tsconfig.json \
  parity/emit-evm-signing-path.ts > evm_signing_path.json
```

`emit-v-id-table.ts` additionally reads `roster.json` from its own directory: a
`{ environment: [chainName, ...] }` object. Produce it from this repository so
both sides are asked about the same chains:

```rust
pillar_config::layerzero_available_chain_names(environment)
```

Then drop the emitted JSON into `crates/pillar-runtime/tests/gasolina_parity/`,
keeping the `_provenance` block, and run:

```bash
cargo test -p pillar-runtime gasolina_parity
```

Remove `apps/gasolina/parity/` afterwards; the upstream checkout is a reference,
not a workspace to leave litter in.

## Why the fixtures are compared field by field

A single hash comparison passes for the wrong reason as soon as two errors
cancel, and it says nothing about *which* step diverged. The tests assert the
normalized event, the packet header, the payload hash, the target contract, the
vId, the ULN call data, the packed DVN call data, and only then the hash.

The vId fixture exists because the two implementations derived it differently and
agreed almost everywhere: folding the V2 endpoint id matches the EndpointV1 id
for 345 of 350 chains. The five exceptions were real, and the vId is signed.
