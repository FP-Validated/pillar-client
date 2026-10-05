// Runs upstream's own GasolinaCantonSignerAdapter.getSignerAddress over fixed public
// keys returned by a stub SignerAdapter; nothing signs and no provider is touched.
// Copy it to a path without "canton" before running: the boundary stubs any such path.
const { GasolinaCantonSignerAdapter } = require('/tmp/gasolina-run/work/migrated/offchain-monorepo/packages/adapters/gasolina-signer-adapter/src/canton/index.ts')

const keys = {
    // secp256k1 generator point, SEC1 uncompressed (65 bytes, 0x04 prefix).
    sec1Uncompressed65: '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
    // The same point as bare x || y (64 bytes), the shape Azure KMS returns.
    bare64: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
}

const main = async () => {
    const vectors = []
    for (const [id, hex] of Object.entries(keys)) {
        const requests = []
        const stub = {
            getPublicKey: async (args) => {
                requests.push(args)
                return Uint8Array.from(Buffer.from(hex, 'hex'))
            },
        }
        const adapter = new GasolinaCantonSignerAdapter(stub)
        vectors.push({ id, publicKey: '0x' + hex, signerAddress: await adapter.getSignerAddress(), getPublicKeyArgs: requests })
    }
    process.stdout.write(JSON.stringify({
        provenance: {
            upstream: 'Gasolina 1.2.66 source snapshot',
            entrypoint: 'packages/adapters/gasolina-signer-adapter/src/canton/index.ts:GasolinaCantonSignerAdapter.getSignerAddress',
            input: 'stub SignerAdapter returning fixed synthetic public keys; offline',
        },
        vectors,
    }, null, 2) + '\n')
}
main().catch((error) => { console.error(error); process.exit(1) })
