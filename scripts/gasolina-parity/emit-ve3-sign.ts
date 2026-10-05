// Upstream 1.2.66's Canton signer over a fixed digest, through the same getter the service
// uses (`GasolinaSignerAdapterGetter.getSignerAdapter` -> `GasolinaCantonSignerAdapter`), with
// a well-known test mnemonic. Mnemonic signing is RFC 6979, so the signature bytes are
// reproducible on both sides. The file name avoids "canton", which the boundary loader
// treats as an excluded path segment.
import { GasolinaSignerAdapterGetter } from '@monorepo/gasolina-signer-adapter'
import { SignerAdapterFactory } from '@monorepo/signer-adapter/src/factory'
import { hexToBytes } from '@monorepo/common-utils'

const MNEMONIC = 'test test test test test test test test test test test junk'
const PATH = "m/44'/60'/0'/0/0"
const DIGEST = '0x' + '5a'.repeat(32)

const main = async () => {
    const getter = new GasolinaSignerAdapterGetter(
        new SignerAdapterFactory({
            walletDefinitions: [
                { name: 'wallet-CANTON', walletSetName: 'parity', byChainType: { CANTON: {} } } as any,
            ],
            mnemonicConfigs: {
                getMnemonicByName: async () => ({ mnemonic: MNEMONIC, path: PATH }),
                getMnemonicConfig: async () => ({
                    getMnemonic: async () => ({ mnemonic: MNEMONIC, path: PATH }),
                }),
            } as any,
        }),
    )
    const adapter = await getter.getSignerAdapter('canton', 'wallet-CANTON')
    const signed = await adapter.gasolinaSign({ data: hexToBytes(DIGEST) })
    const info = await adapter.getSignerInfo()
    process.stdout.write(
        JSON.stringify(
            {
                producedBy: {
                    upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                    entrypoint:
                        'packages/adapters/gasolina-signer-adapter/src/gasolinaSignerAdapterGetter.ts:getSignerAdapter (CANTON)',
                },
                mnemonic: MNEMONIC,
                derivationPath: PATH,
                digest: DIGEST,
                signature: signed.signature,
                address: signed.address,
                signerInfo: info,
            },
            null,
            1,
        ) + '\n',
    )
}

main().then(
    () => process.exit(0),
    (error) => {
        console.error(error)
        process.exit(1)
    },
)
setTimeout(() => {
    console.error('emit-canton-sign: signer never settled')
    process.exit(2)
}, 20_000)
