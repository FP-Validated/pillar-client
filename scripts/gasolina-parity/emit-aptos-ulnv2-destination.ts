// Upstream 1.2.66's ULN V2 path for an EVM source and an Aptos destination, run offline, every
// step upstream's own code:
//  - routing: `getUlnReceiveDetails` (`lz-v2-sdk/src/uln/move/index.ts:137-194`) over a scripted view,
//    the step `app.ts:263-271` consults for a V2 send;
//  - the lookup hash: the EVM `FeatherProofBuilder.deriveHash` (`lz-v1-sdk/src/evm/proof/fp.ts:41-65`)
//    with the inbound config Aptos's `getInboundConfig` returns (`lz-v1-sdk/src/aptos/aptos.ts:592-596`:
//    proofType '2', utilsVersion 2), and `proofUtils.getFeatherProof` itself for both utils versions;
//  - the vId: `getVId(skipVId, ...)` (`hashCallDataBuilder/utils.ts`);
//  - the payload: `GasolinaAptosSdk.buildULNV2VerifyPayload` (`gasolinaSdk/aptos/index.ts:35-73`);
//  - the signature: the Aptos signer adapter over a well-known test mnemonic, as `app.ts` signs.
import { proofUtils } from '@monorepo/layerzero-core-contracts'
import { buildPacketPayloadV2 } from '@monorepo/lz-v1-sdk/src/evm/encoders'
import { FeatherProofBuilder } from '@monorepo/lz-v1-sdk/src/evm/proof/fp'
import { getUlnReceiveDetails } from '@monorepo/lz-v2-sdk/src/uln/move'
import { GasolinaSignerAdapterGetter } from '@monorepo/gasolina-signer-adapter'
import { SignerAdapterFactory } from '@monorepo/signer-adapter/src/factory'
import { hexToBytes } from '@monorepo/common-utils'
import type { Mnemonic, MnemonicConfig } from '@monorepo/common-model'
import type { WalletDefinition } from '@monorepo/wallet-config-models'

import { GasolinaAptosSdk } from '../src/app/sdks/gasolinaSdk/aptos'
import { getVId } from '../src/app/hashCallDataBuilder/utils'

const MNEMONIC = 'test test test test test test test test test test test junk'
const APTOS_PATH = "m/44'/637'/0'/0'/0'"
const mnemonic: Mnemonic = { mnemonic: MNEMONIC, path: APTOS_PATH }
const mnemonicConfigs = {
    async getMnemonicByName(): Promise<Mnemonic> {
        return mnemonic
    },
    async getMnemonicConfig(): Promise<MnemonicConfig> {
        return { getMnemonic: async () => mnemonic }
    },
}
const walletDefinitions: WalletDefinition[] = [
    { name: 'wallet-APTOS', walletSetName: 'parity', byChainType: { APTOS: {} } } as any,
]
const signerGetter = new GasolinaSignerAdapterGetter(new SignerAdapterFactory({ walletDefinitions, mnemonicConfigs }))

const ULN_V2_ETHEREUM = '0x4d73adb72bc3dd368966edd0f0b2148401a178e2'
const PATHWAYS = {
    mainnet: { srcChainName: 'ethereum', srcEid: 101, dstEid: 108 },
    testnet: { srcChainName: 'sepolia', srcEid: 10161, dstEid: 10108 },
} as const
const SENDER = '0x50002cdfe7ccb0c41f519c6eb0653158d11cd907'
const RECEIVER = '0x' + '7a'.repeat(32)
const MESSAGE = '0x01000000000000000000000000000000000000000000000000000000000000002a'

const sentEvent = (environment: keyof typeof PATHWAYS, nonce: number, message = MESSAGE) => {
    const p = PATHWAYS[environment]
    return {
        lzMessageId: {
            pathwayId: { srcEid: p.srcEid, dstEid: p.dstEid, sender: SENDER, receiver: RECEIVER, srcChainName: p.srcChainName, dstChainName: 'aptos' },
            nonce,
            ulnSendVersion: 'V2',
        },
        message,
        packetEmitAddress: ULN_V2_ETHEREUM,
    }
}

const sign = async (hashCallData: string) => {
    const adapter = await signerGetter.getSignerAdapter('aptos', 'wallet-APTOS')
    const signed = await adapter.gasolinaSign({ data: hexToBytes(hashCallData) })
    return { signature: signed.signature, signerAddress: signed.address }
}

const main = async () => {
    const routing: any[] = []
    for (const [environment, answer] of [
        ['mainnet', ['2', 0]],
        ['mainnet', ['1', 0]],
        ['mainnet', ['2', 1]],
        ['testnet', ['2', 0]],
        ['testnet', ['1', 0]],
    ] as [keyof typeof PATHWAYS, unknown[]][]) {
        const calls: unknown[] = []
        const provider = {
            view: async (args: any) => {
                calls.push(args.payload)
                return answer
            },
        }
        const p = PATHWAYS[environment]
        let outcome
        try {
            outcome = await getUlnReceiveDetails({
                provider: provider as any,
                environment,
                pathwayId: { srcEid: p.srcEid, dstEid: p.dstEid, sender: SENDER, receiver: RECEIVER, srcChainName: p.srcChainName, dstChainName: 'aptos' } as any,
            })
        } catch (error: any) {
            outcome = { error: String(error?.message ?? error) }
        }
        routing.push({ environment, answer, calls: JSON.parse(JSON.stringify(calls)), outcome })
    }

    const payloads: any[] = []
    for (const [name, environment, nonce, message, blockConfirmation, expiration, skipVId] of [
        ['mainnet skipVId', 'mainnet', 7, MESSAGE, 15, 1712345678, true],
        ['mainnet skipVId, empty message', 'mainnet', 8, '0x', 1, 1900000000, true],
        ['mainnet skipVId, other confirmations', 'mainnet', 7, MESSAGE, 260, 1712345678, true],
        ['testnet skipVId', 'testnet', 7, MESSAGE, 15, 1712345678, true],
        ['mainnet with vId', 'mainnet', 7, MESSAGE, 15, 1712345678, false],
        ['testnet with vId', 'testnet', 7, MESSAGE, 15, 1712345678, false],
    ] as [string, keyof typeof PATHWAYS, number, string, number, number, boolean][]) {
        const event = sentEvent(environment, nonce, message)
        const builder = new FeatherProofBuilder({} as any)
        const inboundConfig = { proofType: '2', utilsVersion: 2 } as any
        const derived = await builder.deriveHash({ inboundConfig, lzMessage: event as any } as any)
        const p = PATHWAYS[environment]
        let packetPayload: string | null = null
        try {
            packetPayload = buildPacketPayloadV2({ pathwayId: event.lzMessageId.pathwayId, nonce, message })
        } catch {
            packetPayload = null
        }
        const proofs: Record<string, unknown> = {}
        for (const utilsVersion of [1, 2, 3]) {
            try {
                proofs[`utils${utilsVersion}`] = (await proofUtils.getFeatherProof(utilsVersion, ULN_V2_ETHEREUM, packetPayload as string)).proof
            } catch (error: any) {
                proofs[`utils${utilsVersion}`] = { error: String(error?.message ?? error) }
            }
        }
        const vId = getVId(skipVId, 'aptos', environment)
        const sdk = new GasolinaAptosSdk(environment, 'aptos', {} as any)
        let outcome
        try {
            const built = await sdk.buildULNV2VerifyPayload(event as any, derived, blockConfirmation, expiration, vId)
            outcome = { built, signed: await sign(built.hashCallData) }
        } catch (error: any) {
            outcome = { error: String(error?.message ?? error) }
        }
        payloads.push({ name, environment, srcEid: p.srcEid, dstEid: p.dstEid, nonce, message, blockConfirmation, expiration, skipVId, vId, sentEvent: event, packetPayload, proofs, derived, outcome })
    }
    process.stdout.write(
        '@@APTOSV2@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoints: [
                            'packages/sdks/lz-v2-sdk/src/uln/move/index.ts:getUlnReceiveDetails',
                            'packages/sdks/lz-v1-sdk/src/evm/proof/fp.ts:FeatherProofBuilder.deriveHash',
                            'packages/contracts/layerzero-core:proofUtils.getFeatherProof',
                            'apps/gasolina/src/app/hashCallDataBuilder/utils.ts:getVId',
                            'apps/gasolina/src/app/sdks/gasolinaSdk/aptos/index.ts:buildULNV2VerifyPayload',
                            'packages/adapters/gasolina-signer-adapter/src/gasolinaSignerAdapter.ts:gasolinaSign',
                        ],
                        inboundConfig: "aptos.ts:592-596 constants (proofType '2', utilsVersion 2), not read through a scripted Aptos client",
                        mnemonic: MNEMONIC,
                        derivationPath: APTOS_PATH,
                        synthetic: 'sent events and view answers are scripted',
                    },
                    routing,
                    payloads,
                },
                null,
                1,
            ) +
            '\n',
    )
}

main().then(
    () => process.exit(0),
    (error) => {
        console.error(error)
        process.exit(1)
    },
)
