// Upstream 1.2.66's Aptos ULNv2 (LayerZero V1) source path, run offline: the real
// `LZAptosSdk.getLZSentEventFromSrcTxHash` and `getDerivedHash` over a scripted plain Aptos
// client (a non-multiprovider client passes straight through `getAptosQuorumProvider`,
// `multiprovider/src/quorumProvider.ts`), then the real `GasolinaEvmSdk.buildULNV2VerifyPayload`
// for the EVM destination. The packet is the one upstream's own tests use
// (`packages/common-aptos/tests/index.test.ts`: version 26629, 108 -> 110, nonce 26733); the
// transaction and block wrapped around it are synthetic and recorded with every request made.
import { LZAptosSdk } from '@monorepo/lz-v1-sdk/src/aptos/aptos'
import { getVId } from '@monorepo/static-config'

import { GasolinaEvmSdk } from '../src/app/sdks/gasolinaSdk/evm'

const ENVIRONMENT = 'mainnet'
const ACCOUNT = '0x54ad3d30af77b60d939ae356e6606de9a4da67583f02b962d2d3f2e481484e90'
const TEST_PACKET =
    '0x000000000000686d006cf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa006e1bacc2205312534375c8d1801c27d28370656cff0100000000000000000000000082af49447d8a07e3bd95bd0d56f35241523fbab10000000000000000000000005e5878e61a4b3d83eb43aea9eee76e2c3fa97f4100000000000010a901'
// The same packet with its source chain id rewritten from 108 (0x006c) to 109.
const FOREIGN_SOURCE_PACKET = TEST_PACKET.replace('686d006c', '686d006d')
const OTHER_NONCE_PACKET = TEST_PACKET.replace('000000000000686d', '000000000000686e')
const BLOCK = { block_height: '12345', block_hash: '0x' + 'b1'.repeat(32), block_timestamp: '1700000000000000' }

const outbound = (encoded: string, account = ACCOUNT) => ({
    version: '26629',
    guid: { creation_number: '9', account_address: account },
    sequence_number: '0',
    type: `${account}::packet_event::OutboundEvent`,
    data: { encoded_packet: encoded },
})
const transaction = (events: unknown[]) => ({ type: 'user_transaction', version: '26629', hash: '0x' + 'aa'.repeat(32), success: true, events })

const REQUEST = {
    pathwayId: {
        srcEid: 108,
        dstEid: 110,
        sender: '0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa',
        receiver: '0x1bacc2205312534375c8d1801c27d28370656cff',
        srcChainName: 'aptos',
        dstChainName: 'arbitrum',
    },
    nonce: 26733,
    ulnSendVersion: 'V2',
}

const run = async (name: string, srcTxHash: string, events: unknown[], request = REQUEST) => {
    const requests: string[] = []
    const client = {
        getTransactionByVersion: async ({ ledgerVersion }: { ledgerVersion: bigint }) => {
            requests.push(`transactions/by_version/${ledgerVersion}`)
            return transaction(events)
        },
        getBlockByVersion: async ({ ledgerVersion }: { ledgerVersion: number }) => {
            requests.push(`blocks/by_version/${ledgerVersion}`)
            return BLOCK
        },
    }
    const sdk = new LZAptosSdk('aptos', ENVIRONMENT, { rpc: client } as any, {} as any)
    try {
        const event = await sdk.getLZSentEventFromSrcTxHash(srcTxHash, request as any)
        const derived = await sdk.getDerivedHash({
            srcTxHash,
            lzMessage: event,
            inboundConfig: { proofType: '2', utilsVersion: 1 } as any,
        })
        let mptProofType: unknown
        try {
            await sdk.getDerivedHash({ srcTxHash, lzMessage: event, inboundConfig: { proofType: '1', utilsVersion: 1 } as any })
        } catch (error: any) {
            mptProofType = { error: error.message }
        }
        const vId = getVId(event.lzMessageId.pathwayId.dstChainName, ENVIRONMENT)
        const built = await new GasolinaEvmSdk(ENVIRONMENT, event.lzMessageId.pathwayId.dstChainName, {} as any).buildULNV2VerifyPayload(
            event as any,
            derived as any,
            15,
            1_900_000_000,
            vId,
        )
        return { name, srcTxHash, events, request, requests, outcome: { ok: { event, derived, mptProofType, vId, hashCallData: built.hashCallData, details: built.details } } }
    } catch (error: any) {
        return { name, srcTxHash, events, request, requests, outcome: { error: String(error?.message ?? error) } }
    }
}

const main = async () => {
    const scenarios = [
        await run('match', '26629', [outbound(TEST_PACKET)]),
        await run('hex version', '0x6805', [outbound(TEST_PACKET)]),
        await run('second of two', '26629', [outbound(OTHER_NONCE_PACKET), outbound(TEST_PACKET)]),
        await run('other nonce only', '26629', [outbound(OTHER_NONCE_PACKET)]),
        await run('foreign account', '26629', [outbound(TEST_PACKET, '0x' + '11'.repeat(32))]),
        await run('foreign source chain id', '26629', [outbound(FOREIGN_SOURCE_PACKET)]),
        await run('no events', '26629', []),
        await run('not a version', 'abc', [outbound(TEST_PACKET)]),
    ]
    process.stdout.write(
        '@@APTOS@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoints: [
                            'packages/sdks/lz-v1-sdk/src/aptos/aptos.ts:getLZSentEventFromSrcTxHash',
                            'packages/sdks/lz-v1-sdk/src/aptos/aptos.ts:getDerivedHash',
                            'apps/gasolina/src/app/sdks/gasolinaSdk/evm/index.ts:buildULNV2VerifyPayload',
                        ],
                        packetSource: 'packages/common-aptos/tests/index.test.ts (event version 26629)',
                        synthetic: 'transaction wrapper, block, account substitution and the tampered variants',
                    },
                    environment: ENVIRONMENT,
                    account: ACCOUNT,
                    block: BLOCK,
                    scenarios,
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
