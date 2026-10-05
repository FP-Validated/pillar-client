// Upstream 1.2.66's Starknet source resolution: the real `EndpointV2StarknetSdk.getLZSentEvent`
// (`lz-v2-sdk/src/endpoint/starknet/index.ts:180-212`, decoder `starknet/decoders/index.ts:52-120`)
// over a scripted plain provider (not a multiprovider, so `getStarknetQuorumProvider` returns it
// unchanged) whose receipt is starknet.js's own `createTransactionReceipt` wrapper. Receipts are
// synthetic; the endpoint address, event selector, ABI and extractor are upstream's.
import { ethers } from 'ethers'
import { createTransactionReceipt, hash } from 'starknet'

import { UlnVersion } from '@monorepo/common-model'
import { chainMetadataConfigDefinition } from '@monorepo/chain-metadata-config-values'
import { LocalChainMetadataConfigGetter } from '@monorepo/dynamic-config/src/chainMetadataConfig'
import { EndpointV2StarknetSdk } from '@monorepo/lz-v2-sdk/src/endpoint/starknet'

const path = require('path')

const ENVIRONMENT = 'mainnet'
const SRC_EID = 30500
const SENDER = '0x' + '0a'.repeat(32)
const RECEIVER = '0x2222222222222222222222222222222222222222'
const MESSAGE = '0xdeadbeefcafe'
const OPTIONS = '0x00030100110100000000000000000000000000030d40'
const drop = (receiver: string, amount: string) => '010031' + '02' + amount.padStart(32, '0') + receiver.padStart(64, '0')
const DROP_OPTIONS = '0x0003' + '010011' + '01' + '000000000000000000000000000186a0' + drop('44'.repeat(20), 'c')
const TWO_DROPS = DROP_OPTIONS + drop('44'.repeat(20), 'd')
const TX = '0x' + '5a'.repeat(31)
const SEND_LIBRARY = '0x' + '3c'.repeat(31)

const packet = (nonce: number, dstEid = 30101) => {
    const guid = ethers.utils.keccak256(
        ethers.utils.solidityPack(
            ['uint64', 'uint32', 'bytes32', 'uint32', 'bytes32'],
            [nonce, SRC_EID, SENDER, dstEid, ethers.utils.hexZeroPad(RECEIVER, 32)],
        ),
    )
    return ethers.utils.solidityPack(
        ['uint8', 'uint64', 'uint32', 'bytes32', 'uint32', 'bytes32', 'bytes32', 'bytes'],
        [1, nonce, SRC_EID, SENDER, dstEid, ethers.utils.hexZeroPad(RECEIVER, 32), guid, MESSAGE],
    )
}

// Cairo `ByteArray`: full 31-byte words, the pending word and its length, as felts.
const byteArray = (hex: string): string[] => {
    const bytes = ethers.utils.arrayify(hex)
    const words: string[] = []
    let offset = 0
    for (; offset + 31 <= bytes.length; offset += 31) {
        words.push(ethers.BigNumber.from(bytes.slice(offset, offset + 31)).toHexString())
    }
    const pending = bytes.slice(offset)
    return [
        ethers.utils.hexValue(words.length),
        ...words,
        pending.length ? ethers.BigNumber.from(pending).toHexString() : '0x0',
        ethers.utils.hexValue(pending.length),
    ]
}

const main = async () => {
    const metadata = await LocalChainMetadataConfigGetter.create(
        path.join(chainMetadataConfigDefinition.dirname, ENVIRONMENT, `${chainMetadataConfigDefinition.configName}.json`),
    )
    const probe: any = new EndpointV2StarknetSdk('starknet', ENVIRONMENT, {} as any, metadata)
    const endpoint = '0x' + BigInt(probe.endpointAddress).toString(16)
    const selector = '0x' + BigInt(hash.getSelectorFromName('PacketSent')).toString(16)
    const sent = (nonce: number, fields: { options?: string; from?: string; keys?: string[]; data?: string[]; dstEid?: number } = {}) => ({
        from_address: fields.from ?? endpoint,
        keys: fields.keys ?? [selector, SEND_LIBRARY],
        data: fields.data ?? [...byteArray(packet(nonce, fields.dstEid)), ...byteArray(fields.options ?? OPTIONS)],
    })
    const receipt = (events: unknown[], extra: Record<string, unknown> = {}) => ({
        type: 'INVOKE',
        transaction_hash: TX,
        actual_fee: { amount: '0x1', unit: 'FRI' },
        execution_status: 'SUCCEEDED',
        finality_status: 'ACCEPTED_ON_L2',
        block_hash: '0x' + 'b2'.repeat(31),
        block_number: 777,
        messages_sent: [],
        events,
        execution_resources: { l1_gas: 0, l1_data_gas: 0, l2_gas: 0 },
        ...extra,
    })
    const request = (nonce: number, version = UlnVersion.V302) => ({
        pathwayId: { srcEid: SRC_EID, dstEid: 30101, sender: SENDER, receiver: RECEIVER, srcChainName: 'starknet', dstChainName: 'ethereum' },
        nonce,
        ulnSendVersion: version,
    })
    const scenarios: [string, any, any][] = [
        ['match', receipt([sent(7)]), request(7)],
        ['native drop', receipt([sent(7, { options: DROP_OPTIONS })]), request(7)],
        ['two drops to one receiver', receipt([sent(7, { options: TWO_DROPS })]), request(7)],
        ['type-1 options', receipt([sent(7, { options: '0x0001' + '30d40'.padStart(64, '0') })]), request(7)],
        ['empty options', receipt([sent(7, { options: '0x' })]), request(7)],
        ['second of two', receipt([sent(6), sent(7)]), request(7)],
        ['other nonce', receipt([sent(6)]), request(7)],
        ['V301 request', receipt([sent(7)]), request(7, UlnVersion.V301)],
        ['no events', receipt([]), request(7)],
        ['event from another contract', receipt([sent(7, { from: '0x' + '77'.repeat(31) })]), request(7)],
        ['zero-padded from_address', receipt([sent(7, { from: '0x' + endpoint.slice(2).padStart(64, '0') })]), request(7)],
        ['uppercase from_address', receipt([sent(7, { from: '0x' + endpoint.slice(2).toUpperCase() })]), request(7)],
        ['other event selector', receipt([sent(7, { keys: ['0x' + BigInt(hash.getSelectorFromName('PacketVerified')).toString(16), SEND_LIBRARY] })]), request(7)],
        ['zero-padded selector', receipt([sent(7, { keys: ['0x' + selector.slice(2).padStart(64, '0'), SEND_LIBRARY] })]), request(7)],
        ['no keys', receipt([sent(7, { keys: [] })]), request(7)],
        ['without send_library key', receipt([sent(7, { keys: [selector] })]), request(7)],
        ['truncated data', receipt([sent(7, { data: byteArray(packet(7)) })]), request(7)],
        ['malformed second event', receipt([sent(7), sent(8, { data: [] })]), request(7)],
        ['unknown destination eid', receipt([sent(7, { dstEid: 31999 })]), request(7)],
        ['reverted', receipt([sent(7)], { execution_status: 'REVERTED', revert_reason: 'boom' }), request(7)],
        ['no block hash', receipt([sent(7)], { block_hash: undefined }), request(7)],
        ['destination outside the configuration', receipt([sent(7, { dstEid: 30102 })]), { ...request(7), pathwayId: { ...request(7).pathwayId, dstEid: 30102, dstChainName: 'bsc' } }],
        ['destination on another stage', receipt([sent(7, { dstEid: 40161 })]), { ...request(7), pathwayId: { ...request(7).pathwayId, dstEid: 40161, dstChainName: 'sepolia' } }],
    ]
    const results: any[] = []
    for (const [name, raw, lzMessageId] of scenarios) {
        const calls: unknown[] = []
        const client = {
            getTransactionReceipt: async (txHash: string) => {
                calls.push({ getTransactionReceipt: txHash })
                return createTransactionReceipt(JSON.parse(JSON.stringify(raw)))
            },
        }
        const sdk = new EndpointV2StarknetSdk('starknet', ENVIRONMENT, client as any, metadata)
        let outcome
        try {
            outcome = { event: await sdk.getLZSentEvent(TX, lzMessageId as any) }
        } catch (error: any) {
            outcome = { error: String(error?.message ?? error) }
        }
        results.push({ name, receipt: JSON.parse(JSON.stringify(raw)), request: lzMessageId, calls, outcome: JSON.parse(JSON.stringify(outcome, (_, v) => (typeof v === 'bigint' ? v.toString() : v))) })
    }
    process.stdout.write(
        '@@STARKNET@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoint: 'packages/sdks/lz-v2-sdk/src/endpoint/starknet/index.ts:EndpointV2StarknetSdk.getLZSentEvent',
                        library: 'starknet 8.9.0 createTransactionReceipt; @layerzerolabs/lz-v2-utilities 3.0.168 Options',
                        synthetic: 'receipts are scripted; endpoint address, selector, ABI and extractor are upstream',
                    },
                    environment: ENVIRONMENT,
                    txHash: TX,
                    endpoint,
                    selector,
                    scenarios: results,
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
