// Upstream 1.2.66's Initia source resolution: the real `EndpointV2AptosSdk.getLZSentEvent` for chain
// `initia` (`lz-v2-sdk/src/endpoint/factory.ts:66-73`, `endpoint/aptos/index.ts:234-256`), whose events
// come from `common-initia/src/events.ts:45-92`, over a scripted plain Initia client. Transactions
// and blocks are synthetic; the account addresses, event tokens and extractor are upstream's.
import { ethers } from 'ethers'

import { UlnVersion } from '@monorepo/common-model'
import { chainMetadataConfigDefinition } from '@monorepo/chain-metadata-config-values'
import { LocalChainMetadataConfigGetter } from '@monorepo/dynamic-config/src/chainMetadataConfig'
import { EndpointV2AptosSdk } from '@monorepo/lz-v2-sdk/src/endpoint/aptos'

const path = require('path')

const ENVIRONMENT = 'mainnet'
const CHAIN = 'initia'
const SRC_EID = 30326
const SENDER = '0x' + '0a'.repeat(32)
const RECEIVER = '0x2222222222222222222222222222222222222222'
const MESSAGE = '0xdeadbeefcafe'
const OPTIONS = '0x00030100110100000000000000000000000000030d40'
const DROP_OPTIONS =
    '0x0003' + '010011' + '01' + '000000000000000000000000000186a0' + '010031' + '02' + '0000000000000000000000000000000c' + '000000000000000000000000' + '44'.repeat(20)
const TX = 'AB'.repeat(32)
const BLOCK = { block_height: '777', block_hash: 'B2'.repeat(32) }
const SEND_LIBRARY = '0x' + 'c3'.repeat(32)

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

const main = async () => {
    const metadata = await LocalChainMetadataConfigGetter.create(
        path.join(chainMetadataConfigDefinition.dirname, ENVIRONMENT, `${chainMetadataConfigDefinition.configName}.json`),
    )
    const probe: any = new EndpointV2AptosSdk(CHAIN, ENVIRONMENT, { rpc: {} } as any, metadata)
    const token: string = probe.getPacketSentEventTokenFromUlnVersion(UlnVersion.V302)
    let v301Token: string | null = null
    try {
        v301Token = probe.getPacketSentEventTokenFromUlnVersion(UlnVersion.V301)
    } catch {
        v301Token = null
    }
    const [account, ...rest] = token.split('::')
    const moveEvent = (typeTag: string, data: unknown, kind = 'move') => ({
        type: kind,
        attributes: [
            { key: 'type_tag', value: typeTag },
            ...(data === undefined ? [] : [{ key: 'data', value: typeof data === 'string' ? data : JSON.stringify(data) }]),
        ],
    })
    const sent = (nonce: number, fields: Record<string, unknown> = {}) =>
        moveEvent(token, { encoded_packet: packet(nonce), options: OPTIONS, send_library: SEND_LIBRARY, ...fields })
    const request = (nonce: number, version = UlnVersion.V302) => ({
        pathwayId: { srcEid: SRC_EID, dstEid: 30101, sender: SENDER, receiver: RECEIVER, srcChainName: CHAIN, dstChainName: 'ethereum' },
        nonce,
        ulnSendVersion: version,
    })
    const unpadded = '0x' + account.slice(2).replace(/^0+/, '')
    const scenarios: [string, unknown[], any][] = [
        ['match', [sent(7)], request(7)],
        ['native drop', [sent(7, { options: DROP_OPTIONS })], request(7)],
        ['second of two', [sent(6), sent(7)], request(7)],
        ['other nonce', [sent(6)], request(7)],
        ['empty options', [sent(7, { options: '0x' })], request(7)],
        ['no events', [], request(7)],
        ['event from another account', [moveEvent(['0x' + '99'.repeat(32), ...rest].join('::'), { encoded_packet: packet(7), options: OPTIONS, send_library: SEND_LIBRARY })], request(7)],
        ['uppercase type tag', [moveEvent(token.toUpperCase().replace('0X', '0x'), { encoded_packet: packet(7), options: OPTIONS, send_library: SEND_LIBRARY })], request(7)],
        ['unpadded account', [moveEvent([unpadded, ...rest].join('::'), { encoded_packet: packet(7), options: OPTIONS, send_library: SEND_LIBRARY })], request(7)],
        ['not a move event', [moveEvent(token, { encoded_packet: packet(7), options: OPTIONS, send_library: SEND_LIBRARY }, 'wasm')], request(7)],
        ['without a data attribute', [moveEvent(token, undefined)], request(7)],
        ['data not JSON', [moveEvent(token, '{not json')], request(7)],
        ['packet field instead of encoded_packet', [moveEvent(token, { packet: packet(7), options: OPTIONS, send_library: SEND_LIBRARY })], request(7)],
        ['without a packet', [moveEvent(token, { options: OPTIONS, send_library: SEND_LIBRARY })], request(7)],
        ['without send_library', [sent(7, { send_library: undefined })], request(7)],
        ['V301 request', [sent(7)], request(7, UlnVersion.V301)],
        ['unknown destination eid', [moveEvent(token, { encoded_packet: packet(7, 31999), options: OPTIONS, send_library: SEND_LIBRARY })], request(7)],
    ]
    const results: any[] = []
    for (const [name, events, lzMessageId] of scenarios) {
        const calls: unknown[] = []
        const tx = { txhash: TX, height: '777', code: 0, events }
        const client = {
            getTransactionByHashOrVersion: async (args: any) => {
                calls.push({ getTransactionByHashOrVersion: String(args.hashOrVersion) })
                return tx
            },
            getBlockByHashOrVersion: async (args: any) => {
                calls.push({ getBlockByHashOrVersion: String(args.hashOrVersion) })
                return BLOCK
            },
        }
        const sdk = new EndpointV2AptosSdk(CHAIN, ENVIRONMENT, { rpc: client } as any, metadata)
        let outcome
        try {
            outcome = { event: await sdk.getLZSentEvent(TX, lzMessageId as any) }
        } catch (error: any) {
            outcome = { error: String(error?.message ?? error) }
        }
        results.push({ name, transaction: tx, block: BLOCK, request: lzMessageId, calls, outcome })
    }
    process.stdout.write(
        '@@INITIA@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoint: 'packages/sdks/lz-v2-sdk/src/endpoint/aptos/index.ts:EndpointV2AptosSdk.getLZSentEvent (chain initia)',
                        synthetic: 'transactions and blocks are scripted; accounts, event tokens and extractor are upstream',
                    },
                    environment: ENVIRONMENT,
                    tokens: { v302: token, v301: v301Token },
                    txHash: TX,
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
