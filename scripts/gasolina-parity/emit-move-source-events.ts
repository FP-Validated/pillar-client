// Upstream 1.2.66's Aptos-family (aptos, movement) EndpointV2-era source resolution: the real
// `EndpointV2AptosSdk.getLZSentEvent` (`lz-v2-sdk/src/endpoint/aptos/index.ts:234-256`, decoders
// `:56-148`) over a scripted plain Aptos client. The transaction and block are synthetic; the
// account addresses, event tokens and extractor are upstream's.
import { ethers } from 'ethers'

import { calculateAptosGuid } from '@monorepo/common-aptos'
import { UlnVersion } from '@monorepo/common-model'
import { chainMetadataConfigDefinition } from '@monorepo/chain-metadata-config-values'
import { LocalChainMetadataConfigGetter } from '@monorepo/dynamic-config/src/chainMetadataConfig'
import { getAptosV1LayerZeroAddress } from '@monorepo/lz-v1-sdk/src/aptos/addresses'
import { EndpointV2AptosSdk } from '@monorepo/lz-v2-sdk/src/endpoint/aptos'

const path = require('path')

const ENVIRONMENT = 'mainnet'
const SENDER = '0x' + '0a'.repeat(32)
const RECEIVER = '0x2222222222222222222222222222222222222222'
const MESSAGE = '0xdeadbeefcafe'
const OPTIONS = '0x00030100110100000000000000000000000000030d40'
const DROP_OPTIONS =
    '0x0003' + '010011' + '01' + '000000000000000000000000000186a0' + '010031' + '02' + '0000000000000000000000000000000c' + '000000000000000000000000' + '44'.repeat(20)
const BLOCK = { block_height: '777', block_hash: '0x' + 'b2'.repeat(32), first_version: '26000', last_version: '27000', block_timestamp: '1700000000000000' }

const packet = (nonce: number, srcEid: number, dstEid: number) => {
    const guid = ethers.utils.keccak256(
        ethers.utils.solidityPack(
            ['uint64', 'uint32', 'bytes32', 'uint32', 'bytes32'],
            [nonce, srcEid, SENDER, dstEid, ethers.utils.hexZeroPad(RECEIVER, 32)],
        ),
    )
    return ethers.utils.solidityPack(
        ['uint8', 'uint64', 'uint32', 'bytes32', 'uint32', 'bytes32', 'bytes32', 'bytes'],
        [1, nonce, srcEid, SENDER, dstEid, ethers.utils.hexZeroPad(RECEIVER, 32), guid, MESSAGE],
    )
}

const main = async () => {
    const metadata = await LocalChainMetadataConfigGetter.create(
        path.join(chainMetadataConfigDefinition.dirname, ENVIRONMENT, `${chainMetadataConfigDefinition.configName}.json`),
    )
    const results: any[] = []
    const tokens: Record<string, unknown> = {}
    for (const [chain, srcEid] of [
        ['aptos', 30108],
        ['movement', 30325],
    ] as [string, number][]) {
        const probe: any = new EndpointV2AptosSdk(chain, ENVIRONMENT, { rpc: {} } as any, metadata)
        const v302Token: string = probe.getPacketSentEventTokenFromUlnVersion(UlnVersion.V302)
        let v301Token: string | null = null
        try {
            v301Token = probe.getPacketSentEventTokenFromUlnVersion(UlnVersion.V301)
        } catch {
            v301Token = null
        }
        tokens[chain] = { v302: v302Token, v301: v301Token, endpointV2: probe.endpointV2Address }
        const sendLibrary = '0x' + 'c3'.repeat(32)
        const event = (type: string, data: Record<string, unknown>) => ({
            guid: { creation_number: '0', account_address: '0x0' },
            sequence_number: '0',
            type,
            data,
        })
        const v302 = (nonce: number, options = OPTIONS, extra: Record<string, unknown> = {}) =>
            event(v302Token, { encoded_packet: packet(nonce, srcEid, 30101), options, send_library: sendLibrary, ...extra })
        const request = (nonce: number, version = UlnVersion.V302, dstEid = 30101) => ({
            pathwayId: { srcEid, dstEid, sender: SENDER, receiver: RECEIVER, srcChainName: chain, dstChainName: 'ethereum' },
            nonce,
            ulnSendVersion: version,
        })
        const scenarios: [string, unknown[], any][] = [
            ['V302 match', [v302(7)], request(7)],
            ['V302 native drop', [v302(7, DROP_OPTIONS)], request(7)],
            ['V302 second of two', [v302(6), v302(7)], request(7)],
            ['V302 other nonce', [v302(6)], request(7)],
            ['V302 empty options', [v302(7, '0x')], request(7)],
            ['V302 from another module', [event(v302Token.replace(/^0x[0-9a-f]+/, '0x' + '99'.repeat(32)), { encoded_packet: packet(7, srcEid, 30101), options: OPTIONS, send_library: sendLibrary })], request(7)],
            ['V302 packet field instead of encoded_packet', [event(v302Token, { packet: packet(7, srcEid, 30101), options: OPTIONS, send_library: sendLibrary })], request(7)],
            ['V302 without a packet', [event(v302Token, { options: OPTIONS, send_library: sendLibrary })], request(7)],
            ['V302 without send_library', [event(v302Token, { encoded_packet: packet(7, srcEid, 30101), options: OPTIONS })], request(7)],
            ['no events', [], request(7)],
        ]
        if (v301Token) {
            const layerzero = getAptosV1LayerZeroAddress(ENVIRONMENT).replace(/^(0x)0*/i, '$1')
            const guid = calculateAptosGuid({
                pathwayId: { srcEid, dstEid: 101, sender: SENDER, receiver: RECEIVER, srcChainName: chain, dstChainName: 'ethereum' },
                nonce: 7,
            } as any)
            const executor = (kind: string, adapterParams: string) =>
                event(`${layerzero}::${kind}`, { guid, adapter_params: adapterParams })
            const requestEvent = executor('executor_v1::RequestEvent', '0x000100000000000249f0')
            const v301 = (options: string, ...executorEvents: unknown[]) => [
                event(v301Token, { encoded_packet: packet(7, srcEid, 101), options }),
                ...executorEvents,
            ]
            const dropParams = (amount: string, receiver: string) =>
                '0x0002' + '00000000000249f0' + amount + receiver
            for (const [name, events] of [
                ['V301 empty options with executor_v1 adapter params', v301('0x', requestEvent)],
                ['V301 executor_v1 type 2 native drop', v301('0x', executor('executor_v1::RequestEvent', dropParams('000000000000000c', '44'.repeat(20))))],
                ['V301 executor_v1 type 2 zero amount', v301('0x', executor('executor_v1::RequestEvent', dropParams('0000000000000000', '44'.repeat(20))))],
                ['V301 executor_v1 type 2 receiver of 32 bytes', v301('0x', executor('executor_v1::RequestEvent', dropParams('000000000000000c', '44'.repeat(32))))],
                ['V301 executor_v2 adapter params win over executor_v1', v301('0x', executor('executor_v2::ExecutorRequested', '0x000100000000000493e0'), requestEvent)],
                ['V301 event options merged with executor drop', v301(DROP_OPTIONS, executor('executor_v1::RequestEvent', dropParams('000000000000000c', '55'.repeat(20))))],
                ['V301 invalid adapter params', v301('0x', executor('executor_v1::RequestEvent', '0x0003000000000000000a'))],
                ['V301 without executor event', v301('0x')],
            ] as [string, unknown[]][]) {
                scenarios.push([name, events, request(7, UlnVersion.V301, 101)])
            }
        }
        for (const [name, events, lzMessageId] of scenarios) {
            const calls: unknown[] = []
            const tx = { type: 'user_transaction', version: '26629', hash: '0x' + 'aa'.repeat(32), success: true, events }
            const client = {
                getTransactionByHashOrVersion: async (args: any) => {
                    calls.push({ getTransactionByHashOrVersion: String(args.hashOrVersion) })
                    return tx
                },
                getBlockByHashOrVersion: async (args: any) => {
                    calls.push({ getBlockByHashOrVersion: String(args.hashOrVersion) })
                    return BLOCK
                },
                getTransactionByVersion: async (args: any) => {
                    calls.push({ getTransactionByVersion: String(args.ledgerVersion) })
                    return tx
                },
            }
            const sdk = new EndpointV2AptosSdk(chain, ENVIRONMENT, { rpc: client } as any, metadata)
            let outcome
            try {
                outcome = { event: await sdk.getLZSentEvent(tx.hash, lzMessageId) }
            } catch (error: any) {
                outcome = { error: String(error?.message ?? error) }
            }
            results.push({ chain, name, transaction: tx, block: BLOCK, request: lzMessageId, calls, outcome })
        }
    }
    process.stdout.write(
        '@@MOVE@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoint: 'packages/sdks/lz-v2-sdk/src/endpoint/aptos/index.ts:EndpointV2AptosSdk.getLZSentEvent',
                        synthetic: 'transactions and blocks are scripted; accounts, event tokens and extractor are upstream',
                    },
                    environment: ENVIRONMENT,
                    tokens,
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
