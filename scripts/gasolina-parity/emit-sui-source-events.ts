// Upstream 1.2.66's Sui-family (sui, iotal1) source resolution: the real
// `EndpointV2SuiSdk`/`EndpointV2IotaSdk.getLZSentEvent` (`lz-v2-sdk/src/endpoint/sui/index.ts:197-257,789`),
// whose events go through the Aptos-family extractor (`endpoint/aptos/decoders/index.ts:56-148`), over
// a scripted plain client (not a multiprovider, so `getSuiMoveQuorumProvider` returns it unchanged).
// The `queryEvents` answers are synthetic; the package ids, event types and extractor are upstream's.
import { ethers } from 'ethers'

import { UlnVersion } from '@monorepo/common-model'
import { chainMetadataConfigDefinition } from '@monorepo/chain-metadata-config-values'
import { LocalChainMetadataConfigGetter } from '@monorepo/dynamic-config/src/chainMetadataConfig'
import { EndpointV2IotaSdk, EndpointV2SuiSdk } from '@monorepo/lz-v2-sdk/src/endpoint/sui'
import { EndpointV2EventResources, EndpointV2Modules } from '@monorepo/sui-contracts'

const path = require('path')

const ENVIRONMENT = 'mainnet'
const SENDER = '0x' + '0a'.repeat(32)
const RECEIVER = '0x2222222222222222222222222222222222222222'
const MESSAGE = '0xdeadbeefcafe'
const OPTIONS = '0x00030100110100000000000000000000000000030d40'
const DROP_OPTIONS =
    '0x0003' + '010011' + '01' + '000000000000000000000000000186a0' + '010031' + '02' + '0000000000000000000000000000000c' + '000000000000000000000000' + '44'.repeat(20)
const DIGEST = '8Zs3hRk1vYqkm8tQpDq3tJ2W9fXGzH1yUuP6cN4bLwEa'
const bytes = (hex: string) => Array.from(ethers.utils.arrayify(hex))

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
    for (const [chain, srcEid, Sdk] of [
        ['sui', 30378, EndpointV2SuiSdk],
        ['iotal1', 30423, EndpointV2IotaSdk],
    ] as [string, number, typeof EndpointV2SuiSdk][]) {
        const probe: any = new Sdk(chain, ENVIRONMENT, {} as any, metadata)
        const packageId: string = probe.endpointV2PackageId
        const type = `${packageId}::${EndpointV2Modules.messaging_channel}::${EndpointV2EventResources.PacketSent}`
        tokens[chain] = { packetSent: type }
        const sendLibrary = '0x' + 'c3'.repeat(32)
        let seq = 0
        const event = (eventType: string, parsedJson: unknown) => ({
            id: { txDigest: DIGEST, eventSeq: String(seq++) },
            packageId,
            transactionModule: 'endpoint_v2',
            sender: '0x' + '0b'.repeat(32),
            type: eventType,
            parsedJson,
        })
        const sent = (nonce: number, fields: Record<string, unknown> = {}) =>
            event(type, { encoded_packet: bytes(packet(nonce, srcEid, 30101)), options: bytes(OPTIONS), send_library: sendLibrary, ...fields })
        const request = (nonce: number, version = UlnVersion.V302) => ({
            pathwayId: { srcEid, dstEid: 30101, sender: SENDER, receiver: RECEIVER, srcChainName: chain, dstChainName: 'ethereum' },
            nonce,
            ulnSendVersion: version,
        })
        const scenarios: [string, unknown[], any][] = [
            ['V302 match', [sent(7)], request(7)],
            ['V302 native drop', [sent(7, { options: bytes(DROP_OPTIONS) })], request(7)],
            ['V302 second of two', [sent(6), sent(7)], request(7)],
            ['V302 other nonce', [sent(6)], request(7)],
            ['V301 request for a V302 event', [sent(7)], request(7, UlnVersion.V301)],
            ['no events', [], request(7)],
            ['event from another package', [event(type.replace(packageId, '0x' + '99'.repeat(32)), { encoded_packet: bytes(packet(7, srcEid, 30101)), options: bytes(OPTIONS), send_library: sendLibrary })], request(7)],
            ['uppercase package id', [event(type.replace(packageId, packageId.toUpperCase().replace('0X', '0x')), { encoded_packet: bytes(packet(7, srcEid, 30101)), options: bytes(OPTIONS), send_library: sendLibrary })], request(7)],
            ['lowercase event name', [event(type.replace(/::[A-Za-z]+$/, (name) => name.toLowerCase()), { encoded_packet: bytes(packet(7, srcEid, 30101)), options: bytes(OPTIONS), send_library: sendLibrary })], request(7)],
            ['event named PacketSent', [event(`${packageId}::${EndpointV2Modules.messaging_channel}::PacketSent`, { encoded_packet: bytes(packet(7, srcEid, 30101)), options: bytes(OPTIONS), send_library: sendLibrary })], request(7)],
            ['null parsedJson', [event(type, null)], request(7)],
            ['without send_library', [sent(7, { send_library: undefined })], request(7)],
            ['empty send_library', [sent(7, { send_library: '' })], request(7)],
            ['short send_library', [sent(7, { send_library: '0x4444' })], request(7)],
            ['empty options', [sent(7, { options: [] })], request(7)],
            ['options as hex string', [sent(7, { options: OPTIONS })], request(7)],
            ['options as a type-1 digit string', [sent(7, { options: '01' + '0'.repeat(31) + 'a' })], request(7)],
            ['packet field instead of encoded_packet', [event(type, { packet: bytes(packet(7, srcEid, 30101)), options: bytes(OPTIONS), send_library: sendLibrary })], request(7)],
            ['encoded_packet as hex string', [sent(7, { encoded_packet: packet(7, srcEid, 30101) })], request(7)],
            ['without a packet', [event(type, { options: bytes(OPTIONS), send_library: sendLibrary })], request(7)],
            ['malformed second event', [sent(7), event(type, { options: bytes(OPTIONS), send_library: sendLibrary })], request(7)],
        ]
        for (const [name, events, lzMessageId] of scenarios) {
            const calls: unknown[] = []
            const response = { data: events, hasNextPage: false, nextCursor: null }
            const client = {
                queryEvents: async (args: any) => {
                    calls.push({ queryEvents: args })
                    return response
                },
            }
            const sdk = new Sdk(chain, ENVIRONMENT, client as any, metadata)
            let outcome
            try {
                outcome = { event: await sdk.getLZSentEvent(DIGEST, lzMessageId as any) }
            } catch (error: any) {
                outcome = { error: String(error?.message ?? error) }
            }
            results.push({ chain, name, response: JSON.parse(JSON.stringify(response)), request: lzMessageId, calls, outcome })
        }
    }
    process.stdout.write(
        '@@SUI@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoint: 'packages/sdks/lz-v2-sdk/src/endpoint/sui/index.ts:EndpointV2SuiSdk.getLZSentEvent (EndpointV2IotaSdk for iotal1)',
                        synthetic: 'queryEvents answers are scripted; package ids, event types and extractor are upstream',
                    },
                    environment: ENVIRONMENT,
                    digest: DIGEST,
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
