// Upstream 1.2.66's decoding of EndpointV2 `PacketSent` options: the real
// `EndpointV2EvmSdk.getLZSentEvent` whose extractor runs `extractOptionsFromLZSentEvent`
// (`lz-v2-sdk/src/endpoint/evm/decoders/index.ts:96-142`, lz-v2-utilities 3.0.168 `Options`),
// over one scripted receipt per options vector. A throw inside the extractor is swallowed by
// `getLZSentEvent`, so an undecodable vector surfaces as `Packet does not match lzMessageId`.
import { ethers } from 'ethers'

import { EndpointVersion, UlnVersion } from '@monorepo/common-model'
import { chainMetadataConfigDefinition } from '@monorepo/chain-metadata-config-values'
import { LocalChainMetadataConfigGetter } from '@monorepo/dynamic-config/src/chainMetadataConfig'
import { EndpointV2EvmSdk } from '@monorepo/lz-v2-sdk/src/endpoint/evm'
import { getReadLib1002ContractAddress, getSendUln302ContractAddress } from '@monorepo/lz-evm-sdk-v2-contracts'

const path = require('path')

const ENVIRONMENT = 'mainnet'
const SENDER = '0x1111111111111111111111111111111111111111'
const EVM_RECEIVER = '0x2222222222222222222222222222222222222222'
const SOLANA_RECEIVER = '0x' + '33'.repeat(32)
const MESSAGE = '0xdeadbeefcafe'
const TX = '0x' + '7a'.repeat(32)
const READ_CHANNEL = 4294967295

const u = (bits: number, value: bigint | number) => ethers.utils.hexZeroPad(ethers.BigNumber.from(value).toHexString(), bits / 8).slice(2)
const executor = (type: number, params: string) => '01' + u(16, params.length / 2 + 1) + u(8, type) + params
const verifier = (index: number, type: number, params: string) => '02' + u(16, params.length / 2 + 2) + u(8, index) + u(8, type) + params
const type3 = (...entries: string[]) => '0x0003' + entries.join('')
const drop = (amount: number, receiver: string) => u(128, amount) + ethers.utils.hexZeroPad(receiver, 32).slice(2)

const VECTORS: [string, string, string][] = [
    ['lzReceive gas', type3(executor(1, u(128, 200000))), 'ethereum'],
    ['lzReceive gas and value', type3(executor(1, u(128, 200000) + u(128, 7))), 'ethereum'],
    ['two lzReceive summed', type3(executor(1, u(128, 100)), executor(1, u(128, 50) + u(128, 3))), 'ethereum'],
    ['lzReceive 20-byte params', type3(executor(1, u(128, 9) + 'aabbccdd')), 'ethereum'],
    ['lzReceive 15-byte params', type3(executor(1, u(128, 9).slice(2))), 'ethereum'],
    ['lzReceive empty params', type3(executor(1, '')), 'ethereum'],
    ['ordered only', type3(executor(4, '')), 'ethereum'],
    ['lzReceive and ordered', type3(executor(1, u(128, 5)), executor(4, '')), 'ethereum'],
    [
        'native drops summed by receiver',
        type3(
            executor(2, drop(10, '0x' + '44'.repeat(20))),
            executor(2, drop(5, '0x' + '55'.repeat(20))),
            executor(2, drop(1, '0x' + '44'.repeat(20))),
        ),
        'ethereum',
    ],
    ['native drop to solana', type3(executor(1, u(128, 1)), executor(2, drop(2, '0x' + '66'.repeat(32)))), 'solana'],
    ['native drop short receiver', type3(executor(2, u(128, 3) + 'abcd')), 'ethereum'],
    [
        'compose summed by index, out of order',
        type3(executor(3, u(16, 2) + u(128, 10)), executor(3, u(16, 0) + u(128, 1) + u(128, 4)), executor(3, u(16, 2) + u(128, 5))),
        'ethereum',
    ],
    ['compose 33-byte params', type3(executor(3, u(16, 1) + u(128, 1) + 'ff'.repeat(15))), 'ethereum'],
    ['verifier precrime ignored', type3(verifier(0, 1, ''), executor(1, u(128, 8))), 'ethereum'],
    ['unknown worker id', type3('03' + u(16, 2) + 'abcd', executor(1, u(128, 8))), 'ethereum'],
    ['truncated size', '0x0003' + '01' + '00', 'ethereum'],
    ['truncated option type', '0x0003' + '01' + u(16, 1), 'ethereum'],
    ['type 1', '0x0001' + u(256, 300000), 'ethereum'],
    ['type 1 over uint128', '0x0001' + 'ff'.repeat(32), 'ethereum'],
    ['type 2', '0x0002' + u(256, 300000) + u(256, 12) + '77'.repeat(20), 'ethereum'],
    ['type 2 empty receiver', '0x0002' + u(256, 300000) + u(256, 12), 'ethereum'],
    ['type 2 long receiver', '0x0002' + u(256, 1) + u(256, 1) + '88'.repeat(33), 'ethereum'],
    ['type 2 short', '0x0002' + u(256, 1), 'ethereum'],
    ['unknown type', '0x0004' + 'ff', 'ethereum'],
    ['one byte', '0x05', 'ethereum'],
    ['empty', '0x', 'ethereum'],
    ['type 3 with no options', '0x0003', 'ethereum'],
]
const READ_VECTORS: [string, string][] = [
    ['lzRead', type3(executor(5, u(128, 1000) + u(32, 64)))],
    ['lzRead with value', type3(executor(5, u(128, 1000) + u(32, 64) + u(128, 2)))],
    ['two lzRead summed', type3(executor(5, u(128, 1) + u(32, 2)), executor(5, u(128, 3) + u(32, 4)))],
    ['lzRead 18-byte params', type3(executor(5, u(128, 1) + 'abcd'))],
    ['lzRead and lzReceive', type3(executor(5, u(128, 1) + u(32, 2)), executor(1, u(128, 1)))],
]

const bytes32 = (address: string) => ethers.utils.hexZeroPad(address, 32)
const packet = (srcEid: number, dstEid: number, receiver: string) => {
    const guid = ethers.utils.keccak256(
        ethers.utils.solidityPack(['uint64', 'uint32', 'bytes32', 'uint32', 'bytes32'], [7, srcEid, bytes32(SENDER), dstEid, bytes32(receiver)]),
    )
    return ethers.utils.solidityPack(
        ['uint8', 'uint64', 'uint32', 'bytes32', 'uint32', 'bytes32', 'bytes32', 'bytes'],
        [1, 7, srcEid, bytes32(SENDER), dstEid, bytes32(receiver), guid, MESSAGE],
    )
}

class ScriptedProvider extends ethers.providers.JsonRpcProvider {
    constructor(private receipt: unknown) {
        super('http://scripted.invalid', { chainId: 56, name: 'bnb' })
    }
    async detectNetwork() {
        return { chainId: 56, name: 'bnb' }
    }
    async send(method: string): Promise<any> {
        if (method === 'eth_blockNumber') return '0x2000'
        if (method === 'eth_getTransactionReceipt') return this.receipt
        throw new Error(`unscripted ${method}`)
    }
}

const receiptWith = (log: { address: string; topics: string[]; data: string }) => ({
    transactionHash: TX,
    transactionIndex: '0x0',
    blockHash: '0x' + 'ab'.repeat(32),
    blockNumber: '0x1000',
    from: SENDER,
    to: SENDER,
    cumulativeGasUsed: '0x1',
    gasUsed: '0x1',
    contractAddress: null,
    logs: [{ ...log, blockNumber: '0x1000', blockHash: '0x' + 'ab'.repeat(32), transactionHash: TX, transactionIndex: '0x0', logIndex: '0x0', removed: false }],
    logsBloom: '0x' + '00'.repeat(256),
    status: '0x1',
    type: '0x0',
    effectiveGasPrice: '0x1',
})

const main = async () => {
    const metadata = await LocalChainMetadataConfigGetter.create(
        path.join(chainMetadataConfigDefinition.dirname, ENVIRONMENT, `${chainMetadataConfigDefinition.configName}.json`),
    )
    const probe: any = new EndpointV2EvmSdk('bsc', ENVIRONMENT, new ScriptedProvider(null), metadata)
    const endpoint: ethers.Contract = probe.getSendContracts(EndpointVersion.V2)
    const run = async (options: string, library: string, srcEid: number, dstEid: number, receiver: string, request: any) => {
        const log = {
            address: endpoint.address,
            ...endpoint.interface.encodeEventLog(endpoint.interface.getEvent('PacketSent'), [packet(srcEid, dstEid, receiver), options, library]),
        }
        const receipt = receiptWith(log)
        const sdk = new EndpointV2EvmSdk('bsc', ENVIRONMENT, new ScriptedProvider(receipt), metadata)
        try {
            const event: any = await sdk.getLZSentEvent(TX, request)
            return { receipt, request, outcome: { options: event.options ?? null, optionsJson: JSON.stringify(event.options) } }
        } catch (error: any) {
            return { receipt, request, outcome: { error: String(error?.message ?? error) } }
        }
    }
    const results = []
    for (const [name, options, dst] of VECTORS) {
        const dstEid = dst === 'solana' ? 30168 : 30101
        const receiver = dst === 'solana' ? SOLANA_RECEIVER : EVM_RECEIVER
        const request = {
            pathwayId: { srcEid: 30102, dstEid, sender: SENDER, receiver: dst === 'solana' ? ethers.utils.base58.encode(receiver) : receiver, srcChainName: 'bsc', dstChainName: dst },
            nonce: 7,
            ulnSendVersion: UlnVersion.V302,
        }
        results.push({ name, options, dstChainName: dst, version: 'V302', ...(await run(options, getSendUln302ContractAddress('bsc', ENVIRONMENT), 30102, dstEid, receiver, request)) })
    }
    for (const [name, options] of READ_VECTORS) {
        const request = {
            pathwayId: { srcEid: READ_CHANNEL, dstEid: 30102, sender: SENDER, receiver: EVM_RECEIVER, srcChainName: 'bsc', dstChainName: 'bsc' },
            nonce: 7,
            ulnSendVersion: UlnVersion.ReadV1002,
        }
        results.push({ name, options, dstChainName: 'bsc', version: 'ReadV1002', ...(await run(options, getReadLib1002ContractAddress('bsc', ENVIRONMENT), 30102, READ_CHANNEL, EVM_RECEIVER, request)) })
    }
    process.stdout.write(
        '@@OPTIONS@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoint: 'packages/sdks/lz-v2-sdk/src/endpoint/evm/index.ts:EndpointV2EvmSdk.getLZSentEvent -> decoders/index.ts:extractOptionsFromLZSentEvent',
                        library: '@layerzerolabs/lz-v2-utilities 3.0.168 Options',
                        synthetic: 'receipts and option vectors are scripted',
                    },
                    environment: ENVIRONMENT,
                    vectors: results,
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
