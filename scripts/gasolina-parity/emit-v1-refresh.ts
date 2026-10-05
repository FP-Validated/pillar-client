// Upstream 1.2.66's refresh of a ULNv2-sent event before it is hydrated for a migrated
// (V301/V302) receive library (`hashCallDataBuilder/ulnV3.ts:36-63`): the real
// `LZEvmSdk.getLZSentEvent` (`lz-v1-sdk/src/evm/index.ts:840-920,966-1071`) and
// `LZAptosSdk.getLZSentEvent` (`lz-v1-sdk/src/aptos/aptos.ts:518-537,843-854`,
// `aptos/utils.ts:16-101`, `aptos/views.ts:221-244`) over scripted providers. A plain provider
// is not a multiprovider, so `getQuorumProvider` returns it unchanged
// (`multiprovider/src/quorumProvider.ts:31-40`) and every read it makes is recorded here.
import { ethers } from 'ethers'

import { calculateAptosGuid } from '@monorepo/common-aptos'
import { UlnVersion } from '@monorepo/common-model'
import { getUlnV2ContractAddress } from '@monorepo/layerzero-core-contracts'
import { chainMetadataConfigDefinition } from '@monorepo/chain-metadata-config-values'
import { LocalChainMetadataConfigGetter } from '@monorepo/dynamic-config/src/chainMetadataConfig'
import { LZEvmSdk } from '@monorepo/lz-v1-sdk/src/evm'
import { hydrateV1SentEventToV2 } from '@monorepo/lz-v2-sdk/src/utils/common/hydrateV1SentEvent'
import { getAptosV1ExecutorV2Address, getAptosV1LayerZeroAddress } from '@monorepo/lz-v1-sdk/src/aptos/addresses'
import { LZAptosSdk } from '@monorepo/lz-v1-sdk/src/aptos/aptos'

const path = require('path')

const ENVIRONMENT = 'mainnet'
const NONCE = 7
const SRC_EID_V1 = 102
const DST_EID_V1 = 101
const SENDER = '0x1111111111111111111111111111111111111111'
const RECEIVER = '0x2222222222222222222222222222222222222222'
const MESSAGE = '0xdeadbeefcafe'
const TX = '0x' + '7a'.repeat(32)
const MOVED_TX = '0x' + '7b'.repeat(32)
const BLOCK_HASH = '0x' + 'ab'.repeat(32)
const MOVED_BLOCK_HASH = '0x' + 'cd'.repeat(32)
const BLOCK_NUMBER = 0x1000
const MOVED_BLOCK_NUMBER = 0x1003

const ULN_INTERFACE = new ethers.utils.Interface([
    'event Packet(bytes payload)',
    'event RelayerParams(bytes adapterParams, uint16 outboundProofType)',
    'function defaultAdapterParams(uint16, uint16) view returns (bytes)',
])
const PACKET_TOPIC = ULN_INTERFACE.getEventTopic('Packet')
const RELAYER_PARAMS_TOPIC = ULN_INTERFACE.getEventTopic('RelayerParams')
const ADAPTER_V1 = ethers.utils.solidityPack(['uint16', 'uint256'], [1, 200000])
const ADAPTER_V2 = ethers.utils.solidityPack(
    ['uint16', 'uint256', 'uint256', 'address'],
    [2, 200000, 1000, '0x3333333333333333333333333333333333333333'],
)

const packetPayload = (nonce = NONCE) =>
    ethers.utils.solidityPack(
        ['uint64', 'uint16', 'address', 'uint16', 'address', 'bytes'],
        [nonce, SRC_EID_V1, SENDER, DST_EID_V1, RECEIVER, MESSAGE],
    )

type Log = { address: string; topics: string[]; data: string }

const packetLog = (uln: string, nonce = NONCE): Log => ({
    address: uln,
    topics: [PACKET_TOPIC],
    data: ethers.utils.defaultAbiCoder.encode(['bytes'], [packetPayload(nonce)]),
})
const relayerLog = (uln: string, adapterParams: string, proofType = 2): Log => ({
    address: uln,
    topics: [RELAYER_PARAMS_TOPIC],
    data: ethers.utils.defaultAbiCoder.encode(['bytes', 'uint16'], [adapterParams, proofType]),
})
const otherLog = (): Log => ({
    address: '0x4444444444444444444444444444444444444444',
    topics: ['0x' + '99'.repeat(32)],
    data: '0x',
})

const rpcLog = (log: Log, index: number, tx: string, blockHash: string, blockNumber: number) => ({
    ...log,
    blockNumber: ethers.utils.hexValue(blockNumber),
    blockHash,
    transactionHash: tx,
    transactionIndex: '0x0',
    logIndex: ethers.utils.hexValue(index),
    removed: false,
})

const receipt = (logs: Log[], tx = TX, blockHash = BLOCK_HASH, blockNumber = BLOCK_NUMBER, status = '0x1') => ({
    transactionHash: tx,
    transactionIndex: '0x0',
    blockHash,
    blockNumber: ethers.utils.hexValue(blockNumber),
    from: SENDER,
    to: '0x5555555555555555555555555555555555555555',
    cumulativeGasUsed: '0x1',
    gasUsed: '0x1',
    contractAddress: null,
    logs: logs.map((log, index) => rpcLog(log, index, tx, blockHash, blockNumber)),
    logsBloom: '0x' + '00'.repeat(256),
    status,
    type: '0x0',
    effectiveGasPrice: '0x1',
})

type Script = {
    receipts?: Record<string, unknown>
    receiptError?: string
    logs?: unknown[]
    logsError?: string
    defaultAdapterParams?: string
    callError?: string
}

class ScriptedProvider extends ethers.providers.JsonRpcProvider {
    calls: { method: string; params: unknown }[] = []
    constructor(private script: Script) {
        super('http://scripted.invalid', { chainId: 56, name: 'bnb' })
    }
    async detectNetwork() {
        return { chainId: 56, name: 'bnb' }
    }
    async send(method: string, params: any[]): Promise<any> {
        if (method === 'eth_blockNumber' || method === 'eth_chainId') {
            return method === 'eth_chainId' ? '0x38' : ethers.utils.hexValue(BLOCK_NUMBER + 100)
        }
        this.calls.push({ method, params })
        switch (method) {
            case 'eth_getTransactionReceipt':
                if (this.script.receiptError) throw new Error(this.script.receiptError)
                return this.script.receipts?.[params[0]] ?? null
            case 'eth_getLogs':
                if (this.script.logsError) throw new Error(this.script.logsError)
                return this.script.logs ?? []
            case 'eth_call':
                if (this.script.callError) throw new Error(this.script.callError)
                return ULN_INTERFACE.encodeFunctionResult('defaultAdapterParams', [this.script.defaultAdapterParams ?? ADAPTER_V1])
            default:
                throw new Error(`unscripted ${method}`)
        }
    }
}

const sentEvent = (uln: string) => ({
    lzMessageId: {
        pathwayId: {
            srcEid: SRC_EID_V1,
            dstEid: DST_EID_V1,
            srcChainName: 'bsc',
            dstChainName: 'ethereum',
            sender: SENDER,
            receiver: RECEIVER,
        },
        nonce: NONCE,
        ulnSendVersion: UlnVersion.V2,
    },
    message: MESSAGE,
    packetEmitAddress: uln,
    onChainEvent: { txHash: TX, blockHash: BLOCK_HASH, blockNumber: BLOCK_NUMBER, chainName: 'bsc' },
})

const evmScenarios = (uln: string): [string, Script][] => [
    ['adapter params in receipt', { receipts: { [TX]: receipt([relayerLog(uln, ADAPTER_V1), packetLog(uln)]) } }],
    ['airdrop adapter params', { receipts: { [TX]: receipt([relayerLog(uln, ADAPTER_V2), packetLog(uln)]) } }],
    [
        'default adapter params read',
        { receipts: { [TX]: receipt([relayerLog(uln, '0x'), packetLog(uln)]) }, defaultAdapterParams: ADAPTER_V1 },
    ],
    [
        'default adapter params read fails, found again by logs',
        {
            receipts: { [TX]: receipt([relayerLog(uln, '0x'), packetLog(uln)]) },
            callError: 'call reverted',
            logs: [rpcLog(packetLog(uln), 1, TX, BLOCK_HASH, BLOCK_NUMBER)],
        },
    ],
    [
        'no relayer params, not found by logs',
        { receipts: { [TX]: receipt([otherLog(), packetLog(uln)]) }, logs: [] },
    ],
    [
        'relayer params after packet only',
        { receipts: { [TX]: receipt([packetLog(uln), relayerLog(uln, ADAPTER_V1)]) }, logs: [] },
    ],
    [
        'malformed adapter params',
        { receipts: { [TX]: receipt([relayerLog(uln, '0x0001'), packetLog(uln)]) }, logs: [] },
    ],
    [
        'packet at receipt index 0',
        { receipts: { [TX]: receipt([packetLog(uln), otherLog()]) }, logs: [] },
    ],
    [
        'receipt gone, moved by reorg',
        {
            receipts: {
                [MOVED_TX]: receipt([relayerLog(uln, ADAPTER_V1), packetLog(uln)], MOVED_TX, MOVED_BLOCK_HASH, MOVED_BLOCK_NUMBER),
            },
            logs: [
                rpcLog(packetLog(uln, NONCE + 1), 0, MOVED_TX, MOVED_BLOCK_HASH, MOVED_BLOCK_NUMBER),
                rpcLog(packetLog(uln), 1, MOVED_TX, MOVED_BLOCK_HASH, MOVED_BLOCK_NUMBER),
            ],
        },
    ],
    ['receipt gone, not found by logs', { logs: [] }],
    ['receipt read fails', { receiptError: 'upstream receipt failure' }],
    ['logs read fails', { logsError: 'upstream getLogs failure' }],
    [
        'reverted receipt, not found by logs',
        { receipts: { [TX]: receipt([], TX, BLOCK_HASH, BLOCK_NUMBER, '0x0') }, logs: [] },
    ],
    [
        'other nonce in receipt only',
        { receipts: { [TX]: receipt([relayerLog(uln, ADAPTER_V1), packetLog(uln, NONCE + 1)]) }, logs: [] },
    ],
]

const APTOS_EVENT = {
    lzMessageId: {
        pathwayId: {
            srcChainName: 'aptos',
            dstChainName: 'arbitrum',
            sender: '0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa',
            receiver: '0x1bacc2205312534375c8d1801c27d28370656cff',
            srcEid: 108,
            dstEid: 110,
        },
        nonce: 26733,
        ulnSendVersion: 'V2',
    },
    packetEmitAddress: '0x54ad3d30af77b60d939ae356e6606de9a4da67583f02b962d2d3f2e481484e90',
    onChainEvent: { txHash: '26629', blockHash: '0x' + 'b1'.repeat(32), blockNumber: 12345, chainName: 'aptos' },
    message: '0x0100000000000000000000000082af49447d8a07e3bd95bd0d56f35241523fbab10000000000000000000000005e5878e61a4b3d83eb43aea9eee76e2c3fa97f4100000000000010a901',
}

type AptosScript = {
    events: unknown[]
    resourceError?: string
    tableItem?: string
    tableError?: string
}

const aptosScenarios = (guid: string, layerzero: string, executorV2: string): [string, AptosScript][] => {
    const strip = (address: string) => address.replace(/^(0x)0*/i, '$1')
    const v2Type = `${strip(executorV2)}::executor_v2::ExecutorRequested`
    const v1Type = `${strip(layerzero)}::executor_v1::RequestEvent`
    const v1Params = '0x0001' + '0000000000030d40'
    const v2Params = '0x0002' + '0000000000030d40' + '00000000000003e8' + '33'.repeat(20)
    return [
        ['executor_v2 event', { events: [{ type: v2Type, data: { guid, adapter_params: v2Params } }] }],
        [
            'executor_v1 event',
            { events: [{ type: v1Type, data: { guid, adapter_params: v1Params } }] },
        ],
        [
            'executor_v2 other guid falls back to v1',
            {
                events: [
                    { type: v2Type, data: { guid: '0x' + '00'.repeat(32), adapter_params: v2Params } },
                    { type: v1Type, data: { guid, adapter_params: v1Params } },
                ],
            },
        ],
        [
            'executor_v2 empty params falls back to v1',
            {
                events: [
                    { type: v2Type, data: { guid, adapter_params: '' } },
                    { type: v1Type, data: { guid, adapter_params: v1Params } },
                ],
            },
        ],
        [
            'default adapter params from table',
            { events: [{ type: v1Type, data: { guid, adapter_params: '0x' } }], tableItem: v1Params },
        ],
        [
            'default adapter params table miss',
            { events: [{ type: v1Type, data: { guid, adapter_params: '0x' } }], tableError: 'table item not found' },
        ],
        [
            'default adapter params resource fails',
            { events: [{ type: v1Type, data: { guid, adapter_params: '0x' } }], resourceError: 'resource not found' },
        ],
        ['no executor event', { events: [] }],
        ['invalid adapter params', { events: [{ type: v1Type, data: { guid, adapter_params: '0x0003' } }] }],
        ['short default adapter params', { events: [{ type: v1Type, data: { guid, adapter_params: '0x00010000' } }] }],
    ]
}

const main = async () => {
    const metadata = await LocalChainMetadataConfigGetter.create(
        path.join(chainMetadataConfigDefinition.dirname, ENVIRONMENT, `${chainMetadataConfigDefinition.configName}.json`),
    )
    const uln = getUlnV2ContractAddress('bsc', ENVIRONMENT)
    const evm = []
    for (const [name, script] of evmScenarios(uln)) {
        const provider = new ScriptedProvider(script)
        const sdk = new LZEvmSdk('bsc', ENVIRONMENT, provider, metadata)
        let outcome
        try {
            const refreshed = await sdk.getLZSentEvent(sentEvent(uln) as any)
            outcome = refreshed
                ? { refreshed, hydrated: hydrateV1SentEventToV2(refreshed as any) }
                : { refreshed: null }
        } catch (error: any) {
            outcome = { error: String(error?.message ?? error) }
        }
        evm.push({ name, script, calls: provider.calls, outcome })
    }

    const guid = calculateAptosGuid(APTOS_EVENT.lzMessageId as any)
    const layerzero = getAptosV1LayerZeroAddress(ENVIRONMENT)
    const executorV2 = getAptosV1ExecutorV2Address(ENVIRONMENT)
    const aptos = []
    for (const [name, script] of aptosScenarios(guid, layerzero, executorV2)) {
        const calls: unknown[] = []
        const client = {
            getTransactionByVersion: async (args: any) => {
                calls.push({ getTransactionByVersion: String(args.ledgerVersion) })
                return { type: 'user_transaction', version: '26629', events: script.events }
            },
            getAccountResource: async (args: any) => {
                calls.push({ getAccountResource: args })
                if (script.resourceError) throw new Error(script.resourceError)
                return { params: { handle: '0x' + 'ee'.repeat(32) } }
            },
            getTableItem: async (args: any) => {
                calls.push({ getTableItem: args })
                if (script.tableError) throw new Error(script.tableError)
                return script.tableItem
            },
        }
        const sdk = new LZAptosSdk('aptos', ENVIRONMENT, { rpc: client } as any, metadata as any)
        let outcome
        try {
            const refreshed: any = await sdk.getLZSentEvent(APTOS_EVENT as any)
            outcome = {
                refreshed: { adapterParams: refreshed.adapterParams },
                hydrated: hydrateV1SentEventToV2(refreshed),
            }
        } catch (error: any) {
            outcome = { error: String(error?.message ?? error) }
        }
        aptos.push({ name, script, calls, outcome })
    }

    const addresses: Record<string, unknown> = {}
    for (const environment of ['mainnet', 'testnet', 'sandbox']) {
        const read = (f: (env: string) => string) => {
            try {
                return f(environment)
            } catch (error: any) {
                return { error: String(error?.message ?? error) }
            }
        }
        addresses[environment] = {
            layerzero: read(getAptosV1LayerZeroAddress),
            executorV2: read(getAptosV1ExecutorV2Address),
        }
    }

    process.stdout.write(
        '@@REFRESH@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoints: [
                            'packages/sdks/lz-v1-sdk/src/evm/index.ts:LZEvmSdk.getLZSentEvent',
                            'packages/sdks/lz-v1-sdk/src/aptos/aptos.ts:LZAptosSdk.getLZSentEvent',
                        ],
                        synthetic: 'receipts, logs, transactions and table answers are scripted; contracts and constants are upstream',
                    },
                    environment: ENVIRONMENT,
                    evm: {
                        uln,
                        packetTopic: PACKET_TOPIC,
                        relayerParamsTopic: RELAYER_PARAMS_TOPIC,
                        maxEthGetLogsBlockRange: metadata.getMaxEthGetLogsBlockRange('bsc'),
                        sentEvent: sentEvent(uln),
                        scenarios: evm,
                    },
                    aptos: { guid, sentEvent: APTOS_EVENT, scenarios: aptos },
                    aptosAddresses: addresses,
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
