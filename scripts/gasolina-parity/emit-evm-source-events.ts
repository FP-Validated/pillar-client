// Upstream 1.2.66's EVM source resolution for EndpointV2-era sends: the real
// `EndpointV2EvmSdk.getLZSentEvent` (`lz-v2-sdk/src/endpoint/evm/index.ts:163-200`) over a
// scripted plain ethers provider (not a multiprovider, so `getQuorumProvider` returns it
// unchanged). Receipts are synthetic; the contracts, ABIs, addresses and extractor are
// upstream's. Covers ULN V301 (SendUln301 `PacketSent`) and V302 (EndpointV2 `PacketSent`).
import { ethers } from 'ethers'

import { EndpointVersion, UlnVersion } from '@monorepo/common-model'
import { chainMetadataConfigDefinition } from '@monorepo/chain-metadata-config-values'
import { LocalChainMetadataConfigGetter } from '@monorepo/dynamic-config/src/chainMetadataConfig'
import { EndpointV2EvmSdk } from '@monorepo/lz-v2-sdk/src/endpoint/evm'
import {
    getReadLib1002ContractAddress,
    getReceiveUln302ContractAddress,
    getSendUln302ContractAddress,
    getSimpleMessageLibContractAddress,
} from '@monorepo/lz-evm-sdk-v2-contracts'

const path = require('path')

const ENVIRONMENT = 'mainnet'
const SENDER = '0x1111111111111111111111111111111111111111'
const RECEIVER = '0x2222222222222222222222222222222222222222'
const MESSAGE = '0xdeadbeefcafe'
const TX = '0x' + '7a'.repeat(32)
const BLOCK_HASH = '0x' + 'ab'.repeat(32)
const OPTIONS = '0x00030100110100000000000000000000000000030d40'

const bytes32 = (address: string) => ethers.utils.hexZeroPad(address, 32)
const guidOf = (nonce: number, srcEid: number, dstEid: number) =>
    ethers.utils.keccak256(
        ethers.utils.solidityPack(
            ['uint64', 'uint32', 'bytes32', 'uint32', 'bytes32'],
            [nonce, srcEid, bytes32(SENDER), dstEid, bytes32(RECEIVER)],
        ),
    )
const packet = (nonce: number, srcEid: number, dstEid: number) =>
    ethers.utils.solidityPack(
        ['uint8', 'uint64', 'uint32', 'bytes32', 'uint32', 'bytes32', 'bytes32', 'bytes'],
        [1, nonce, srcEid, bytes32(SENDER), dstEid, bytes32(RECEIVER), guidOf(nonce, srcEid, dstEid), MESSAGE],
    )

class ScriptedProvider extends ethers.providers.JsonRpcProvider {
    calls: { method: string; params: unknown }[] = []
    constructor(private receipt: unknown) {
        super('http://scripted.invalid', { chainId: 56, name: 'bnb' })
    }
    async detectNetwork() {
        return { chainId: 56, name: 'bnb' }
    }
    async send(method: string, params: any[]): Promise<any> {
        if (method === 'eth_blockNumber') return '0x2000'
        if (method === 'eth_chainId') return '0x38'
        this.calls.push({ method, params })
        if (method === 'eth_getTransactionReceipt') return this.receipt
        throw new Error(`unscripted ${method}`)
    }
}

const receipt = (logs: { address: string; topics: string[]; data: string }[], status = '0x1') => ({
    transactionHash: TX,
    transactionIndex: '0x0',
    blockHash: BLOCK_HASH,
    blockNumber: '0x1000',
    from: SENDER,
    to: '0x5555555555555555555555555555555555555555',
    cumulativeGasUsed: '0x1',
    gasUsed: '0x1',
    contractAddress: null,
    logs: logs.map((log, index) => ({
        ...log,
        blockNumber: '0x1000',
        blockHash: BLOCK_HASH,
        transactionHash: TX,
        transactionIndex: '0x0',
        logIndex: ethers.utils.hexValue(index),
        removed: false,
    })),
    logsBloom: '0x' + '00'.repeat(256),
    status,
    type: '0x0',
    effectiveGasPrice: '0x1',
})

const main = async () => {
    const metadata = await LocalChainMetadataConfigGetter.create(
        path.join(chainMetadataConfigDefinition.dirname, ENVIRONMENT, `${chainMetadataConfigDefinition.configName}.json`),
    )
    const probe: any = new EndpointV2EvmSdk('bsc', ENVIRONMENT, new ScriptedProvider(null), metadata)
    const uln301: ethers.Contract = probe.getSendContracts(EndpointVersion.V1)
    const endpoint: ethers.Contract = probe.getSendContracts(EndpointVersion.V2)
    const sendUln302 = getSendUln302ContractAddress('bsc', ENVIRONMENT)
    const receiveUln302 = getReceiveUln302ContractAddress('bsc', ENVIRONMENT)
    const readLib = getReadLib1002ContractAddress('bsc', ENVIRONMENT)
    let simpleMessageLib: string | null = null
    try {
        simpleMessageLib = getSimpleMessageLibContractAddress('bsc', ENVIRONMENT)
    } catch {
        simpleMessageLib = null
    }
    const READ_CHANNEL = 4294967295

    const v301Log = (nonce: number, address = uln301.address) => ({
        address,
        ...uln301.interface.encodeEventLog(uln301.interface.getEvent('PacketSent'), [packet(nonce, 30102, 101), OPTIONS, 1000, 0]),
    })
    const v302Log = (nonce: number, library: string, address = endpoint.address, srcEid = 30102, dstEid = 30101) => ({
        address,
        ...endpoint.interface.encodeEventLog(endpoint.interface.getEvent('PacketSent'), [packet(nonce, srcEid, dstEid), OPTIONS, library]),
    })
    const request = (version: string, nonce: number) => ({
        pathwayId: {
            srcEid: 30102,
            dstEid: version === UlnVersion.V301 ? 101 : 30101,
            sender: SENDER,
            receiver: RECEIVER,
            srcChainName: 'bsc',
            dstChainName: 'ethereum',
        },
        nonce,
        ulnSendVersion: version,
    })

    const scenarios: [string, unknown, any][] = [
        ['V301 match', receipt([v301Log(7)]), request(UlnVersion.V301, 7)],
        ['V301 second of two', receipt([v301Log(6), v301Log(7)]), request(UlnVersion.V301, 7)],
        ['V301 other nonce', receipt([v301Log(6)]), request(UlnVersion.V301, 7)],
        ['V301 log from another address', receipt([v301Log(7, '0x' + '99'.repeat(20))]), request(UlnVersion.V301, 7)],
        ['V301 request, V302 log', receipt([v302Log(7, sendUln302)]), request(UlnVersion.V301, 7)],
        ['V302 match', receipt([v302Log(7, sendUln302)]), request(UlnVersion.V302, 7)],
        ['V302 through ReceiveUln302 library', receipt([v302Log(7, receiveUln302)]), request(UlnVersion.V302, 7)],
        ['V302 request, V301 log', receipt([v301Log(7)]), request(UlnVersion.V302, 7)],
        ['V302 unknown send library', receipt([v302Log(7, '0x' + '88'.repeat(20))]), request(UlnVersion.V302, 7)],
        ...(simpleMessageLib
            ? ([['V302 through SimpleMessageLib', receipt([v302Log(7, simpleMessageLib)]), request(UlnVersion.V302, 7)]] as [string, unknown, any][])
            : []),
        [
            'ReadV1002 match',
            receipt([v302Log(7, readLib, endpoint.address, 30102, READ_CHANNEL)]),
            {
                pathwayId: {
                    srcEid: READ_CHANNEL,
                    dstEid: 30102,
                    sender: SENDER,
                    receiver: RECEIVER,
                    srcChainName: 'bsc',
                    dstChainName: 'bsc',
                },
                nonce: 7,
                ulnSendVersion: UlnVersion.ReadV1002,
            },
        ],
        ['reverted receipt', receipt([], '0x0'), request(UlnVersion.V301, 7)],
        ['missing receipt', null, request(UlnVersion.V301, 7)],
    ]
    const results = []
    for (const [name, script, lzMessageId] of scenarios) {
        const provider = new ScriptedProvider(script)
        const sdk = new EndpointV2EvmSdk('bsc', ENVIRONMENT, provider, metadata)
        let outcome
        try {
            outcome = { event: await sdk.getLZSentEvent(TX, lzMessageId) }
        } catch (error: any) {
            outcome = { error: String(error?.message ?? error) }
        }
        results.push({ name, receipt: script, request: lzMessageId, calls: provider.calls, outcome })
    }
    process.stdout.write(
        '@@SOURCE@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoint: 'packages/sdks/lz-v2-sdk/src/endpoint/evm/index.ts:EndpointV2EvmSdk.getLZSentEvent',
                        synthetic: 'receipts are scripted; contracts, ABIs and addresses are upstream',
                    },
                    environment: ENVIRONMENT,
                    srcChainName: 'bsc',
                    sendUln301: uln301.address,
                    endpointV2: endpoint.address,
                    sendUln302,
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
