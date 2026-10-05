// Upstream 1.2.66's Stellar source resolution: the real `EndpointV2StellarSdk.getLZSentEvent`
// (`lz-v2-sdk/src/endpoint/stellar/index.ts:239-275`, decoder `stellar/decoders/index.ts:173-197`,
// `utils/stellar/events.ts:46-64`, `common-stellar/src/events.ts:53-80`) over a scripted plain
// provider whose `getTransaction` answers the SDK-parsed form; the same answer's raw form (events as
// base64 `ContractEvent` XDR) is recorded for the replay. Transactions are synthetic; the endpoint
// address, topic encoding and extractor are upstream's.
import { ethers } from 'ethers'
import { Address, StrKey, xdr } from '@stellar/stellar-sdk'

import { UlnVersion } from '@monorepo/common-model'
import { chainMetadataConfigDefinition } from '@monorepo/chain-metadata-config-values'
import { LocalChainMetadataConfigGetter } from '@monorepo/dynamic-config/src/chainMetadataConfig'
import { EndpointV2StellarSdk } from '@monorepo/lz-v2-sdk/src/endpoint/stellar'
import { getEndpointV2ContractAddress } from '@monorepo/lz-stellar-sdk'

// The constructor builds an `endpoint.Client` from contract bindings the 1.2.66 snapshot does not
// carry (boundary `MISSING_GENERATED`); `getLZSentEvent` and `getPacketSentEventsFromTxHash` use
// none of it, so upstream's own prototype methods run on the fields the constructor would set.
const stellarSdk = (provider: unknown) => ({
    chainName: 'stellar',
    environment: ENVIRONMENT,
    provider,
    endpointAddress: getEndpointV2ContractAddress('stellar', ENVIRONMENT),
    composedTxQuorumFn: () => '',
    getPacketSentEventsFromTxHash: (EndpointV2StellarSdk.prototype as any).getPacketSentEventsFromTxHash,
    getLZSentEvent: EndpointV2StellarSdk.prototype.getLZSentEvent,
})

const path = require('path')

const ENVIRONMENT = 'mainnet'
const SRC_EID = 30600
const SENDER = '0x' + '0a'.repeat(32)
const RECEIVER = '0x2222222222222222222222222222222222222222'
const MESSAGE = '0xdeadbeefcafe'
const OPTIONS = '0x00030100110100000000000000000000000000030d40'
const drop = (receiver: string, amount: string) => '010031' + '02' + amount.padStart(32, '0') + receiver.padStart(64, '0')
const DROP_OPTIONS = '0x0003' + '010011' + '01' + '000000000000000000000000000186a0' + drop('44'.repeat(20), 'c')
const TWO_DROPS = DROP_OPTIONS + drop('44'.repeat(20), 'd')
const TX = '5a'.repeat(32)
const SEND_LIBRARY = StrKey.encodeContract(Buffer.alloc(32, 0x3c))
const OTHER_CONTRACT = StrKey.encodeContract(Buffer.alloc(32, 0x77))

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

const bytes = (hex: string) => Buffer.from(ethers.utils.arrayify(hex))
const entry = (key: string, val: xdr.ScVal) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val })

type Fields = {
    nonce?: number
    dstEid?: number
    options?: string
    contract?: string
    topics?: xdr.ScVal[]
    data?: xdr.ScVal
    type?: xdr.ContractEventType
    sendLibrary?: string
    omit?: string
}

const main = async () => {
    const endpoint: string = stellarSdk({}).endpointAddress
    const event = (fields: Fields = {}) => {
        const map = [
            entry('encoded_packet', xdr.ScVal.scvBytes(bytes(packet(fields.nonce ?? 7, fields.dstEid)))),
            entry('options', xdr.ScVal.scvBytes(bytes(fields.options ?? OPTIONS))),
            entry('send_library', new Address(fields.sendLibrary ?? SEND_LIBRARY).toScVal()),
        ].filter((item) => item.key().sym().toString() !== fields.omit)
        return new xdr.ContractEvent({
            ext: new xdr.ExtensionPoint(0),
            contractId: StrKey.decodeContract(fields.contract ?? endpoint) as any,
            type: fields.type ?? xdr.ContractEventType.contract(),
            body: new xdr.ContractEventBody(
                0,
                new xdr.ContractEventV0({
                    topics: fields.topics ?? [xdr.ScVal.scvSymbol('packet_sent')],
                    data: fields.data ?? xdr.ScVal.scvMap(map),
                }),
            ),
        })
    }
    const request = (nonce: number, version = UlnVersion.V302) => ({
        pathwayId: { srcEid: SRC_EID, dstEid: 30101, sender: SENDER, receiver: RECEIVER, srcChainName: 'stellar', dstChainName: 'ethereum' },
        nonce,
        ulnSendVersion: version,
    })
    const scenarios: [string, string, xdr.ContractEvent[], any][] = [
        ['match', 'SUCCESS', [event()], request(7)],
        ['native drop', 'SUCCESS', [event({ options: DROP_OPTIONS })], request(7)],
        ['two drops to one receiver', 'SUCCESS', [event({ options: TWO_DROPS })], request(7)],
        ['empty options', 'SUCCESS', [event({ options: '0x' })], request(7)],
        ['second of two', 'SUCCESS', [event({ nonce: 6 }), event()], request(7)],
        ['other nonce', 'SUCCESS', [event({ nonce: 6 })], request(7)],
        ['V301 request', 'SUCCESS', [event()], request(7, UlnVersion.V301)],
        ['no events', 'SUCCESS', [], request(7)],
        ['event from another contract', 'SUCCESS', [event({ contract: OTHER_CONTRACT })], request(7)],
        ['other event name', 'SUCCESS', [event({ topics: [xdr.ScVal.scvSymbol('packet_verified')] })], request(7)],
        ['extra topic', 'SUCCESS', [event({ topics: [xdr.ScVal.scvSymbol('packet_sent'), xdr.ScVal.scvU32(1)] })], request(7)],
        ['event name as a string', 'SUCCESS', [event({ topics: [xdr.ScVal.scvString('packet_sent')] })], request(7)],
        ['system event type', 'SUCCESS', [event({ type: xdr.ContractEventType.system() })], request(7)],
        ['data not a map', 'SUCCESS', [event({ data: xdr.ScVal.scvU32(1) })], request(7)],
        ['without options', 'SUCCESS', [event({ omit: 'options' })], request(7)],
        ['without send_library', 'SUCCESS', [event({ omit: 'send_library' })], request(7)],
        ['account send_library', 'SUCCESS', [event({ sendLibrary: StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 0x3c)) })], request(7)],
        ['malformed second event', 'SUCCESS', [event(), event({ data: xdr.ScVal.scvU32(1) })], request(7)],
        ['unknown destination eid', 'SUCCESS', [event({ dstEid: 31999 })], request(7)],
        ['failed transaction', 'FAILED', [event()], request(7)],
    ]
    const results: any[] = []
    for (const [name, status, events, lzMessageId] of scenarios) {
        const calls: unknown[] = []
        const common = { status, ledger: 777, createdAt: 1700000000, applicationOrder: 1, txHash: TX }
        const raw = { ...common, events: { transactionEventsXdr: [], contractEventsXdr: [events.map((e) => e.toXDR('base64'))] } }
        const client = {
            getTransaction: async (txHash: string) => {
                calls.push({ getTransaction: txHash })
                return { ...common, events: { transactionEventsXdr: [], contractEventsXdr: [events] } }
            },
        }
        const sdk = stellarSdk(client)
        let outcome
        try {
            outcome = { event: await sdk.getLZSentEvent(TX, lzMessageId as any) }
        } catch (error: any) {
            outcome = { error: String(error?.message ?? error) }
        }
        results.push({ name, transaction: raw, request: lzMessageId, calls, outcome: JSON.parse(JSON.stringify(outcome, (_, v) => (typeof v === 'bigint' ? v.toString() : v))) })
    }
    process.stdout.write(
        '@@STELLAR@@' +
            JSON.stringify(
                {
                    producedBy: {
                        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                        entrypoint: 'packages/sdks/lz-v2-sdk/src/endpoint/stellar/index.ts:EndpointV2StellarSdk.prototype.getLZSentEvent (constructor not run: contract bindings absent from the snapshot)',
                    },
                    environment: ENVIRONMENT,
                    txHash: TX,
                    endpoint,
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
