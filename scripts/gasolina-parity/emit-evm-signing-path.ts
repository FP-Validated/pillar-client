// Emits what the real Gasolina EVM signing path produces for a fixed PacketSent log,
// so the Rust port can be compared against it byte for byte. Read-only: no RPC, no
// signer, no network. Every function called here is the one the service itself calls.
import { ethers } from 'ethers'

import { extractLZEventFromPacketSentEvent } from '@monorepo/lz-v2-sdk/src/endpoint/evm/decoders'
import {
    buildULNReadV1VerifyCallData,
    buildULNV3VerifyCallData,
} from '@monorepo/lz-v2-sdk/src/utils/evm'
import {
    EndpointV2__factory,
    getReadLib1002ContractAddress,
    getReceiveUln302ContractAddress,
} from '@monorepo/lz-evm-sdk-v2-contracts'
import type { PacketSentEvent } from '@monorepo/lz-evm-sdk-v2-contracts'
import { getVId } from '@monorepo/static-config'

import { packDVNCallData } from '../src/app/sdks/gasolinaSdk/evm/utils'

const ENVIRONMENT = 'mainnet'
const SRC_CHAIN = 'ethereum'

// The real send libraries, so `getUlnVersionFromAddress` resolves the version from the
// address table rather than from anything this harness asserts.
const SEND_ULN_302 = '0xbB2Ea70C9E858123480642Cf96acbcCE1372dCe1'
const SEND_ULN_READ_1002 = '0x74F55Bc2a79A27A0bF1D1A35dB5d0Fc36b9FDB9D'

// The real destination EndpointV2, which is also the only trusted packet emitter
// the Rust port will accept for this chain.
const ENDPOINT_V2 = '0x1a44076050125825900e736c501f859c50fE728c'

const NONCE = 7
const SENDER = '0x1111111111111111111111111111111111111111'
const RECEIVER = '0x2222222222222222222222222222222222222222'
const GUID = '0x' + 'bb'.repeat(32)
const MESSAGE = '0xdeadbeef'
const OPTIONS = '0x1234'
const TX_HASH = '0x' + '11'.repeat(32)
const BLOCK_HASH = '0x' + '22'.repeat(32)
const BLOCK_NUMBER = 21_000_000

const BLOCK_CONFIRMATION = 15
const EXPIRATION = 1_767_400_000
const RESOLVED_PAYLOAD = 'cafebabe'

// `ChannelId.READ_CHANNEL_1`, @layerzerolabs/lz-definitions@3.1.2 dist/index.d.ts.
const READ_CHANNEL_1 = 4_294_967_295

/**
 * PacketV1 wire layout, which no single expression explains:
 * version(1) | nonce(8) | srcEid(4) | sender(32) | dstEid(4) | receiver(32) | guid(32) | message
 */
const encodePacketV1 = (srcEid: number, dstEid: number): string =>
    '0x01' +
    NONCE.toString(16).padStart(16, '0') +
    srcEid.toString(16).padStart(8, '0') +
    SENDER.slice(2).toLowerCase().padStart(64, '0') +
    dstEid.toString(16).padStart(8, '0') +
    RECEIVER.slice(2).toLowerCase().padStart(64, '0') +
    GUID.slice(2) +
    MESSAGE.slice(2)

/**
 * The decoder reads `args`, `transactionHash`, `blockHash` and `blockNumber`. The
 * typechain event type also carries the ethers `Event` methods, which a literal cannot
 * supply and this path never calls.
 */
interface PacketSentLogFields {
    blockNumber: number
    blockHash: string
    transactionHash: string
    address: string
    data: string
    topics: string[]
    logIndex: number
    transactionIndex: number
    removed: boolean
    args: { encodedPayload: string; options: string; sendLibrary: string }
}

const packetSentEvent = (
    srcEid: number,
    dstEid: number,
    sendLibrary: string,
): {
    event: PacketSentEvent
    log: { address: string; data: string; topics: string[] }
} => {
    const iface = EndpointV2__factory.createInterface()
    const encoded = iface.encodeEventLog(iface.getEvent('PacketSent'), [
        encodePacketV1(srcEid, dstEid),
        OPTIONS,
        sendLibrary,
    ])
    const log = {
        blockNumber: BLOCK_NUMBER,
        blockHash: BLOCK_HASH,
        transactionIndex: 0,
        removed: false,
        address: ENDPOINT_V2,
        data: encoded.data,
        topics: encoded.topics,
        transactionHash: TX_HASH,
        logIndex: 0,
    }
    const parsed = iface.parseLog(log)
    const fields: PacketSentLogFields = {
        ...log,
        args: {
            encodedPayload: parsed.args.encodedPayload,
            options: parsed.args.options,
            sendLibrary: parsed.args.sendLibrary,
        },
    }
    // Structurally complete for this path; the unused `Event` methods are unexpressible
    // in a literal.
    const event = fields as unknown as PacketSentEvent
    return { event, log: { address: log.address, data: log.data, topics: log.topics } }
}

const v302Arm = () => {
    const { event, log } = packetSentEvent(30_101, 30_102, SEND_ULN_302)
    const sentEvent = extractLZEventFromPacketSentEvent(
        SRC_CHAIN,
        ENVIRONMENT,
        event,
    )
    const { callData, details } = buildULNV3VerifyCallData(
        sentEvent,
        BLOCK_CONFIRMATION,
    )
    const { dstChainName } = sentEvent.lzMessageId.pathwayId
    const targetContract = getReceiveUln302ContractAddress(
        dstChainName,
        ENVIRONMENT,
    )
    const vId = getVId(dstChainName, ENVIRONMENT)
    const dvnCallData = packDVNCallData(
        targetContract,
        callData,
        EXPIRATION,
        vId,
    )
    return {
        arm: 'uln_v3_verify',
        input: {
            log,
            srcChainName: SRC_CHAIN,
            environment: ENVIRONMENT,
            blockConfirmation: BLOCK_CONFIRMATION,
            expiration: EXPIRATION,
        },
        normalizedEvent: sentEvent,
        proof: details.ulnCallData.proof,
        vId,
        targetContract,
        ulnCallData: callData,
        dvnCallData,
        hashCallData: ethers.utils.keccak256(dvnCallData),
    }
}

const readV1002Arm = () => {
    // Upstream flips the endpoint ids for a read packet, so the raw dstEid is the
    // channel and the pathway that comes out names the chain on both sides.
    const { event, log } = packetSentEvent(
        30_101,
        READ_CHANNEL_1,
        SEND_ULN_READ_1002,
    )
    const sentEvent = extractLZEventFromPacketSentEvent(
        SRC_CHAIN,
        ENVIRONMENT,
        event,
    )
    const { callData, details } = buildULNReadV1VerifyCallData(
        sentEvent,
        RESOLVED_PAYLOAD,
    )
    const { dstChainName } = sentEvent.lzMessageId.pathwayId
    const targetContract = getReadLib1002ContractAddress(
        dstChainName,
        ENVIRONMENT,
    )
    const vId = getVId(dstChainName, ENVIRONMENT)
    const dvnCallData = packDVNCallData(
        targetContract,
        callData,
        EXPIRATION,
        vId,
    )
    return {
        arm: 'uln_read_v1002_verify',
        input: {
            log,
            srcChainName: SRC_CHAIN,
            environment: ENVIRONMENT,
            resolvedPayload: RESOLVED_PAYLOAD,
            expiration: EXPIRATION,
        },
        normalizedEvent: sentEvent,
        proof: details.ulnCallData.proof,
        vId,
        targetContract,
        ulnCallData: callData,
        dvnCallData,
        hashCallData: ethers.utils.keccak256(dvnCallData),
    }
}

process.stdout.write(
    JSON.stringify(
        {
            producedBy: {
                upstream: 'gasolina-audit',
                entrypoints: [
                    'packages/sdks/lz-v2-sdk/src/endpoint/evm/decoders/index.ts:extractLZEventFromPacketSentEvent',
                    'packages/sdks/lz-v2-sdk/src/utils/common/index.ts:computeLZMessageV2Proof',
                    'packages/sdks/lz-v2-sdk/src/utils/evm/index.ts:buildULNV3VerifyCallData',
                    'packages/sdks/lz-v2-sdk/src/utils/evm/index.ts:buildULNReadV1VerifyCallData',
                    'apps/gasolina/src/app/sdks/gasolinaSdk/evm/utils.ts:packDVNCallData',
                ],
            },
            arms: [v302Arm(), readV1002Arm()],
        },
        null,
        2,
    ) + '\n',
)
