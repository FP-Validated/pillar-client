// Drives the real Gasolina **public** signing entrypoint over recorded historical
// PacketSent receipts, one destination chain family per environment, and reports what
// each pathway produces so the Rust port can be compared field by field.
//
// Public path, not a recomposition of its steps: the event comes from upstream's own
// `extractLZEventFromPacketSentEvent`, the SDK from upstream's own
// `GasolinaSdkFactory`, the payload from that SDK's `buildULNV3VerifyPayload`. That
// matters because `GasolinaEvmSdk.buildDvnCallData` derives the *receive* ULN version
// from the destination endpoint id (`evm/index.ts:135-145`) - a step any hand-recomposed
// harness silently skips.
//
// Offline: no RPC, no signer, no network. Receipts come from the fixture, and every
// family compared here leaves its provider untouched on the verify path - except TON,
// excluded for the reason recorded in the output.
import * as fs from 'fs'
import * as path from 'path'

import { extractLZEventFromPacketSentEvent } from '@monorepo/lz-v2-sdk/src/endpoint/evm/decoders'
import { EndpointV2__factory } from '@monorepo/lz-evm-sdk-v2-contracts'
import type { PacketSentEvent } from '@monorepo/lz-evm-sdk-v2-contracts'
import { getVId } from '@monorepo/static-config'

import { GasolinaSdkFactory } from '../src/app/sdks/gasolinaSdk/factory'

const PACKET_SENT_TOPIC =
    '0x1ab700d4ced0c005b164c0f789fd09fcbb0156d4c2041b8a3bfbcd961cd1567f'

// TON's verify path resolves the DVN proxy's implementation through a quorum-backed
// storage read (`apps/gasolina/src/app/sdks/gasolinaSdk/ton/index.ts:144-159` ->
// `packages/contracts/lz-ton-contracts/src/index.ts:613-645`), which no argument
// bypasses. Its payload builders are compared byte for byte through
// `crates/pillar-layerzero/tests/gasolina_parity/ton_dvn_verify.json` instead.
const OFFLINE_EXCLUDED: Record<string, string> = {
    TON: 'verify path performs a quorum-backed storage read to resolve the DVN proxy implementation; covered by ton_dvn_verify.json',
}

interface FixtureLog {
    address: string
    topics: string[]
    data: string
    blockNumber: string
    blockHash: string
    transactionHash: string
    logIndex: string
    transactionIndex: string
}

interface Pathway {
    id: string
    environment: string
    family: string
    srcChainName: string
    dstChainName: string
    dstEid: number
    txHash: string
    gate0Blocked: string | null
    signingContext: {
        blockConfirmation: number
        expiration: number
        dvnAddress: string
    }
    receipt: { logs: FixtureLog[] }
}

const fixture: { pathways: Pathway[] } = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'historical_pathways.json'), 'utf8'),
)

const packetSentEventFrom = (log: FixtureLog): PacketSentEvent => {
    const parsed = EndpointV2__factory.createInterface().parseLog({
        topics: log.topics,
        data: log.data,
    })
    const fields = {
        blockNumber: Number(log.blockNumber),
        blockHash: log.blockHash,
        transactionHash: log.transactionHash,
        transactionIndex: Number(log.transactionIndex),
        logIndex: Number(log.logIndex),
        removed: false,
        address: log.address,
        data: log.data,
        topics: log.topics,
        args: {
            encodedPayload: parsed.args.encodedPayload,
            options: parsed.args.options,
            sendLibrary: parsed.args.sendLibrary,
        },
    }
    // Structurally complete for this path; the ethers `Event` methods the typechain
    // type also declares are unexpressible in a literal and never called here.
    return fields as unknown as PacketSentEvent
}

const runPathway = async (pathway: Pathway) => {
    const base = {
        id: pathway.id,
        environment: pathway.environment,
        family: pathway.family,
        srcChainName: pathway.srcChainName,
        dstChainName: pathway.dstChainName,
        txHash: pathway.txHash,
        gate0Blocked: pathway.gate0Blocked,
    }
    const excluded = OFFLINE_EXCLUDED[pathway.family]
    if (excluded) {
        return { ...base, skipped: excluded }
    }

    const raw = pathway.receipt.logs.find(
        (log) =>
            log.topics.length === 1 &&
            log.topics[0].toLowerCase() === PACKET_SENT_TOPIC,
    )
    if (!raw) {
        return { ...base, error: 'no PacketSent log in the recorded receipt' }
    }

    let normalizedEvent
    let vId: string
    try {
        normalizedEvent = extractLZEventFromPacketSentEvent(
            pathway.srcChainName,
            pathway.environment,
            packetSentEventFrom(raw),
        )
        vId = getVId(pathway.dstChainName, pathway.environment)
    } catch (error) {
        return { ...base, decodeError: (error as Error).message.slice(0, 300) }
    }

    try {
        // Providers deliberately absent: nothing compared here reads one.
        const factory = new GasolinaSdkFactory({
            environment: pathway.environment,
            providers: {},
        })
        const built = await factory
            .getSdk(pathway.dstChainName)
            .buildULNV3VerifyPayload(
                normalizedEvent,
                pathway.signingContext.blockConfirmation,
                pathway.signingContext.expiration,
                vId,
                pathway.signingContext.dvnAddress,
            )
        return {
            ...base,
            vId,
            normalizedEvent,
            targetContract: built.details.dvnCallData?.targetContract,
            ulnCallData: built.details.dvnCallData?.ulnCallData,
            vid: built.details.dvnCallData?.vid,
            expiration: built.details.dvnCallData?.expiration,
            ulnCallDataDetails: built.details.ulnCallData,
            hashCallData: built.hashCallData,
        }
    } catch (error) {
        return {
            ...base,
            vId,
            normalizedEvent,
            buildError: (error as Error).message.slice(0, 300),
        }
    }
}

const main = async () => {
    const pathways = []
    for (const pathway of fixture.pathways) {
        pathways.push(await runPathway(pathway))
    }
    process.stdout.write(
        JSON.stringify(
            {
                producedBy: {
                    upstream: 'gasolina-audit',
                    entrypoints: [
                        'packages/sdks/lz-v2-sdk/src/endpoint/evm/decoders/index.ts:extractLZEventFromPacketSentEvent',
                        'apps/gasolina/src/app/sdks/gasolinaSdk/factory.ts:GasolinaSdkFactory.getSdk',
                        'apps/gasolina/src/app/sdks/gasolinaSdk/<family>/index.ts:buildULNV3VerifyPayload',
                        'packages/static-config/src/index.ts:getVId',
                    ],
                },
                pathways,
            },
            null,
            2,
        ) + '\n',
    )
}

void main()
