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
import { Cell } from '@ton/core'
import { ethers } from 'ethers'
import * as fs from 'fs'
import * as path from 'path'

import { extractLZEventFromPacketSentEvent } from '@monorepo/lz-v2-sdk/src/endpoint/evm/decoders'
import { EndpointV2__factory } from '@monorepo/lz-evm-sdk-v2-contracts'
import type { PacketSentEvent } from '@monorepo/lz-evm-sdk-v2-contracts'
import { getVId } from '@monorepo/static-config'

import { GasolinaSdkFactory } from '../src/app/sdks/gasolinaSdk/factory'
import { GasolinaSignerAdapterGetter } from '@monorepo/gasolina-signer-adapter'
import { SignerAdapterFactory } from '@monorepo/signer-adapter/src/factory'
import { hexToBytes } from '@monorepo/common-utils'
import { StaticChainConfigs } from '@monorepo/static-config'
import type { Mnemonic, MnemonicConfig } from '@monorepo/common-model'
import type { WalletDefinition } from '@monorepo/wallet-config-models'
import { EndpointV2EvmSdk } from '@monorepo/lz-v2-sdk/src/endpoint/evm'
import { EndpointV2EvmSdk as EndpointV2EvmSdkViem } from '@monorepo/lz-v2-sdk/src/endpoint/evm/viemSdk'
import type { ChainMetadataConfigGetter, LZMessageId } from '@monorepo/common-model'

// The service reads these from wallet config; here they are fixed so the Rust port
// can be handed the identical mnemonic and path and the two signatures compared as
// bytes. A well-known test mnemonic, never used for anything real.
const MNEMONIC = 'test test test test test test test test test test test junk'

// One conventional BIP44 path per chain type. Both sides are given this same table,
// so a signature difference is a difference in key derivation or signing, not config.
const DERIVATION_PATH: Record<string, string> = {
    APTOS: "m/44'/637'/0'/0'/0'",
    SOLANA: "m/44'/501'/0'/0'",
    SUI: "m/44'/784'/0'/0'/0'",
    IOTAMOVE: "m/44'/784'/0'/0'/0'",
    INITIA: "m/44'/118'/0'/0'/0'",
    TON: "m/44'/607'/0'",
    STARKNET: "m/44'/9004'/0'/0/0",
    STELLAR: "m/44'/148'/0'",
    EVM: "m/44'/60'/0'/0/0",
    TRON: "m/44'/60'/0'/0/0",
}

const walletNameFor = (chainType: string) => `wallet-${chainType}`

const mnemonicFor = (chainType: string): Mnemonic => ({
    mnemonic: MNEMONIC,
    path: DERIVATION_PATH[chainType] ?? DERIVATION_PATH.EVM,
})

const mnemonicConfigs = {
    async getMnemonicByName(
        _walletName: string,
        chainType: string,
    ): Promise<Mnemonic> {
        return mnemonicFor(chainType)
    },
    async getMnemonicConfig(
        _walletName: string,
        chainType: string,
    ): Promise<MnemonicConfig> {
        const mnemonic = mnemonicFor(chainType)
        return { getMnemonic: async () => mnemonic }
    },
}

const walletDefinitions: WalletDefinition[] = Object.keys(DERIVATION_PATH).map(
    (chainType) => ({
        name: walletNameFor(chainType),
        walletSetName: 'parity',
        // No signerType means the mnemonic signer, which is what the factory
        // defaults to (packages/adapters/signer-adapter/src/factory.ts:66-77).
        byChainType: { [chainType]: {} },
    }),
)

const signerGetter = new GasolinaSignerAdapterGetter(
    new SignerAdapterFactory({ walletDefinitions, mnemonicConfigs }),
)

const PACKET_SENT_TOPIC =
    '0x1ab700d4ced0c005b164c0f789fd09fcbb0156d4c2041b8a3bfbcd961cd1567f'

// TON's verify path resolves the DVN proxy's implementation through a quorum-backed
// storage read (`apps/gasolina/src/app/sdks/gasolinaSdk/ton/index.ts:144-159` ->
// `packages/contracts/lz-ton-contracts/src/index.ts:613-645`), which no argument
// bypasses. Its payload builders are compared byte for byte through
// `crates/pillar-layerzero/tests/gasolina_parity/ton_dvn_verify.json` instead.
// A TON destination needs its DVN proxy's account state, because upstream resolves
// the proxy's implementation before it can name the contract the DVN call targets.
// The state is recorded in the pathway fixture, so the read is replayed rather than
// performed: `getTonV2QuorumProvider` hands a non-multiprovider straight back
// (`multiprovider/src/quorumProvider.ts:101-109`), so a plain object is enough.
const tonProvidersFor = (pathway: Pathway): any => {
    const recorded = pathway.dvnAccountState
    const open = (contract: any) => ({
        address: contract.address,
        getState: async () => ({
            state: { type: recorded ? recorded.state : 'uninit' },
        }),
        getCurrentStorageCell: async () =>
            Cell.fromBoc(Buffer.from(recorded!.data, 'base64'))[0],
    })
    return { v2: { open }, v3: { open } }
}

const OFFLINE_EXCLUDED: Record<string, string> = {}

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
    dvnAccountState?: { address: string; state: string; data: string }
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

// The service's own sign stage: `app.ts:530-538` resolves an adapter per destination
// chain and wallet, then calls `gasolinaSign` on the built hash call data. Same two
// calls here, so what is compared is the public signer path and not a re-derivation.
const signStage = async (dstChainName: string, hashCallData: string) => {
    const chainType = StaticChainConfigs.getChainType(dstChainName)
    try {
        const adapter = await signerGetter.getSignerAdapter(
            dstChainName,
            walletNameFor(chainType),
        )
        const signed = await adapter.gasolinaSign({
            data: hexToBytes(hashCallData),
        })
        return {
            signerChainType: chainType,
            derivationPath: mnemonicFor(chainType).path,
            signature: signed.signature,
            signerAddress: signed.address,
        }
    } catch (error) {
        return {
            signerChainType: chainType,
            derivationPath: mnemonicFor(chainType).path,
            signError: (error as Error).message.slice(0, 300),
        }
    }
}

// getLZSentEvent never consults chain metadata; the interface is only needed to
// construct the sdk (`endpoint/evm/index.ts:95-100`), so a literal is enough.
const OFFLINE_METADATA = {
    getBlockFinalities: () => ({}) as any,
    getBlockFinality: () => 0,
    getAvgBlockTime: () => 0,
    getMaxEthGetLogsBlockRange: () => 100,
    getSupportsBlockPinning: () => false,
} as unknown as ChainMetadataConfigGetter

// The service picks the viem implementation for testnet and the ethers one for
// mainnet (`endpoint/factory.ts:33-55`). Both are exercised, because they are two
// different resolvers that the single Rust resolver has to match.
const endpointSdkFor = (pathway: Pathway, receipt: unknown) => {
    // ethers validates that it was handed a real provider when it connects the
    // endpoint contract, so this is a real one with a static network (no detection)
    // whose single reachable method is replaced. The URL is never dialled: the only
    // call on this path is getTransactionReceipt (`endpoint/evm/index.ts:194-195`).
    const provider: any = new ethers.providers.JsonRpcProvider(
        'http://127.0.0.1:1',
        { chainId: 1, name: 'offline-parity' },
    )
    provider.getTransactionReceipt = async () => receipt
    provider.viem = { getTransactionReceipt: async () => receipt }
    const Sdk =
        pathway.environment === 'mainnet' ? EndpointV2EvmSdk : EndpointV2EvmSdkViem
    return new Sdk(
        pathway.srcChainName,
        pathway.environment,
        provider,
        OFFLINE_METADATA,
    )
}

// Upstream's own source-event resolution over the recorded receipt: this is the
// stage that picks the PacketSent log, checks who emitted it, decodes the packet and
// matches it against the requested lzMessageId.
const resolveStage = async (
    pathway: Pathway,
    receipt: unknown,
    lzMessageId: LZMessageId,
) => endpointSdkFor(pathway, receipt).getLZSentEvent(pathway.txHash, lzMessageId)

// The same receipt with the packet emitted by an address that is not the endpoint.
const withForeignEmitter = (pathway: Pathway) => ({
    ...pathway.receipt,
    logs: pathway.receipt.logs.map((log) =>
        log.topics[0]?.toLowerCase() === PACKET_SENT_TOPIC
            ? { ...log, address: '0x00000000000000000000000000000000deadbeef' }
            : log,
    ),
})

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
        // Decoded once by hand only to obtain the lzMessageId the caller would send;
        // the event actually compared below is the one upstream's resolver returns.
        const requested = extractLZEventFromPacketSentEvent(
            pathway.srcChainName,
            pathway.environment,
            packetSentEventFrom(raw),
        ).lzMessageId
        normalizedEvent = await resolveStage(pathway, pathway.receipt, requested)
        vId = getVId(pathway.dstChainName, pathway.environment)
    } catch (error) {
        return { ...base, decodeError: (error as Error).message.slice(0, 300) }
    }

    let foreignEmitter: string
    try {
        const requested = normalizedEvent.lzMessageId
        await resolveStage(pathway, withForeignEmitter(pathway), requested)
        foreignEmitter = 'ACCEPTED'
    } catch (error) {
        foreignEmitter = `refused: ${(error as Error).message.slice(0, 120)}`
    }

    try {
        // Providers deliberately absent: nothing compared here reads one.
        const factory = new GasolinaSdkFactory({
            environment: pathway.environment,
            providers:
                pathway.family === 'TON'
                    ? { [pathway.dstChainName]: tonProvidersFor(pathway) }
                    : {},
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
            resolver:
                pathway.environment === 'mainnet'
                    ? 'EndpointV2EvmSdk'
                    : 'EndpointV2EvmSdkViem',
            foreignEmitter,
            normalizedEvent,
            targetContract: built.details.dvnCallData?.targetContract,
            ulnCallData: built.details.dvnCallData?.ulnCallData,
            vid: built.details.dvnCallData?.vid,
            expiration: built.details.dvnCallData?.expiration,
            ulnCallDataDetails: built.details.ulnCallData,
            hashCallData: built.hashCallData,
            ...(await signStage(pathway.dstChainName, built.hashCallData)),
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
                        'packages/sdks/lz-v2-sdk/src/endpoint/evm/index.ts:EndpointV2EvmSdk.getLZSentEvent',
                        'packages/sdks/lz-v2-sdk/src/endpoint/evm/viemSdk.ts:EndpointV2EvmSdk.getLZSentEvent',
                        'packages/adapters/signer-adapter/src/factory.ts:SignerAdapterFactory',
                        'packages/adapters/gasolina-signer-adapter/src/gasolinaSignerAdapterGetter.ts:getSignerAdapter',
                        'packages/adapters/gasolina-signer-adapter/src/gasolinaSignerAdapter.ts:gasolinaSign',
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
