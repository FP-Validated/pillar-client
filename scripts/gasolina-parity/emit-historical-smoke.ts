// Drives the real Gasolina service entrypoint - `App.signRequestV2`, the method the
// HTTP layer calls - over recorded historical PacketSent receipts, one destination
// chain family per environment, and reports what each pathway produces so the Rust
// port can be compared field by field.
//
// The whole orchestrator runs, not a hand-picked subset of it: protocol-type checks,
// message-hash validation, readiness, expiration, already-signed, then the builder and
// then the signer. That matters twice over. `GasolinaEvmSdk.buildDvnCallData` derives
// the *receive* ULN version from the destination endpoint id (`evm/index.ts:135-145`),
// which a recomposed harness skips; and a reject path is only meaningfully rejected if
// the thing rejecting it is the same orchestrator that would otherwise have signed.
//
// Each pathway is run four times - once normally and once per reject scenario - and the
// signer adapter counts its own invocations, so 'refused without signing' is observed
// rather than assumed.
//
// Offline: no live RPC, no network. Receipts and the TON DVN account state come from
// the fixture; chain reads the orchestrator performs (block confirmations, block
// timestamp, already-signed) are answered by stubs that are named in the output.
import { Cell } from '@ton/core'
import { ethers } from 'ethers'
import * as fs from 'fs'
import * as path from 'path'

import { extractLZEventFromPacketSentEvent } from '@monorepo/lz-v2-sdk/src/endpoint/evm/decoders'
import { EndpointV2__factory } from '@monorepo/lz-evm-sdk-v2-contracts'
import type { PacketSentEvent } from '@monorepo/lz-evm-sdk-v2-contracts'
import { getVId } from '@monorepo/static-config'

import { GasolinaSdkFactory } from '../src/app/sdks/gasolinaSdk/factory'
import { App } from '../src/app/app'
import { buildHashCallDataBuilder } from '../src/app/hashCallDataBuilder'
import { hashSentEventMessageForGasolina } from '@monorepo/gasolina-client'
import { ProtocolType, UlnVersion } from '@monorepo/common-model'
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

// Everything the orchestrator reads from a chain, in one place, so the output can say
// exactly what was answered rather than leaving it implicit. None of these values feed
// a signed field: they gate the request, and the gate is what is being exercised.
const stubReads = (pathway: Pathway, alreadySigned: boolean) => ({
    // Readiness: report exactly the confirmations the request asks for.
    getBlockConfirmations: async (_txHash: string, want: number) => want,
    // Expiration: a timestamp inside the window the caller computed, so the request is
    // neither expired nor too far in the future.
    getBlockTimestamp: async () => pathway.signingContext.expiration - 100,
    getFromAddress: async () => pathway.receipt.from ?? '0x' + '00'.repeat(20),
    // Already-signed: the on-chain question this offline harness cannot ask.
    hasPayloadSigned: async () => alreadySigned,
    getDstUlnConfig: async () => ({}),
    getUlnReceiveVersion: async () => UlnVersion.V302,
})

const buildApp = (
    pathway: Pathway,
    options: {
        receipt: unknown
        alreadySigned: boolean
        availableChains?: string[]
    },
) => {
    const reads = stubReads(pathway, options.alreadySigned)
    const realEndpointFactory = {
        getSdk: (chainName: string) =>
            chainName === pathway.srcChainName
                ? endpointSdkFor(pathway, options.receipt)
                : ({ getUlnReceiveVersion: reads.getUlnReceiveVersion } as any),
    }
    const chains = options.availableChains ?? [
        pathway.srcChainName,
        pathway.dstChainName,
    ]
    const chainType = StaticChainConfigs.getChainType(pathway.dstChainName)
    let signerCalls = 0
    const countingSignerGetter = {
        getSignerAdapter: async (chainName: string, walletName: string) => {
            const adapter = await signerGetter.getSignerAdapter(
                chainName,
                walletName,
            )
            return {
                gasolinaSign: async (args: { data: Uint8Array }) => {
                    signerCalls += 1
                    return adapter.gasolinaSign(args)
                },
            }
        },
    }

    const app = new App({
        signerAdapterGetter: countingSignerGetter as any,
        walletsByChainName: {
            [pathway.dstChainName]: [{ walletName: walletNameFor(chainType) }],
        },
        endpointV2SdkFactory: realEndpointFactory as any,
        rpcSdkFactory: { getSdk: () => reads } as any,
        ulnSdkFactory: { getSdk: () => reads } as any,
        // READ-protocol only; every recorded pathway is a MESSAGE.
        timeMarkerValidatorSdkFactory: {
            getSdk: () => {
                throw new Error('time markers are not part of a MESSAGE pathway')
            },
        } as any,
        lzCmdResolverSdkFactory: {
            getSdk: () => {
                throw new Error('lz cmd resolution is not part of a MESSAGE pathway')
            },
        } as any,
        providerConfigGetter: {
            getProviderConfigs: () =>
                Object.fromEntries(chains.map((name) => [name, {}])),
        } as any,
        environment: pathway.environment,
        debugMode: true,
        maximumExpiration: 60 * 60 * 24 * 7,
        maximumExpirationGracePeriod: 30,
        hashCallDataBuilders: buildHashCallDataBuilder({
            gasolinaSdkFactory: new GasolinaSdkFactory({
                environment: pathway.environment,
                providers:
                    pathway.family === 'TON'
                        ? { [pathway.dstChainName]: tonProvidersFor(pathway) }
                        : {},
            }),
            endpointV2SdkFactory: realEndpointFactory as any,
            lzSdkFactory: {
                getSdk: () => {
                    throw new Error('the V1 LZ sdk is not part of a V3 pathway')
                },
            } as any,
            lzCmdResolverSdkFactory: {
                getSdk: () => {
                    throw new Error('lz cmd resolution is not part of a MESSAGE pathway')
                },
            } as any,
            environment: pathway.environment,
        }),
    })
    return { app, signerCalls: () => signerCalls }
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

    const raw = pathway.receipt.logs.find(
        (log) =>
            log.topics.length === 1 &&
            log.topics[0].toLowerCase() === PACKET_SENT_TOPIC,
    )
    if (!raw) {
        return { ...base, error: 'no PacketSent log in the recorded receipt' }
    }

    // Only to obtain the lzMessageId and messageHash a caller would send. What is
    // compared comes back out of the orchestrator.
    let requested
    try {
        requested = extractLZEventFromPacketSentEvent(
            pathway.srcChainName,
            pathway.environment,
            packetSentEventFrom(raw),
        )
    } catch (error) {
        return { ...base, decodeError: (error as Error).message.slice(0, 300) }
    }
    const request = {
        srcTxHash: pathway.txHash,
        lzMessageId: requested.lzMessageId,
        messageHash: hashSentEventMessageForGasolina(requested),
        signingContext: {
            expiration: pathway.signingContext.expiration,
            blockConfirmation: pathway.signingContext.blockConfirmation,
            dvnAddress: pathway.signingContext.dvnAddress,
            protocolType: ProtocolType.MESSAGE,
        },
    } as any

    // Every reject scenario reports whether the signer was reached, which is the
    // property that matters: refused is only refused if nothing got signed.
    const reject = async (
        label: string,
        build: () => ReturnType<typeof buildApp>,
    ) => {
        const { app, signerCalls } = build()
        try {
            await app.signRequestV2(request)
            return { [label]: 'ACCEPTED', [`${label}SignerCalls`]: signerCalls() }
        } catch (error) {
            return {
                [label]: `refused: ${(error as Error).message.slice(0, 120)}`,
                [`${label}SignerCalls`]: signerCalls(),
            }
        }
    }

    const rejects = {
        ...(await reject('foreignEmitter', () =>
            buildApp(pathway, {
                receipt: withForeignEmitter(pathway),
                alreadySigned: false,
            }),
        )),
        ...(await reject('alreadySigned', () =>
            buildApp(pathway, { receipt: pathway.receipt, alreadySigned: true }),
        )),
        ...(await reject('unavailableChain', () =>
            buildApp(pathway, {
                receipt: pathway.receipt,
                alreadySigned: false,
                availableChains: [pathway.srcChainName],
            }),
        )),
    }

    const { app, signerCalls } = buildApp(pathway, {
        receipt: pathway.receipt,
        alreadySigned: false,
    })
    try {
        const response = await app.signRequestV2(request)
        const details = (response as any).debugInfo.details
        return {
            ...base,
            ...rejects,
            resolver:
                pathway.environment === 'mainnet'
                    ? 'EndpointV2EvmSdk'
                    : 'EndpointV2EvmSdkViem',
            vId: getVId(pathway.dstChainName, pathway.environment),
            normalizedEvent: requested,
            targetContract: details.dvnCallData?.targetContract,
            ulnCallData: details.dvnCallData?.ulnCallData,
            vid: details.dvnCallData?.vid,
            expiration: details.dvnCallData?.expiration,
            ulnCallDataDetails: details.ulnCallData,
            hashCallData: (response as any).debugInfo.dvnHashCallData,
            payload: (response as any).payload,
            signerChainType: StaticChainConfigs.getChainType(pathway.dstChainName),
            derivationPath: mnemonicFor(
                StaticChainConfigs.getChainType(pathway.dstChainName),
            ).path,
            signature: (response as any).signatures[0].signature,
            signerAddress: (response as any).signatures[0].address,
            signerCalls: signerCalls(),
        }
    } catch (error) {
        return {
            ...base,
            ...rejects,
            signRequestError: (error as Error).message.slice(0, 400),
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
