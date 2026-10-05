// Runs upstream's own Aptos V301 already-signed chain - `getUlnReceiveDetails`, then
// `UlnAptosSdk.getDstUlnConfig` and `hasPayloadSigned`, as `App.validatePayloadSigned`
// calls them (`apps/gasolina/src/app/app.ts:403-422`) - against a stub Move provider
// that answers each scenario and records every request. Offline; nothing is signed.
const { UlnAptosSdk } = require('/tmp/gasolina-run/work/migrated/offchain-monorepo/packages/sdks/lz-v2-sdk/src/uln/aptos/index.ts')
const { getUlnReceiveDetails } = require('/tmp/gasolina-run/work/migrated/offchain-monorepo/packages/sdks/lz-v2-sdk/src/uln/move/index.ts')

const NONCE = 74756
const DVN = '0x' + '33'.repeat(32)
const MAIN_RECEIVER = '0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa'
const TEST_RECEIVER = '0xec84c05cc40950c86d8a8bed19552f1e8ebb783196bb021c916161d22dc179f7'
const MAIN_SENDER = '0x50002cdfe7ccb0c41f519c6eb0653158d11cd907'
const TEST_SENDER = '0x2afd0d8a477ad393d2234253407fb1cec92749d1'
const configBlob = (confirmations) =>
    '0x' + confirmations.toString(16).padStart(16, '0') + '00' + '01' + DVN.slice(2) + '00' + '000000'

const unsigned = {
    receiveMsglib: ['2', 0],
    requiredConfirmations: 2,
    dvnConfirmations: 1,
    verificationState: 0,
    inboundNonce: NONCE - 1,
    storedPayloadHash: null,
}
const scenarios = {
    unsigned,
    confirmationsAtThreshold: { ...unsigned, dvnConfirmations: 2 },
    nonceAlreadyReceived: { ...unsigned, inboundNonce: NONCE },
    payloadHashStored: { ...unsigned, storedPayloadHash: '0xfeed' },
    verifyingWithoutStoredHash: unsigned,
    verified: { ...unsigned, verificationState: 2 },
    verifiable: { ...unsigned, verificationState: 1 },
    notInitializable: { ...unsigned, verificationState: 3 },
    capExceeded: { ...unsigned, verificationState: 4 },
    unknownState: { ...unsigned, verificationState: 5 },
    ulnV2ReceiveLibrary: { ...unsigned, receiveMsglib: ['1', 0] },
}
const environments = {
    mainnet: { srcChainName: 'ethereum', srcEid: 101, dstEid: 108, receiver: MAIN_RECEIVER, sender: MAIN_SENDER },
    testnet: { srcChainName: 'sepolia', srcEid: 10161, dstEid: 10108, receiver: TEST_RECEIVER, sender: TEST_SENDER },
}

const notFound = () => Object.assign(new Error('Not found'), { status: 404 })

const main = async () => {
    const out = {}
    for (const [environment, pathway] of Object.entries(environments)) {
        out[environment] = {}
        for (const [name, state] of Object.entries(scenarios)) {
            const requests = []
            const rpc = {
                view: async ({ payload }) => {
                    requests.push({ kind: 'view', function: payload.function, arguments: payload.functionArguments.map(String), functionArguments: payload.functionArguments.map(String), functionArgumentTypes: payload.functionArgumentTypes })
                    const fn = payload.function.split('::').pop()
                    if (fn === 'get_receive_msglib') return state.receiveMsglib
                    if (fn === 'get_config') return [configBlob(state.requiredConfirmations)]
                    if (fn === 'get_verification_confirmations') return [String(state.dvnConfirmations)]
                    if (fn === 'verifiable') return [state.verificationState]
                    if (fn === 'inbound_nonce') return [String(state.inboundNonce)]
                    throw new Error('unscripted view ' + payload.function)
                },
                getAccountResource: async (args) => {
                    requests.push({ kind: 'getAccountResource', ...args })
                    if (state.storedPayloadHash === null) throw notFound()
                    return { states: { handle: '0xstates' } }
                },
                getTableItem: async (args) => {
                    requests.push({ kind: 'getTableItem', ...args })
                    if (args.handle === '0xstates') return { payload_hashs: { handle: '0xhashes' } }
                    if (args.handle === '0xhashes') return state.storedPayloadHash
                    throw new Error('unscripted table ' + args.handle)
                },
            }
            const pathwayId = {
                srcChainName: pathway.srcChainName,
                dstChainName: 'aptos',
                srcEid: pathway.srcEid,
                dstEid: pathway.dstEid,
                sender: pathway.sender,
                receiver: pathway.receiver,
            }
            const lzMessage = {
                lzMessageId: { pathwayId, nonce: NONCE, ulnSendVersion: 'V301' },
                guid: '0x' + '5a'.repeat(32),
                message: '0x' + 'c0ffee'.repeat(11),
            }
            let verdict
            try {
                const { ulnVersion } = await getUlnReceiveDetails({ provider: rpc, environment, pathwayId })
                const sdk = new UlnAptosSdk('aptos', environment, { rpc }, undefined)
                const inboundUlnConfig = await sdk.getDstUlnConfig(pathwayId, ulnVersion)
                const signed = await sdk.hasPayloadSigned({ lzMessage, ulnReceiveVersion: ulnVersion, inboundUlnConfig, verifierAddress: DVN })
                verdict = { ulnVersion, signed }
            } catch (error) {
                verdict = { error: String((error && error.message) || error) }
            }
            out[environment][name] = { state, requests, verdict }
        }
    }
    process.stdout.write(JSON.stringify({
        provenance: {
            upstream: 'Gasolina 1.2.66 source snapshot; @layerzerolabs/lz-aptos-sdk-v1@3.0.168 (lockfile)',
            entrypoints: [
                'packages/sdks/lz-v2-sdk/src/uln/move/index.ts:getUlnReceiveDetails',
                'packages/sdks/lz-v2-sdk/src/uln/aptos/index.ts:UlnAptosSdk.getDstUlnConfig',
                'packages/sdks/lz-v2-sdk/src/uln/aptos/index.ts:UlnAptosSdk.hasPayloadSigned',
            ],
            input: 'stub Move provider answering each scenario; offline',
        },
        nonce: NONCE,
        dvn: DVN,
        environments: out,
    }, null, 2) + '\n')
}
main().catch((error) => { console.error(error); process.exit(1) })
