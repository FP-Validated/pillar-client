// Upstream 1.2.66's Canton sequencer path, run offline: `createCantonSequencerProvider`
// (URI and committee parsing, the real HttpRpcClient/HttpScanClient and
// Secp256k1QuorumVerifier) under a scripted `globalThis.fetch`, and the three SDK calls a
// signing request makes through it — `EndpointV2CantonSdk.getLZSentEvent`,
// `RpcCantonSdk.getBlockConfirmations` and `UlnCantonSdk.getDstUlnConfig` +
// `hasPayloadSigned`. Every HTTP exchange is recorded with the outcome, so the Rust side can
// replay the same bytes. `@offchain-monorepo/lz-canton-sdk` is a boundary stub here (its
// package index needs Daml codegen); its three address getters are re-pointed at
// `STATIC_VE3_CONTRACT_ADDRESSES`, which is all `contractGetters.ts:25-46` does. The file
// name avoids "canton", which the boundary loader treats as an excluded path segment.
import * as secp from '/private/tmp/gasolina-run/work/node_modules/.pnpm/@noble+secp256k1@1.7.1/node_modules/@noble/secp256k1/lib/index.js'

const VER = '/private/tmp/gasolina-run/work/packages/protocol/lz-ver-protocol'
const { serializeJson } = require(`${VER}/ver-transport/src/index.ts`)
const { createCantonSequencerProvider } = require(`${VER}/sequencer-sdk/src/index.ts`)
const { STATIC_VE3_CONTRACT_ADDRESSES } = require(`${VER}/ver-address/src/index.ts`)
const { keccak256 } = require(require.resolve('viem', { paths: [`${VER}/ver-transport`] }))

const lzCantonSdk = require('@offchain-monorepo/lz-canton-sdk')
lzCantonSdk.getEndpointV2ContractAddress = () => STATIC_VE3_CONTRACT_ADDRESSES.endpointV2
lzCantonSdk.getUln302ContractAddress = () => STATIC_VE3_CONTRACT_ADDRESSES.uln302
lzCantonSdk.getStaticVe3ContractAddresses = () => Object.values(STATIC_VE3_CONTRACT_ADDRESSES)

const { EndpointV2CantonSdk } = require('@offchain-monorepo/lz-v2-sdk/src/endpoint/canton')
const { UlnCantonSdk } = require('@offchain-monorepo/lz-v2-sdk/src/uln/canton')
const { RpcCantonSdk } = require('@offchain-monorepo/rpc-sdk/src/canton')

const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')
const hex = (bytes: Uint8Array) => '0x' + Buffer.from(bytes).toString('hex')
const keyOf = (seed: string) => keccak256(new TextEncoder().encode(seed)).slice(2)
const KEYS = ['ve3-committee-1', 've3-committee-2', 've3-committee-3', 've3-outsider'].map(keyOf)
const PUB = KEYS.map((key) => secp.getPublicKey(key, false) as Uint8Array)
const COMPRESSED = KEYS.map((key) => secp.getPublicKey(key, true) as Uint8Array)
const BASE = 'https://sequencer.example:8443/base/'
const committeeUri = (quorum: number, keys = [hex(PUB[0]), hex(COMPRESSED[1]), hex(PUB[2])]) =>
    `${BASE}?sequencer-validators=${keys.join(',')}&sequencer-quorum=${quorum}`
const AUTH = { authorization: 'Bearer parity' }

type Signer = { key: number; highS?: boolean; recovery?: number; truncate?: boolean; corrupt?: boolean }
const sign = async (type: string, request: unknown, response: Record<string, unknown>, signers: Signer[]) => {
    const digest = keccak256(serializeJson({ type, request, response }), 'bytes')
    const signatures: string[] = []
    for (const signer of signers) {
        const [compact, recovered] = (await secp.sign(digest, KEYS[signer.key], { recovered: true, der: false })) as [
            Uint8Array,
            number,
        ]
        let bytes = Uint8Array.from(compact)
        let recovery = recovered
        if (signer.highS) {
            const s = BigInt(hex(bytes.slice(32)))
            bytes.set(Buffer.from((N - s).toString(16).padStart(64, '0'), 'hex'), 32)
            recovery ^= 1
        }
        if (signer.corrupt) bytes[5] ^= 0xff
        let signature = hex(bytes) + (signer.recovery ?? recovery).toString(16).padStart(2, '0')
        if (signer.truncate) signature = signature.slice(0, -2)
        signatures.push(signature)
    }
    return { ...response, signatures }
}

type Exchange = { method: string; url: string; headers: Record<string, string>; body: unknown; status: number; text: string }
type Responder = (method: string, url: URL, body: any) => Promise<{ status: number; text: string }>
let exchanges: Exchange[] = []
let responder: Responder = async () => ({ status: 500, text: 'no responder' })
;(globalThis as any).fetch = async (input: string | URL, init: RequestInit = {}) => {
    const url = new URL(String(input))
    const method = (init.method ?? 'GET').toUpperCase()
    const body = init.body ? JSON.parse(String(init.body)) : null
    const { status, text } = await responder(method, url, body)
    exchanges.push({ method, url: url.toString(), headers: { ...(init.headers as any) }, body, status, text })
    return new Response(text, { status })
}
const json = (value: unknown, status = 200) => ({ status, text: JSON.stringify(value) })
const scanRequest = (url: URL) => Object.fromEntries(url.searchParams.entries())

const RealDate = Date
const NOW_MS = 1_800_000_123_456
;(globalThis as any).Date = class extends RealDate {
    constructor(...args: any[]) {
        super(...((args.length ? args : [NOW_MS]) as []))
    }
    static now() {
        return NOW_MS
    }
}

const outcome = async (run: () => Promise<unknown>) => {
    try {
        return { ok: await run() }
    } catch (error: any) {
        return { error: String(error?.message ?? error) }
    }
}

const SR = '0x' + '5e'.repeat(32)
const EP = STATIC_VE3_CONTRACT_ADDRESSES.endpointV2
const CANTON_SENDER = '0x' + 'c4'.repeat(32)
const EVM_RECEIVER = '0x' + '00'.repeat(12) + 'e7'.repeat(20)
const packet = (nonce: bigint, srcEid: number, sender: string, dstEid: number, receiver: string, guid: string, message: string) =>
    '0x01' +
    nonce.toString(16).padStart(16, '0') +
    srcEid.toString(16).padStart(8, '0') +
    sender.slice(2) +
    dstEid.toString(16).padStart(8, '0') +
    receiver.slice(2) +
    guid.slice(2) +
    message.slice(2)
const scanEvent = (nonce: number, payloadNonce: bigint, overrides: Record<string, unknown> = {}) => ({
    requestId: `req-${nonce}`,
    eventIndex: '0',
    name: 'EndpointV2_PacketSentEvent',
    data: {
        encodedPayload: packet(payloadNonce, 30567, CANTON_SENDER, 30101, EVM_RECEIVER, '0x' + 'ab'.repeat(32), '0xdeadbeef'),
        options: '0x0003010011010000000000000000000000000000ea60',
        sendLibrary: STATIC_VE3_CONTRACT_ADDRESSES.uln302,
    },
    emitter: EP,
    hash: '0x' + '11'.repeat(32),
    requestTimestamp: '1799999000000',
    requestTransactionHash: '1220' + 'aa'.repeat(32),
    commitmentTransactionHash: '1220' + 'bb'.repeat(32),
    nonce: String(nonce),
    ...overrides,
})
const requestedId = (nonce: number) => ({
    pathwayId: {
        srcEid: 30567,
        dstEid: 30101,
        sender: CANTON_SENDER,
        receiver: '0x' + 'e7'.repeat(20),
        srcChainName: 'canton',
        dstChainName: 'ethereum',
    },
    nonce,
    ulnSendVersion: 'V302',
})
const requestRecord = (timestamp: string) => ({
    id: 'req-77',
    commitmentId: 'c-1',
    transactionHash: '1220' + 'aa'.repeat(32),
    timestamp,
    nonce: '77',
    blockNumber: '5',
    msgValue: '0',
    transaction: {
        caller: '0x' + '01'.repeat(32),
        transaction: { functionSignature: { contract: 'EndpointV2', function: 'send' }, address: EP, arguments: {} },
    },
})

const COMMITTEE = [{ key: 0 }, { key: 1 }]
const scanResponder =
    (answers: Record<string, (url: URL) => Record<string, unknown> | { raw: string; status: number }>, signers: Signer[] = COMMITTEE): Responder =>
    async (_method, url) => {
        const kind = url.searchParams.get('type')!
        const key = kind === 'events' ? `events:${url.searchParams.get('emitter')}` : kind
        const answer = (answers[key] ?? answers[kind])?.(url)
        if (!answer) return json({ error: true, message: `no answer for ${key}`, stateRoot: SR, signatures: [] })
        if ('raw' in answer) return { status: answer.status as number, text: answer.raw as string }
        return json(await sign('scan', scanRequest(url), answer, signers))
    }
const readResponder =
    (answers: Record<string, Record<string, unknown>>, signers: Signer[] = COMMITTEE): Responder =>
    async (_method, _url, body) => {
        const fn = body.transaction.functionSignature.function
        const answer = answers[fn] ?? { error: true, message: `no answer for ${fn}`, stateRoot: SR }
        if ('raw' in answer) return { status: answer.status as number, text: answer.raw as string }
        return json(await sign('contract', body, answer, (answer as any).__signers ?? signers))
    }

const scenarios: any[] = []
const run = async (scenario: any, responderFor: Responder, call: (provider: any) => Promise<unknown>) => {
    exchanges = []
    responder = responderFor
    const result = await outcome(async () => {
        const provider = createCantonSequencerProvider({ uri: scenario.provider.uri, headers: scenario.provider.headers, chainName: 'canton' })
        return call(provider)
    })
    scenarios.push({ ...scenario, exchanges, outcome: result })
}

const resolve = (name: string, nonce: number, answers: any, signers?: Signer[], uri = committeeUri(2)) =>
    run({ name, kind: 'resolve', provider: { uri, headers: AUTH }, srcTxHash: '1220' + 'bb'.repeat(32), lzMessageId: requestedId(nonce) },
        scanResponder(answers, signers),
        (provider) => new EndpointV2CantonSdk('canton', 'mainnet', { sequencer: provider }, {}).getLZSentEvent('1220' + 'bb'.repeat(32), requestedId(nonce)))

const confirmations = (name: string, nonce: number, answers: any, signers?: Signer[]) =>
    run({ name, kind: 'confirmations', provider: { uri: committeeUri(2), headers: AUTH }, nonce, nowMs: NOW_MS },
        scanResponder(answers, signers),
        (provider) =>
            new RpcCantonSdk({ provider: { sequencer: provider, parties: [] }, chainName: 'canton', chainMetadataConfigGetter: {}, environment: 'mainnet' })
                .getBlockConfirmations('ignored', 0, nonce))

const SENT = {
    onChainEvent: { chainName: 'ethereum', txHash: '0x' + '77'.repeat(32), blockHash: '0x' + '78'.repeat(32), blockNumber: 1 },
    lzMessageId: {
        pathwayId: { srcEid: 30101, srcChainName: 'ethereum', dstEid: 30567, dstChainName: 'canton', sender: '0x' + '5a'.repeat(20), receiver: '0x' + 'c9'.repeat(32) },
        nonce: 42,
        ulnSendVersion: 'V302',
    },
    guid: '0x' + '9d'.repeat(32),
    message: '0x0102030405',
    sendLibrary: '0x' + '33'.repeat(20),
    options: {},
}
const DVN = '0x' + 'dd'.repeat(32)
const payloadSigned = (name: string, answers: any, extra: Record<string, unknown> = {}) =>
    run({ name, kind: 'payloadSigned', provider: { uri: committeeUri(2), headers: AUTH, ...extra }, sentEvent: SENT, dvnAddress: DVN },
        readResponder(answers),
        async (provider) => {
            const uln = new UlnCantonSdk('canton', 'mainnet', { sequencer: provider }, {})
            const inboundUlnConfig = await uln.getDstUlnConfig(SENT.lzMessageId.pathwayId, 'V302')
            return uln.hasPayloadSigned({ lzMessage: SENT, ulnReceiveVersion: 'V302', inboundUlnConfig, verifierAddress: DVN })
        })
const config = (confirmations: unknown = '15') => ({
    value: { confirmations, requiredDvns: ['0x' + 'AA'.repeat(32)], optionalDvns: [], optionalDvnThreshold: 0 },
    stateRoot: SR,
})
const value = (v: unknown, signers?: Signer[]) => ({ value: v, stateRoot: SR, ...(signers ? { __signers: signers } : {}) })

const main = async () => {
    // Provider construction: URI, committee and authorization refusals.
    const uriCases: [string, string, Record<string, string>][] = [
        ['plain https', 'https://sequencer.example/', AUTH],
        ['loopback http', 'http://127.0.0.1:8080', AUTH],
        ['localhost http', 'http://localhost:8080/x', AUTH],
        ['ipv6 loopback http', 'http://[::1]:8080', AUTH],
        ['remote http', 'http://sequencer.example', AUTH],
        ['not a url', 'sequencer.example', AUTH],
        ['committee', committeeUri(2), AUTH],
        ['x-only key', committeeUri(1, [hex(PUB[0].slice(1, 33))]), AUTH],
        ['quorum over committee', committeeUri(4), AUTH],
        ['quorum zero', committeeUri(0), AUTH],
        ['quorum text', `${BASE}?sequencer-validators=${hex(PUB[0])}&sequencer-quorum=two`, AUTH],
        ['quorum fraction', `${BASE}?sequencer-validators=${hex(PUB[0])}&sequencer-quorum=1.5`, AUTH],
        ['quorum hex', `${BASE}?sequencer-validators=${hex(PUB[0])}&sequencer-quorum=0x1`, AUTH],
        ['quorum empty', `${BASE}?sequencer-validators=${hex(PUB[0])}&sequencer-quorum=`, AUTH],
        ['validators only', `${BASE}?sequencer-validators=${hex(PUB[0])}`, AUTH],
        ['quorum only', `${BASE}?sequencer-quorum=1`, AUTH],
        ['no keys', `${BASE}?sequencer-validators=,%20,&sequencer-quorum=1`, AUTH],
        ['duplicate point', committeeUri(1, [hex(PUB[0]), hex(COMPRESSED[0])]), AUTH],
        ['odd key', committeeUri(1, ['0xabc']), AUTH],
        ['bad hex key', committeeUri(1, ['0xzz']), AUTH],
        ['short key', committeeUri(1, ['0x' + '11'.repeat(20)]), AUTH],
        ['off-curve key', committeeUri(1, ['0x04' + '11'.repeat(64)]), AUTH],
        ['field-overflow x', committeeUri(1, ['0x02' + 'ff'.repeat(32)]), AUTH],
        ['no auth', committeeUri(2), {}],
        ['blank auth', committeeUri(2), { Authorization: '   ' }],
    ]
    for (const [name, uri, headers] of uriCases) {
        scenarios.push({
            name,
            kind: 'uri',
            provider: { uri, headers },
            outcome: await outcome(async () => {
                const p = createCantonSequencerProvider({ uri, headers, chainName: 'canton' })
                return { sequencerUrl: p.sequencerUrl, committee: p.sequencerCommittee ?? null }
            }),
        })
    }

    // Source resolution.
    const events = (list: unknown[], latestNonce = '900') => () => ({ events: list, latestNonce, isLatest: true, stateRoot: SR })
    await resolve('one match', 7, { events: events([scanEvent(900, 7n)]) })
    await resolve('second of two', 8, { events: events([scanEvent(900, 7n), scanEvent(901, 8n)]) })
    await resolve('no match', 9, { events: events([scanEvent(900, 7n), scanEvent(901, 8n)]) })
    await resolve('empty', 7, { events: events([]) })
    await resolve('sequencer error', 7, { events: () => ({ error: true, message: 'commitment not found', stateRoot: SR }) })
    await resolve('null latestNonce', 7, { events: events([scanEvent(900, 7n)], null as any) })
    await resolve('outsider signer', 7, { events: events([scanEvent(900, 7n)]) }, [{ key: 0 }, { key: 3 }])
    await resolve('truncated signature', 7, { events: events([scanEvent(900, 7n)]) }, [{ key: 0 }, { key: 1, truncate: true }])
    await resolve('high-s signature', 7, { events: events([scanEvent(900, 7n)]) }, [{ key: 0 }, { key: 1, highS: true }])
    await resolve('recovery 27', 7, { events: events([scanEvent(900, 7n)]) }, [{ key: 0 }, { key: 1, recovery: 27 }])
    await resolve('corrupt signature', 7, { events: events([scanEvent(900, 7n)]) }, [{ key: 0 }, { key: 1, corrupt: true }])
    await resolve('duplicate signer', 7, { events: events([scanEvent(900, 7n)]) }, [{ key: 0 }, { key: 0 }])
    await resolve('no committee', 7, { events: events([scanEvent(900, 7n)]) }, [], 'https://sequencer.example')
    await resolve('html 502', 7, { events: () => ({ raw: '<html>Bad gateway</html>', status: 502 }) })
    await resolve('event without data', 7, { events: events([{ ...scanEvent(900, 7n), data: undefined }]) })

    // Source readiness.
    const at = (emitter: string) => `events:${emitter}`
    const addresses = Object.values(STATIC_VE3_CONTRACT_ADDRESSES) as string[]
    await confirmations('second emitter', 77, {
        [at(addresses[0])]: () => ({ error: true, message: 'no events', stateRoot: SR }),
        [at(addresses[1])]: () => ({ events: [scanEvent(76, 1n), scanEvent(77, 2n, { requestId: 'req-77' })], latestNonce: '80', isLatest: true, stateRoot: SR }),
        requests: () => ({ requests: [requestRecord('1799999990999')], stateRoot: SR }),
    })
    await confirmations('nowhere', 77, {
        events: () => ({ events: [], latestNonce: '76', isLatest: false, stateRoot: SR }),
    })
    await confirmations('no request record', 77, {
        events: () => ({ events: [scanEvent(77, 2n, { requestId: 'req-77' })], latestNonce: '80', isLatest: true, stateRoot: SR }),
        requests: () => ({ requests: [], stateRoot: SR }),
    })
    await confirmations('request error', 77, {
        events: () => ({ events: [scanEvent(77, 2n, { requestId: 'req-77' })], latestNonce: '80', isLatest: true, stateRoot: SR }),
        requests: () => ({ error: true, message: 'request pruned', stateRoot: SR }),
    })
    await confirmations('future emission', 77, {
        events: () => ({ events: [scanEvent(77, 2n, { requestId: 'req-77' })], latestNonce: '80', isLatest: true, stateRoot: SR }),
        requests: () => ({ requests: [requestRecord('1900000000000')], stateRoot: SR }),
    })

    // Already-signed check.
    await payloadSigned('not signed', { getUlnConfig: config(), getHashLookup: value({ submitted: false, confirmations: '0' }), getVerificationState: value('1') })
    await payloadSigned('verified state', { getUlnConfig: config(), getHashLookup: value({ submitted: false, confirmations: '0' }), getVerificationState: value(2) })
    await payloadSigned('dvn confirmed', { getUlnConfig: config(), getHashLookup: value({ submitted: true, confirmations: '15' }), getVerificationState: value('0') })
    await payloadSigned('dvn short', { getUlnConfig: config(), getHashLookup: value({ submitted: true, confirmations: '14' }), getVerificationState: value('0') })
    await payloadSigned('unknown state', { getUlnConfig: config(), getHashLookup: value({ submitted: false, confirmations: '0' }), getVerificationState: value('7') })
    await payloadSigned('config error', { getUlnConfig: { error: true, message: 'no config', stateRoot: SR } })
    await payloadSigned('nan confirmations', { getUlnConfig: config('abc'), getHashLookup: value({ submitted: true, confirmations: '1' }), getVerificationState: value('0') })
    await payloadSigned('state outsider', {
        getUlnConfig: config(),
        getHashLookup: value({ submitted: false, confirmations: '0' }),
        getVerificationState: value('1', [{ key: 0 }, { key: 3 }]),
    })
    await payloadSigned('schema mismatch', { getUlnConfig: { value: {}, stateRoot: 7 } as any })
    await payloadSigned('null dvn entry', {
        getUlnConfig: { value: { confirmations: '1', requiredDvns: [null], optionalDvns: [], optionalDvnThreshold: 0 }, stateRoot: SR },
    })

    process.stdout.write(
        JSON.stringify(
            {
                producedBy: {
                    upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                    entrypoints: [
                        'packages/protocol/lz-ver-protocol/sequencer-sdk/src/provider.ts:createCantonSequencerProvider',
                        'packages/sdks/lz-v2-sdk/src/endpoint/canton/index.ts:getLZSentEvent',
                        'packages/sdks/rpc-sdk/src/canton/index.ts:getBlockConfirmations',
                        'packages/sdks/lz-v2-sdk/src/uln/canton/index.ts:getDstUlnConfig+hasPayloadSigned',
                    ],
                    doubles:
                        'globalThis.fetch scripted; Date fixed at nowMs; lz-canton-sdk getters = STATIC_VE3_CONTRACT_ADDRESSES',
                },
                staticVe3ContractAddresses: Object.entries(STATIC_VE3_CONTRACT_ADDRESSES),
                committee: { privateKeySeeds: ['ve3-committee-1', 've3-committee-2', 've3-committee-3', 've3-outsider'], publicKeys: PUB.map(hex) },
                scenarios,
            },
            null,
            1,
        ) + '\n',
    )
}

main().then(
    () => process.exit(0),
    (error) => {
        console.error(error)
        process.exit(1)
    },
)
setTimeout(() => {
    console.error('emit-ve3-sequencer: never settled')
    process.exit(2)
}, 30_000)
