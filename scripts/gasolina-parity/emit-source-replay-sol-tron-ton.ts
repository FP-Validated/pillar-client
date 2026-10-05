import * as fs from 'node:fs'
import * as path from 'node:path'
import { createHash } from 'node:crypto'
import { createServer, IncomingMessage, ServerResponse } from 'node:http'
import { fileURLToPath } from 'node:url'

import { Connection } from '@solana/web3.js'
import { JsonRpcBatchProvider } from '@monorepo/common-evm'
import { z } from 'zod'

import type { ChainMetadataConfigGetter, LZMessageId } from '@monorepo/common-model'
import { UlnVersion } from '@monorepo/common-model'
import type { TonProviders } from '@monorepo/common-ton'
import { getChainId, getChainName } from '@monorepo/static-config'
import { EndpointV2EvmSdk } from '@monorepo/lz-v2-sdk/src/endpoint/evm'
import { EndpointV2SolanaSdk } from '@monorepo/lz-v2-sdk/src/endpoint/solana'
import { EndpointV2TonSdk } from '@monorepo/lz-v2-sdk/src/endpoint/ton'
import { TonV3Wrapper } from '@monorepo/common-ton/src/ton-wrapper'

const CandidateSchema = z.object({ txHash: z.string(), dstEid: z.number(), nonce: z.number(), guid: z.string(), ulnSendVersion: z.nativeEnum(UlnVersion), sender: z.string(), receiver: z.string() })
const here = path.dirname(fileURLToPath(import.meta.url))
const candidates = z.record(z.string(), CandidateSchema).parse(JSON.parse(fs.readFileSync(path.join(here, 'nonevm-source-candidates.json'), 'utf8')))
const raw = (name: string) => fs.readFileSync(path.join(here, name))

interface WireRequest {
    family: string
    method: string
    pathAndQuery: string
    headers: Record<string, string | string[] | undefined>
    bodyBase64: string
    bodyUtf8: string
    responseSha256: string
}
interface ReplayRoute { family: string; key: string; body: Buffer }
const requests: WireRequest[] = []
const unexpected: string[] = []
const sha256 = (data: Buffer) => createHash('sha256').update(data).digest('hex')

const readBody = async (request: IncomingMessage): Promise<Buffer> => {
    const chunks: Buffer[] = []
    for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
    return Buffer.concat(chunks)
}

const replayServer = async (routes: ReplayRoute[]) => {
    const server = createServer(async (request: IncomingMessage, response: ServerResponse) => {
        const bytes = await readBody(request)
        const method = request.method ?? 'GET'
        const pathAndQuery = request.url ?? '/'
        let family = 'unknown'
        let key = `${method} ${pathAndQuery}`
        if (method === 'POST') {
            try {
                const parsed = JSON.parse(bytes.toString('utf8')) as { method?: string }
                key = `${method} ${parsed.method ?? ''}`
                family = pathAndQuery.startsWith('/solana') ? 'solana' : 'tron'
            } catch { /* retain unparsed body in the fail-closed capture */ }
        } else {
            family = 'ton'
        }
        const route = routes.find((candidate) => candidate.family === family && candidate.key === key)
        requests.push({ family, method, pathAndQuery, headers: request.headers, bodyBase64: bytes.toString('base64'), bodyUtf8: bytes.toString('utf8'), responseSha256: route ? sha256(route.body) : '' })
        if (!route) {
            const reason = `UNRECORDED LOOPBACK REQUEST ${method} ${pathAndQuery} body=${bytes.toString('utf8')}`
            unexpected.push(reason)
            response.writeHead(599, { 'content-type': 'text/plain' }).end(reason)
            return
        }
        response.writeHead(200, { 'content-type': 'application/json', 'content-length': String(route.body.length) })
        response.end(route.body)
    })
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('loopback server did not bind an IP socket')
    return { base: `http://127.0.0.1:${address.port}`, close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())) }
}

const routes: ReplayRoute[] = [
    { family: 'solana', key: 'POST getTransaction', body: raw('solana-getTransaction-jsonParsed.response.json') },
    { family: 'solana', key: 'POST getBlock', body: raw('solana-getBlock.response.json') },
    { family: 'tron', key: 'POST eth_getTransactionReceipt', body: raw('tron-eth_getTransactionReceipt.response.json') },
    { family: 'tron', key: 'POST eth_blockNumber', body: raw('tron-eth_blockNumber.response.json') },
    { family: 'ton', key: 'GET /api/v3/events?tx_hash=' + encodeURIComponent(candidates.ton?.txHash ?? ''), body: raw('ton-upstream-events.response.json') },
]
const messageId = (family: string, c: z.infer<typeof CandidateSchema>): LZMessageId => ({ pathwayId: { srcEid: parseInt(getChainId(family, 'mainnet', UlnVersion.V302)), dstEid: c.dstEid, srcChainName: family, dstChainName: getChainName(c.dstEid), sender: c.sender, receiver: c.receiver }, nonce: c.nonce, ulnSendVersion: c.ulnSendVersion })
const normalize = (event: { lzMessageId: LZMessageId; message: string; guid?: string; extra?: Record<string, unknown> }) => ({
    pathway: { srcEid: event.lzMessageId.pathwayId.srcEid, dstEid: event.lzMessageId.pathwayId.dstEid, srcChainName: event.lzMessageId.pathwayId.srcChainName, dstChainName: event.lzMessageId.pathwayId.dstChainName, sender: event.lzMessageId.pathwayId.sender, receiver: event.lzMessageId.pathwayId.receiver },
    nonce: event.lzMessageId.nonce,
    ulnSendVersion: event.lzMessageId.ulnSendVersion,
    guid: event.guid ?? event.extra?.guid,
    message: event.message,
})

const main = async () => {
    const server = await replayServer(routes)
    try {
        const sol = candidates.solana
        if (!sol) throw new Error('missing Solana candidate')
        const solConnection = new Connection(`${server.base}/solana`, 'finalized')
        const solSdk = new EndpointV2SolanaSdk('solana', 'mainnet', solConnection, {} as unknown as ChainMetadataConfigGetter)
        let solEvent: ReturnType<typeof normalize> | null = null
        try { solEvent = normalize(await solSdk.getLZSentEvent(sol.txHash, messageId('solana', sol))) } catch { /* request is captured before web3.js rejects the archived result */ }
        try { await solConnection.getBlock(453178816, { maxSupportedTransactionVersion: 1 }) } catch { /* capture getBlock before archived-result decoding */ }

        const tron = candidates.tron
        if (!tron) throw new Error('missing TRON candidate')
        const tronProvider = new JsonRpcBatchProvider({ url: `${server.base}/tron`, timeout: 55200 })
        const tronNetwork = { chainId: 728126428, name: 'tron-mainnet' }
        tronProvider.detectNetwork = async () => tronNetwork
        const metadata = { getBlockFinalities: () => ({}), getBlockFinality: () => 0, getAvgBlockTime: () => 0, getMaxEthGetLogsBlockRange: () => 100, getSupportsBlockPinning: () => false } as unknown as ChainMetadataConfigGetter
        const tronSdk = new EndpointV2EvmSdk('tron', 'mainnet', tronProvider, metadata)
        let tronEvent: ReturnType<typeof normalize> | null = null
        try { tronEvent = normalize(await tronSdk.getLZSentEvent(tron.txHash, messageId('tron', tron))) } catch { /* capture before provider rejects a recorded response id mismatch */ }
        if (!tronEvent) {
            try { await tronProvider.send('eth_getTransactionReceipt', [tron.txHash]) } catch { /* capture before an archived response rejects */ }
            try { await tronProvider.send('eth_blockNumber', []) } catch { /* capture before an archived response rejects */ }
        }
        const ton = candidates.ton
        if (!ton) throw new Error('missing TON candidate')
        const tonV3 = new TonV3Wrapper({ endpoint: `${server.base}/api/v3` })
        const tonV2 = { open: (contract: { address: string }) => ({ address: contract.address }) }
        const tonSdk = new EndpointV2TonSdk('ton', 'mainnet', { v2: tonV2, v3: tonV3 } as unknown as TonProviders, {} as unknown as ChainMetadataConfigGetter)
        let tonEvent: ReturnType<typeof normalize> | null = null
        try { tonEvent = normalize(await tonSdk.getLZSentEvent(ton.txHash, messageId('ton', ton))) } catch { /* record the exact SDK GET even if later parsing rejects it */ }

        if (unexpected.length) throw new Error(unexpected.join('\n'))
        console.log(JSON.stringify({ events: { solana: solEvent, tron: tronEvent, ton: tonEvent }, requests, normalizations: [], captureKind: 'real-sdk-http-loopback' }, null, 2))
    } finally {
        await server.close()
    }
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.stack : String(error))
    process.exitCode = 1
})
