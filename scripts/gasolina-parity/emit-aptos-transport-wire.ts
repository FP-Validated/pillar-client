// Captures gasolina's Aptos provider adapter and real Aptos SDK HTTP bytes against
// public recorded responses. No upstream view function is stubbed or monkey-patched.
import * as fs from 'node:fs'
import * as path from 'node:path'
import { createHash } from 'node:crypto'
import { createServer, IncomingMessage, ServerResponse } from 'node:http'
import { fileURLToPath } from 'node:url'

import { UlnVersion } from '@monorepo/common-model'
import { TRIVIAL_STRATEGY } from '@monorepo/common-utils'

const ROOT = '/tmp/gasolina-run/work/migrated/offchain-monorepo'
const { AptosMultiProvider } = require(`${ROOT}/packages/multiprovider/src/aptos.ts`)
const { UlnAptosSdk } = require(`${ROOT}/packages/sdks/lz-v2-sdk/src/uln/aptos/index.ts`)
const { getUlnReceiveDetails } = require(`${ROOT}/packages/sdks/lz-v2-sdk/src/uln/move/index.ts`)
const { ProviderCategory } = require('@monorepo/common-model')

const here = path.dirname(fileURLToPath(import.meta.url))
const exchangeDir = path.join(here, 'aptos-exchanges')
interface Exchange {
    name: string
    method: string
    pathAndQuery: string
    headers: Record<string, string>
    requestBody: string
    parsedBody?: Record<string, any>
    status: number
    responseHeaders: Record<string, string>
    responseBody: Buffer
}
interface Captured {
    method: string
    pathAndQuery: string
    headers: Record<string, string | string[] | undefined>
    bodyBase64: string
    bodyHex: string
    bodyUtf8: string
    decodedFunction?: string
    status: number
    responseSha256: string
    matchedRecording?: string
    syntheticResponse?: boolean
}
interface ViewObservation {
    function: string
    functionArguments: unknown[]
    functionArgumentTypes?: string[]
}

const readExchangeFiles = (directory: string): Exchange[] => {
    const sourceDir = path.join(here, directory)
    const files = fs.readdirSync(sourceDir).filter((name) => name.endsWith('.request.json')).sort()
    return files.map((name) => {
        const requestPath = path.join(sourceDir, name)
        const request = JSON.parse(fs.readFileSync(requestPath, 'utf8')) as { method: string; url: string; headers?: Record<string, string>; body?: string | null }
        const stem = name.replace(/\.request\.json$/, '')
        const responseMetadata = JSON.parse(fs.readFileSync(path.join(sourceDir, `${stem}.response.json`), 'utf8')) as { status: number; headers?: Record<string, string> }
        const responseBody = fs.readFileSync(path.join(sourceDir, `${stem}.response.body`))
        const url = new URL(request.url)
        const requestBody = request.body ?? ''
        let parsedBody: Record<string, any> | undefined
        try { parsedBody = JSON.parse(requestBody) as Record<string, any> } catch {}
        return {
            name: stem,
            method: request.method,
            pathAndQuery: `${url.pathname}${url.search}`,
            headers: request.headers ?? {},
            requestBody,
            parsedBody,
            status: responseMetadata.status,
            responseHeaders: responseMetadata.headers ?? {},
            responseBody,
        }
    })
}

const readBody = async (request: IncomingMessage): Promise<Buffer> => {
    const chunks: Buffer[] = []
    for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
    return Buffer.concat(chunks)
}
const sha256 = (body: Buffer) => createHash('sha256').update(body).digest('hex')
const exchanges = [...readExchangeFiles('aptos-exchanges'), ...readExchangeFiles('movement-exchanges')]
const captured: Captured[] = []
const unrecorded: string[] = []
const viewObservations: ViewObservation[] = []

const readUleb = (bytes: Buffer, state: { offset: number }): number => {
    let value = 0
    let shift = 0
    while (true) {
        const next = bytes[state.offset++]
        if (next === undefined) throw new Error('truncated BCS ULEB128')
        value |= (next & 0x7f) << shift
        if ((next & 0x80) === 0) return value >>> 0
        shift += 7
        if (shift > 28) throw new Error('invalid BCS ULEB128')
    }
}
const readBcsString = (bytes: Buffer, state: { offset: number }): string => {
    const size = readUleb(bytes, state)
    if (state.offset + size > bytes.length) throw new Error('truncated BCS string')
    const value = bytes.toString('utf8', state.offset, state.offset + size)
    state.offset += size
    return value
}
const decodeViewFunction = (bytes: Buffer): string => {
    const state = { offset: 0 }
    if (bytes.length < 32) throw new Error('truncated BCS module address')
    const address = `0x${bytes.subarray(0, 32).toString('hex')}`
    state.offset = 32
    const module = readBcsString(bytes, state)
    const functionName = readBcsString(bytes, state)
    return `${address}::${module}::${functionName}`
}
const normalizeArg = (value: unknown): string => {
    if (typeof value === 'string') return value.toLowerCase()
    if (typeof value === 'number' || typeof value === 'bigint') return String(value)
    if (Array.isArray(value)) return JSON.stringify(value)
    return JSON.stringify(value)
}
const matchingObservation = (functionId: string, exchange: Exchange): ViewObservation | undefined =>
    viewObservations.find((entry) => {
        const recordedArgs = exchange.parsedBody?.arguments as unknown[] | undefined
        if (entry.function !== functionId || !recordedArgs || entry.functionArguments.length !== recordedArgs.length) return false
        return entry.functionArguments.every((arg, index) => {
            const recorded = recordedArgs[index]
            if (normalizeArg(arg) !== normalizeArg(recorded)) return false
            const type = entry.functionArgumentTypes?.[index]
            if (type === 'u64' || type === 'u128' || type === 'u256') return typeof recorded === 'string'
            if (type === 'u8' || type === 'u16' || type === 'u32') return typeof recorded === 'number'
            return true
        })
    })

const server = createServer(async (request: IncomingMessage, response: ServerResponse) => {
    const body = await readBody(request)
    const method = request.method ?? 'GET'
    const pathAndQuery = request.url ?? '/'
    const bodyText = body.toString('utf8')
    let decodedFunction: string | undefined
    let exchange: Exchange | undefined

    if (method === 'POST' && pathAndQuery.startsWith('/v1/view') && body.length && body[0] !== 0x7b) {
        try {
            decodedFunction = decodeViewFunction(body)
            const candidates = exchanges.filter((candidate) => candidate.method === 'POST' && candidate.pathAndQuery.startsWith('/v1/view') && candidate.parsedBody?.function === decodedFunction)
            exchange = candidates.find((candidate) => matchingObservation(decodedFunction!, candidate))
                ?? candidates.find((candidate) => candidate.name.includes('synthetic'))
        } catch (error) {
            unrecorded.push(`BCS_DECODE ${method} ${pathAndQuery}: ${String(error)}`)
        }
    } else {
        exchange = exchanges.find((candidate) => {
            if (candidate.method !== method || candidate.pathAndQuery !== pathAndQuery) return false
            if (!candidate.requestBody) return !body.length
            if (!body.length) return false
            try { return JSON.stringify(JSON.parse(candidate.requestBody)) === JSON.stringify(JSON.parse(bodyText)) } catch { return candidate.requestBody === bodyText }
        })
    }

    if (!exchange && decodedFunction && (decodedFunction.endsWith('::verifiable') || decodedFunction.endsWith('::get_verification_confirmations'))) {
        const responseBody = Buffer.from(decodedFunction.endsWith('::verifiable') ? '[0]' : '["0"]')
        captured.push({ method, pathAndQuery, headers: request.headers, bodyBase64: body.toString('base64'), bodyHex: body.toString('hex'), bodyUtf8: bodyText, decodedFunction, status: 200, responseSha256: sha256(responseBody), matchedRecording: 'synthetic-zero-response', syntheticResponse: true })
        response.writeHead(200, { 'content-type': 'application/json', 'content-length': String(responseBody.length), connection: 'close' }).end(responseBody)
        return
    }

    if (!exchange) {
        const reason = `UNRECORDED APTOS REQUEST ${method} ${pathAndQuery} bodyHex=${body.toString('hex')}`
        unrecorded.push(reason)
        const responseBody = Buffer.from(reason)
        captured.push({ method, pathAndQuery, headers: request.headers, bodyBase64: body.toString('base64'), bodyHex: body.toString('hex'), bodyUtf8: bodyText, decodedFunction, status: 599, responseSha256: sha256(responseBody) })
        response.writeHead(599, { 'content-type': 'text/plain', 'content-length': String(responseBody.length), connection: 'close' }).end(responseBody)
        return
    }

    captured.push({ method, pathAndQuery, headers: request.headers, bodyBase64: body.toString('base64'), bodyHex: body.toString('hex'), bodyUtf8: bodyText, decodedFunction, status: exchange.status, responseSha256: sha256(exchange.responseBody), matchedRecording: exchange.name })
    const responseHeaders: Record<string, string> = { 'content-length': String(exchange.responseBody.length), connection: 'close' }
    const contentType = Object.entries(exchange.responseHeaders).find(([key]) => key.toLowerCase() === 'content-type')?.[1]
    if (contentType) responseHeaders['content-type'] = contentType
    response.writeHead(exchange.status, responseHeaders).end(exchange.responseBody)
})

const main = async () => {
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('Aptos loopback server failed to bind')
    try {
        const fullnode = `http://127.0.0.1:${address.port}/v1`
        const makeRpc = (chainName: string) => {
            const endpoint = { uri: fullnode, category: ProviderCategory.INTERNAL, entity: 'offline-loopback' }
            const config = {
                getProviderConfig: () => ({ rpc: [endpoint] }),
                getProviderConfigs: () => ({ [chainName]: { rpc: [endpoint] } }),
                getStrategy: () => TRIVIAL_STRATEGY,
            }
            const rpc = new AptosMultiProvider({ chainName, providerConfig: config as never })
            return new Proxy(rpc, {
                get(target, property, receiver) {
                    if (property !== 'view') return Reflect.get(target, property, receiver)
                    return (args: { payload: { function: string; functionArguments?: unknown[]; functionArgumentTypes?: string[] }; options?: unknown }) => {
                        viewObservations.push({ function: args.payload.function, functionArguments: [...(args.payload.functionArguments ?? [])], functionArgumentTypes: args.payload.functionArgumentTypes })
                        return target.view(args as never)
                    }
                },
            })
        }
        const observedRpc = makeRpc('aptos')
        const provider = { rpc: observedRpc }
        const sdk = new UlnAptosSdk('aptos', 'mainnet', provider as never, undefined as never)
        const pathwayId = {
            srcChainName: 'ethereum',
            dstChainName: 'aptos',
            srcEid: 101,
            dstEid: 108,
            sender: '0x50002cdfe7ccb0c41f519c6eb0653158d11cd907',
            receiver: '0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa',
        }
        const receive = await getUlnReceiveDetails({ provider: observedRpc as never, environment: 'mainnet', pathwayId: pathwayId as never })
        const inboundUlnConfig = await sdk.getDstUlnConfig(pathwayId as never, receive.ulnVersion)
        const lzMessage = {
            lzMessageId: { pathwayId, nonce: 74756, ulnSendVersion: UlnVersion.V301 },
            guid: `0x${'5a'.repeat(32)}`,
            message: `0x${'c0ffee'.repeat(11)}`,
        }
        const signed = await sdk.hasPayloadSigned({
            lzMessage: lzMessage as never,
            ulnReceiveVersion: receive.ulnVersion,
            inboundUlnConfig,
            verifierAddress: `0x${'33'.repeat(32)}`,
        })
        const aptosV302PathwayId = { ...pathwayId, srcEid: 30101 }
        const aptosV302Config = await sdk.getDstUlnConfig(aptosV302PathwayId as never, UlnVersion.V302)
        const aptosV302Signed = await sdk.hasPayloadSigned({
            lzMessage: { lzMessageId: { pathwayId: aptosV302PathwayId, nonce: 74756, ulnSendVersion: UlnVersion.V302 }, guid: `0x${'5a'.repeat(32)}`, message: `0x${'c0ffee'.repeat(11)}` } as never,
            ulnReceiveVersion: UlnVersion.V302, inboundUlnConfig: aptosV302Config, verifierAddress: `0x${'33'.repeat(32)}`,
        })
        const movementRpc = makeRpc('movement')
        const movementSdk = new UlnAptosSdk('movement', 'mainnet', { rpc: movementRpc } as never, undefined as never)
        const movementPathwayId = {
            srcChainName: 'ethereum',
            dstChainName: 'movement',
            srcEid: 30101,
            dstEid: 40161,
            sender: `0x${'22'.repeat(32)}`,
            receiver: `0x${'22'.repeat(32)}`,
        }
        const movementV302Config = await movementSdk.getDstUlnConfig(movementPathwayId as never, UlnVersion.V302)
        const movementV302Signed = await movementSdk.hasPayloadSigned({
            lzMessage: { lzMessageId: { pathwayId: movementPathwayId, nonce: 74756, ulnSendVersion: UlnVersion.V302 }, guid: `0x${'5a'.repeat(32)}`, message: `0x${'c0ffee'.repeat(11)}` } as never,
            ulnReceiveVersion: UlnVersion.V302, inboundUlnConfig: movementV302Config, verifierAddress: `0x${'33'.repeat(32)}`,
        })
        process.stdout.write(JSON.stringify({ captureKind: 'real-gasolina-aptos-multiprovider-sdk-http-loopback', aptosSdkVersion: '1.39.0', fullnode, receive, inboundUlnConfig, signed, aptosV302Config, aptosV302Signed, movementV302Config, movementV302Signed, viewObservations, requests: captured, unrecorded }, null, 2) + '\n')
        if (unrecorded.length) process.exitCode = 1
    } finally {
        await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
    }
}

main().catch((error: unknown) => { console.error(error instanceof Error ? error.stack : String(error)); process.exitCode = 1 })
