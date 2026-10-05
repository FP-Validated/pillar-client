import express from 'express'
import { IncomingMessage, ServerResponse } from 'http'
import { Socket } from 'net'
import { deflateRawSync, deflateSync, gzipSync } from 'zlib'

import { App } from '../src/app/app'
import { startServer } from '../src/bootstrap'

// Upstream's own Express bootstrap (body parser, envelope unwrap, v1 presence check,
// v2 Zod gate, signer-info query handling) with a stub app behind it. `getSignerInfo`
// is upstream's own method on a stub roster; nothing past it is reached.
//
// The bootstrap's `listen` is captured instead of binding a socket, and each request is
// handed to the Express application in process, so the run needs no network at all.
type StartServerApp = Parameters<typeof startServer>[0]

const signerInfoHost = {
    getAvailableChainNames: () => ['ethereum', 'bsc'],
    options: {
        gasolinaSenderFactory: {
            getSignerAdaptersByChainName: async () => [{ getSignerInfo: async () => ({ address: '0xsigner' }) }],
        },
    },
}

const stub = {
    getProviderHealth: async () => ({}),
    signRequestV1: async () => ({ reached: 'signRequestV1' }),
    signRequestV2: async () => ({ reached: 'signRequestV2' }),
    getSignerInfo: (chainName: string) => App.prototype.getSignerInfo.call(signerInfoHost, chainName),
} as unknown as StartServerApp

let application: any
;(express.application as any).listen = function () {
    application = this
    return {}
}
startServer(stub, 0)

interface Answer {
    status: number
    body: unknown
}

// How a request body is rebuilt on the Rust side. Small bodies travel as exact hex;
// large ones as a recipe, since only their inflated content reaches the parser.
type BodySpec = { text: string } | { hex: string } | { pad: number } | { gzip: BodySpec } | { deflate: BodySpec }

const bytesOf = (spec: BodySpec): Buffer => {
    if ('text' in spec) return Buffer.from(spec.text, 'utf8')
    if ('hex' in spec) return Buffer.from(spec.hex, 'hex')
    if ('pad' in spec) return Buffer.from(JSON.stringify({ pad: 'a'.repeat(spec.pad) }), 'utf8')
    if ('gzip' in spec) return gzipSync(bytesOf(spec.gzip))
    return deflateSync(bytesOf(spec.deflate))
}
const hex = (bytes: Buffer): BodySpec => ({ hex: bytes.toString('hex') })

const send = (
    method: string,
    path: string,
    contentType: string | null,
    body: Buffer,
    contentEncoding: string | string[] | null,
): Promise<Answer> => {
    const { promise, resolve } = Promise.withResolvers<Answer>()
    const req = new IncomingMessage(new Socket())
    req.method = method
    req.url = path
    req.httpVersion = '1.1'
    const headers: Record<string, string | string[]> = { host: '127.0.0.1' }
    if (method === 'POST') headers['content-length'] = String(body.length)
    if (contentType !== null) headers['content-type'] = contentType
    // Node joins a repeated Content-Encoding line with ", " before Express sees it.
    if (contentEncoding !== null) {
        headers['content-encoding'] = Array.isArray(contentEncoding) ? contentEncoding.join(', ') : contentEncoding
    }
    req.headers = headers
    const res = new ServerResponse(req)
    const chunks: Buffer[] = []
    res.write = ((chunk: any, encoding?: any) => {
        if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8'))
        return true
    }) as any
    res.end = ((chunk?: any, encoding?: any) => {
        if (chunk && typeof chunk !== 'function') {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8'))
        }
        const text = Buffer.concat(chunks).toString('utf8')
        const json = String(res.getHeader('content-type') ?? '').startsWith('application/json')
        // Express's HTML error page embeds a host stack trace, so only its status is portable.
        resolve({ status: res.statusCode, body: json ? (JSON.parse(text) as unknown) : null })
        return res
    }) as any
    // What Express's finalhandler answers when the router falls through: the error's
    // own status, else 500, else 404 when nothing matched.
    application.handle(req, res, (error?: any) =>
        resolve({ status: error ? (error.status ?? error.statusCode ?? 500) : 404, body: null }),
    )
    if (method === 'POST') req.push(body)
    req.push(null)
    return promise
}

// The RFC 2152 encoder iconv-lite uses (`encodings/utf7.js`), for building UTF-7 bodies.
const utf16be = (text: string): Buffer => {
    const le = Buffer.from(text, 'utf16le')
    const be = Buffer.alloc(le.length)
    for (let i = 0; i < le.length; i += 2) {
        be[i] = le[i + 1]
        be[i + 1] = le[i]
    }
    return be
}
const utf7 = (text: string): Buffer =>
    Buffer.from(
        text.replace(/[^A-Za-z0-9'(),\-./:? \n\r\t]+/g, (chunk) =>
            '+' + (chunk === '+' ? '' : utf16be(chunk).toString('base64').replace(/=+$/, '')) + '-',
        ),
    )
const utf7imap = (text: string): Buffer =>
    Buffer.from(
        text.replace(/[^\x20-\x7e]+|&/g, (chunk) =>
            chunk === '&' ? '&-' : '&' + utf16be(chunk).toString('base64').replace(/\//g, ',').replace(/=+$/, '') + '-',
        ),
    )

const object = JSON.stringify({ srcTxHash: '0xtx' })
// A v1 request upstream's presence check passes, so the stub answers 200 when the
// body arrives intact.
const validV1 = JSON.stringify({
    srcTxHash: '0xtx',
    lzMessageId: { srcChainId: '101', dstChainId: '102', nonce: 7, srcUAAddress: '0xs', dstUAAddress: '0xd' },
    blockConfirmation: 1,
    expiration: 123,
    ulnVersion: 'V2',
    messageHash: '0xhash',
})
// v2 echoes an invalid `ulnSendVersion` in its Zod message, so a decoded body is visible.
const echo = JSON.stringify({ srcTxHash: '0xtx', lzMessageId: { ulnSendVersion: 'V\u00e9\u20ac\ud83d\ude00' } })
const echoBytes = Buffer.from(echo, 'utf8')
const echoLe = Buffer.from(echo, 'utf16le')
const echoBe = utf16be(echo)
const half = Math.floor(echoBytes.length / 2)
const invalidUtf8 = Buffer.concat([
    Buffer.from('{"srcTxHash":"0xtx","lzMessageId":{"ulnSendVersion":"V'),
    Buffer.from([0xff, 0xe2, 0x82]),
    Buffer.from('"}}'),
])

type Case = [string, string | null, BodySpec, (string | string[] | null)?]
const postCases: Case[] = [
    ['noContentType', null, { text: object }],
    ['textPlain', 'text/plain', { text: object }],
    ['plusJson', 'application/merge-patch+json', { text: object }],
    ['emptyJson', 'application/json', { text: '' }],
    ['latin1Charset', 'application/json; charset=latin1', { text: object }],
    ['latin1Empty', 'application/json; charset=latin1', { text: '' }],
    ['duplicateCharsetLastWins', 'application/json; charset=utf-8; charset=latin1', { text: object }],
    ['emptyCharset', 'application/json; charset=""', { text: object }],
    ['bomObject', 'application/json', { text: '\uFEFF' + object }],
    ['rawString', 'application/json', { text: '"x"' }],
    ['rawNull', 'application/json', { text: 'null' }],
    ['rawNumber', 'application/json', { text: '5' }],
    ['malformed', 'application/json', { text: '{' }],
    ['envelopeString', 'application/json', { text: JSON.stringify({ body: '"x"' }) }],
    ['envelopeNull', 'application/json', { text: JSON.stringify({ body: 'null' }) }],
    ['envelopeNumber', 'application/json', { text: JSON.stringify({ body: '5' }) }],
    ['envelopeArray', 'application/json', { text: JSON.stringify({ body: '[]' }) }],
    ['tooLarge', 'application/json', { pad: 102400 }],
    ['tooLargeNoContentType', null, { pad: 102400 }],
    ['deflateEmptyBody', 'application/json', { text: '' }, 'deflate'],
    ['tooLargeLatin1', 'application/json; charset=latin1', { pad: 102400 }],
    ['brotliEncoding', 'application/json', { text: object }, 'br'],
    ['identityEncoding', 'application/json', { text: object }, 'Identity'],
    ['emptyEncoding', 'application/json', { text: object }, ''],
    ['duplicateEncoding', 'application/json', { text: object }, ['identity', 'identity']],
    ['gzipLabelledPlain', 'application/json', { text: object }, 'gzip'],
    ['deflateLabelledPlain', 'application/json', { text: object }, 'deflate'],
    ['tooLargeBrotli', 'application/json', { pad: 102400 }, 'br'],
    // Compressed bodies, decoded upstream by zlib under the 100kb limit on inflated bytes.
    ['gzipValid', 'application/json', hex(gzipSync(echoBytes)), 'gzip'],
    ['gzipUpperCase', 'application/json', hex(gzipSync(echoBytes)), 'GZIP'],
    ['deflateValid', 'application/json', hex(deflateSync(echoBytes)), 'deflate'],
    ['deflateRaw', 'application/json', hex(deflateRawSync(echoBytes)), 'deflate'],
    ['gzipMultiMember', 'application/json', hex(Buffer.concat([gzipSync(echoBytes.subarray(0, half)), gzipSync(echoBytes.subarray(half))])), 'gzip'],
    ['gzipTrailingGarbage', 'application/json', hex(Buffer.concat([gzipSync(echoBytes), Buffer.from('garbage')])), 'gzip'],
    ['deflateTrailingGarbage', 'application/json', hex(Buffer.concat([deflateSync(echoBytes), Buffer.from('garbage')])), 'deflate'],
    ['deflateTruncatedTrailer', 'application/json', hex(deflateSync(echoBytes).subarray(0, -4)), 'deflate'],
    ['deflateHeaderOnly', 'application/json', hex(deflateSync(echoBytes).subarray(0, 2)), 'deflate'],
    ['deflateTruncatedValidV1', 'application/json', hex(deflateSync(Buffer.from(validV1)).subarray(0, -4)), 'deflate'],
    ['deflateCompleteValidV1', 'application/json', hex(deflateSync(Buffer.from(validV1))), 'deflate'],
    ['gzipTrailingZeros', 'application/json', hex(Buffer.concat([gzipSync(echoBytes), Buffer.alloc(8)])), 'gzip'],
    ['gzipTrailingZeroThenText', 'application/json', hex(Buffer.concat([gzipSync(echoBytes), Buffer.from([0x00, 0x41, 0x42])])), 'gzip'],
    ['gzipMemberThenZeros', 'application/json', hex(Buffer.concat([gzipSync(echoBytes.subarray(0, half)), gzipSync(echoBytes.subarray(half)), Buffer.alloc(3)])), 'gzip'],
    ['gzipTruncated', 'application/json', hex(gzipSync(echoBytes).subarray(0, 20)), 'gzip'],
    ['gzipEmptyBody', 'application/json', { text: '' }, 'gzip'],
    ['gzipOfEmpty', 'application/json', hex(gzipSync(Buffer.alloc(0))), 'gzip'],
    ['gzipWithBom', 'application/json', hex(gzipSync(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), echoBytes]))), 'gzip'],
    ['gzipUtf16le', 'application/json; charset=utf-16le', hex(gzipSync(echoLe)), 'gzip'],
    ['gzipInflatesAtLimit', 'application/json', { gzip: { pad: 102400 - 10 } }, 'gzip'],
    ['gzipInflatesOverLimit', 'application/json', { gzip: { pad: 102400 - 9 } }, 'gzip'],
    ['gzipBomb', 'application/json', { gzip: { pad: 4 * 1024 * 1024 } }, 'gzip'],
    ['deflateInflatesOverLimit', 'application/json', { deflate: { pad: 102400 - 9 } }, 'deflate'],
    ['gzipUnknownUtfLabel', 'application/json; charset=utf-32', hex(gzipSync(echoBytes)), 'gzip'],
    // Charsets: iconv-lite 0.4.24 knows utf8, utf16le, utf16be, utf16, utf7 and utf7imap.
    ['utf16leBom', 'application/json; charset=utf-16le', hex(Buffer.concat([Buffer.from([0xff, 0xfe]), echoLe]))],
    ['utf16leNoBom', 'application/json; charset=utf-16le', hex(echoLe)],
    ['utf16leOddTrailingByte', 'application/json; charset=utf-16le', hex(Buffer.concat([echoLe, Buffer.from([0x20])]))],
    ['utf16beBom', 'application/json; charset=utf-16be', hex(Buffer.concat([Buffer.from([0xfe, 0xff]), echoBe]))],
    ['utf16beNoBom', 'application/json; charset=UTF-16BE', hex(echoBe)],
    ['utf16DetectBeBom', 'application/json; charset=utf-16', hex(Buffer.concat([Buffer.from([0xfe, 0xff]), echoBe]))],
    ['utf16DetectLeBom', 'application/json; charset=utf-16', hex(Buffer.concat([Buffer.from([0xff, 0xfe]), echoLe]))],
    ['utf16DetectBeHeuristic', 'application/json; charset=utf-16', hex(echoBe)],
    ['utf16DetectLeHeuristic', 'application/json; charset=utf-16', hex(echoLe)],
    ['utf16DetectShort', 'application/json; charset=utf-16', hex(Buffer.from('{ }', 'utf16le'))],
    ['utf16DashedLabel', 'application/json; charset="utf-16-le"', hex(echoLe)],
    ['utf8YearSuffix', 'application/json; charset="utf-8:1990"', { text: echo }],
    ['utf7', 'application/json; charset=utf-7', hex(utf7(echo))],
    ['utf7Plus', 'application/json; charset=UTF-7', hex(Buffer.from('{"srcTxHash":"0xtx","lzMessageId":{"ulnSendVersion":"a+-b+AOk"}}'))],
    ['utf7HighByte', 'application/json; charset=utf-7', hex(Buffer.from([...Buffer.from('{"srcTxHash":"0xtx","lzMessageId":{"ulnSendVersion":"x'), 0xe9, ...Buffer.from('"}}')]))],
    ['utf7Imap', 'application/json; charset=utf-7-imap', hex(utf7imap(echo))],
    ['utf7RunBom', 'application/json; charset=utf-7', hex(Buffer.from('{"srcTxHash":"0xtx","lzMessageId":{"ulnSendVersion":"x+/v8-y"}}'))],
    ['utf7LeadingRunBom', 'application/json; charset=utf-7', hex(Buffer.from('{+/v8-"srcTxHash":"0xtx","lzMessageId":{"ulnSendVersion":"z"}}'))],
    ['utf7RunAtEnd', 'application/json; charset=utf-7', hex(Buffer.from('{"srcTxHash":"0xtx","lzMessageId":{"ulnSendVersion":"w"}}+AAAAAAAA/v8'))],
    ['utf9TooLarge', 'application/json; charset=utf-9', { pad: 102400 }],
    ['utf32Unknown', 'application/json; charset=utf-32', { text: object }],
    ['utf9Unknown', 'application/json; charset=utf-9', { text: object }],
    ['invalidUtf8', 'application/json', hex(invalidUtf8)],
    ['echoUtf8', 'application/json', { text: echo }],
]

// `req.query` is Express's extended `qs` parse (`application.js` "query parser").
const signerInfoQueries: Array<[string, string]> = [
    ['none', ''],
    ['empty', 'chainName='],
    ['bare', 'chainName'],
    ['plain', 'chainName=ethereum'],
    ['caseDiffers', 'chainName=ETHEREUM'],
    ['unknown', 'chainName=solana'],
    ['repeated', 'chainName=ethereum&chainName=bsc'],
    ['repeatedSame', 'chainName=ethereum&chainName=ethereum'],
    ['bareThenValue', 'chainName&chainName=bsc'],
    ['bracketArray', 'chainName[]=ethereum'],
    ['bracketArrayTwo', 'chainName[]=x&chainName[]=y'],
    ['bracketEmpty', 'chainName[]='],
    ['indexed', 'chainName[0]=a&chainName[2]=b'],
    ['indexedSingle', 'chainName[0]=ethereum'],
    ['indexOverLimit', 'chainName[21]=x'],
    ['indexAtLimit', 'chainName[20]=x'],
    ['objectKey', 'chainName[k]=x'],
    ['nested', 'chainName[a][b]=c'],
    ['nestedArray', 'chainName[][]=x'],
    ['plainThenBracket', 'chainName=ethereum&chainName[]=x'],
    ['bracketThenPlain', 'chainName[]=x&chainName=ethereum'],
    ['objectThenPlain', 'chainName[k]=x&chainName=ethereum'],
    ['plainThenObject', 'chainName=ethereum&chainName[k]=x'],
    ['arrayThenObject', 'chainName[]=x&chainName[k]=y'],
    ['encodedKey', 'chain%4Eame=bsc'],
    ['bracketedRoot', '[chainName]=bsc'],
    ['toStringKey', 'chainName[toString]=x'],
    ['valueOfKey', 'chainName[valueOf]=x'],
    ['plus', 'chainName=bad+name'],
    ['encodedComma', 'chainName=a%2Cb'],
    ['badPercent', 'chainName=%E0%A4%A'],
    ['newline', 'chainName=bad%0Aname'],
    ['deep', 'chainName[a][b][c][d][e][f][g]=x'],
    ['bracketEquals', 'chainName[a]=b]=c'],
    ['emptyBracketKey', 'chainName[=x'],
    ['emptyParts', '&&chainName=bsc&&'],
    ['encodedBrackets', 'chainName=ethereum&chainName%5B%5D=x'],
    ['encodedBracketsBadPercent', 'chainName=ethereum&chainName%5B%5D%E0=x'],
    ['encodedBracketsLower', 'chainName%5bk%5d=x'],
    ['encodedBracketEquals', 'chainName=ethereum&chainName%5Ba=b%5D=x'],
]

const main = async () => {
    const out: Record<string, unknown> = {}
    for (const path of ['/', '/v2/resolve-and-sign']) {
        for (const [name, contentType, body, contentEncoding = null] of postCases) {
            const answer = await send('POST', path, contentType, bytesOf(body), contentEncoding)
            // Upstream's 200 body is the stub's echo; only its status is portable.
            const portable = answer.status === 200 ? { status: 200, body: null } : answer
            out[`POST ${path} ${name}`] = { method: 'POST', path, contentType, contentEncoding, body: body, answer: portable }
        }
    }
    for (const [name, query] of signerInfoQueries) {
        const path = query === '' ? '/signer-info' : `/signer-info?${query}`
        const answer = await send('GET', path, null, Buffer.alloc(0), null)
        // Upstream's 200 body is the stub's signer list; only its status is portable.
        out[`GET /signer-info ${name}`] = {
            method: 'GET',
            path,
            contentType: null,
            contentEncoding: null,
            body: null,
            answer: answer.status === 200 ? { status: 200, body: null } : answer,
        }
    }
    process.stdout.write('\n@@GOLDEN@@' + JSON.stringify(out, null, 1) + '\n')
    process.exit(0)
}

void main()
