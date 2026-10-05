import { App } from '../src/app/app'

// Upstream's v1 conversion, run through `App.signRequestV1` itself (`app/app.ts:380-405`)
// with `signRequestV2` replaced by an echo: the pathway is converted first, then
// `parseInt(nonce.toString())`. Each case is the JSON `lzMessageId` a client sends.
type Json = null | boolean | number | string | Json[] | { [key: string]: Json }
type V1Request = Parameters<App['signRequestV1']>[0]
type V2Request = Parameters<App['signRequestV2']>[0]

const base: { [key: string]: Json } = { srcChainId: '101', dstChainId: '102', srcUAAddress: '0xs', dstUAAddress: '0xd', nonce: 7 }
const withField = (key: string, value: Json | undefined): { [key: string]: Json } => {
    const copy = { ...base }
    if (value === undefined) delete copy[key]
    else copy[key] = value
    return copy
}

const ids: Array<[string, Json | undefined]> = [
    ['v1Eid', '101'],
    ['v1ChainId', '1'],
    ['v2Eid', '30101'],
    ['testnetV1Eid', '10102'],
    ['testnetV2Eid', '40161'],
    ['sandboxGap', '20101'],
    ['zero', '0'],
    ['unknownLarge', '999999'],
    ['hex', '0x65'],
    ['hexUpper', '0X66'],
    ['trailingText', '101abc'],
    ['leadingSpace', ' 102'],
    ['leadingTabNewline', '\t\n109'],
    ['leadingNbsp', '\u00a0110'],
    ['exponent', '1e2'],
    ['decimal', '101.7'],
    ['negative', '-101'],
    ['negativeZero', '-0'],
    ['plusSign', '+102'],
    ['empty', ''],
    ['letters', 'abc'],
    ['hugeDigits', '123456789012345678901234567890'],
    ['hugeHex', '0x55a7f61f29e432b2b8265d8'],
    ['hugeHexTie', '0x20000000000001800000001'],
    ['number', 101],
    ['numberFloat', 101.9],
    ['numberHuge', 1e21],
    ['numberNegative', -5],
    ['boolean', true],
    ['array', ['102']],
    ['arrayTwo', ['102', '103']],
    ['object', { a: 1 }],
    ['nullValue', null],
    ['missing', undefined],
    ['ownToString', { toString: 1 }],
    ['arrayOfOwnToString', [{ toString: 1 }]],
    ['arrayWithNull', [null, '102']],
]

const nonces: Array<[string, Json | undefined]> = [
    ['numberNonce', 7],
    ['stringNonce', '7'],
    ['stringNonceText', '7abc'],
    ['floatNonce', 7.9],
    ['hexNonce', '0x10'],
    ['negativeNonce', -3],
    ['nanNonce', 'abc'],
    ['bigNonce', '18446744073709551615'],
    ['nullNonce', null],
    ['missingNonce', undefined],
    ['arrayNonce', [8]],
    ['objectNonce', { a: 1 }],
    ['ownToStringNonce', { toString: 1 }],
]

const echoHost = { signRequestV2: async (request: V2Request) => request }
// JSON cannot carry NaN or -0, so both are spelled out.
const portable = (value: number) => (Number.isNaN(value) ? 'NaN' : Object.is(value, -0) ? '-0' : value)

const run = async (lzMessageId: { [key: string]: Json }) => {
    const request = { srcTxHash: '0xtx', lzMessageId, ulnVersion: 'V2', expiration: 1, blockConfirmation: 1, messageHash: '0xm' }
    try {
        const echoed = (await App.prototype.signRequestV1.call(echoHost, request as unknown as V1Request)) as unknown as V2Request
        const { pathwayId, nonce } = echoed.lzMessageId
        return {
            pathwayId: { ...pathwayId, srcEid: portable(pathwayId.srcEid), dstEid: portable(pathwayId.dstEid) },
            nonce: portable(nonce),
        }
    } catch (error) {
        return { error: error instanceof Error ? error.message : String(error) }
    }
}

const main = async () => {
    const out: Record<string, unknown> = {}
    for (const [name, value] of ids) {
        for (const side of ['src', 'dst']) {
            const lzMessageId = withField(`${side}ChainId`, value)
            out[`${side} ${name}`] = { lzMessageId, result: await run(lzMessageId) }
        }
    }
    const extra: Array<[string, { [key: string]: Json }]> = [
        ['both invalid', { ...base, srcChainId: 'abc', dstChainId: null }],
        ['src unknown dst null', { ...base, srcChainId: '20101', dstChainId: null }],
        ['src null dst unknown', { ...base, srcChainId: null, dstChainId: '20101' }],
        ['invalid id before missing nonce', { ...withField('nonce', undefined), srcChainId: 'x' }],
    ]
    for (const [name, value] of nonces) extra.push([name, withField('nonce', value)])
    for (const [name, lzMessageId] of extra) out[name] = { lzMessageId, result: await run(lzMessageId) }
    process.stdout.write('\n@@GOLDEN@@' + JSON.stringify(out, null, 1) + '\n')
}

void main()
