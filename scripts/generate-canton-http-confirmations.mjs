// Writes the synthetic Canton sequencer transcript used by `round2_canton_http_e2e.rs`.
// It is derived from upstream's `canton_sequencer.json`, but it is not upstream output.
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const sourceFixturePath = resolve(root, 'crates/pillar-runtime/tests/gasolina_parity/canton_sequencer.json')
const outputPath = resolve(root, 'crates/pillar-runtime/tests/synthetic/canton_http_confirmations.json')
const timestamp = '1700000000000'
const stateRoot = `0x${'5e'.repeat(32)}`
const endpoint = '0xc35194c1ae9936954bea5931c720168c376ede8af156fcc37993a2fbfdc647ac'
const sourceHash = '1220' + 'bb'.repeat(32)
const authorization = { authorization: 'Bearer parity' }
const keySeeds = ['ve3-committee-1', 've3-committee-2']
const p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const mask = (1n << 64n) - 1n
const roundConstants = [
    0x1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn,
    0x80000001n, 0x8000000080008081n, 0x8000000000008009n, 0x8an, 0x88n,
    0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn, 0x8000000000008089n,
    0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x800an,
    0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n,
    0x8000000080008008n,
]
const rotations = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]
const generator = {
    x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
}

function keccak256(input) {
    const bytes = Buffer.from(input)
    const rate = 136
    const padded = Buffer.alloc(Math.ceil((bytes.length + 1) / rate) * rate)
    bytes.copy(padded)
    padded[bytes.length] = 1
    padded[padded.length - 1] |= 0x80
    const state = Array(25).fill(0n)
    for (let offset = 0; offset < padded.length; offset += rate) {
        for (let index = 0; index < rate; index++) {
            state[Math.floor(index / 8)] ^= BigInt(padded[offset + index]) << BigInt((index % 8) * 8)
        }
        for (const rc of roundConstants) {
            const column = Array(5)
            for (let x = 0; x < 5; x++) column[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            const delta = Array.from({ length: 5 }, (_, x) => column[(x + 4) % 5] ^ (((column[(x + 1) % 5] << 1n) | (column[(x + 1) % 5] >> 63n)) & mask))
            for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) state[x + 5 * y] ^= delta[x]
            const rotated = Array(25).fill(0n)
            for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) {
                const index = x + 5 * y
                const shift = rotations[index]
                const value = state[index]
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = shift === 0 ? value : ((value << BigInt(shift)) | (value >> BigInt(64 - shift))) & mask
            }
            for (let y = 0; y < 5; y++) for (let x = 0; x < 5; x++) state[x + 5 * y] = rotated[x + 5 * y] ^ ((~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y])
            state[0] ^= rc
        }
    }
    return Buffer.from(Array.from({ length: 32 }, (_, index) => Number((state[Math.floor(index / 8)] >> BigInt((index % 8) * 8)) & 0xffn)))
}

function mod(value, modulus) {
    const result = value % modulus
    return result < 0n ? result + modulus : result
}

function inverse(value, modulus) {
    let [oldT, t, oldR, r] = [0n, 1n, modulus, mod(value, modulus)]
    while (r !== 0n) {
        const quotient = oldR / r
        ;[oldT, t] = [t, oldT - quotient * t]
        ;[oldR, r] = [r, oldR - quotient * r]
    }
    if (oldR !== 1n) throw new Error('non-invertible scalar')
    return mod(oldT, modulus)
}

function pointAdd(left, right) {
    if (!left) return right
    if (!right) return left
    if (left.x === right.x && mod(left.y + right.y, p) === 0n) return null
    const slope = left.x === right.x
        ? mod(3n * left.x * left.x * inverse(2n * left.y, p), p)
        : mod((right.y - left.y) * inverse(right.x - left.x, p), p)
    const x = mod(slope * slope - left.x - right.x, p)
    return { x, y: mod(slope * (left.x - x) - left.y, p) }
}

function pointMultiply(scalar, point = generator) {
    let result = null
    while (scalar > 0n) {
        if (scalar & 1n) result = pointAdd(result, point)
        point = pointAdd(point, point)
        scalar >>= 1n
    }
    return result
}

function integer(bytes) {
    return BigInt(`0x${Buffer.from(bytes).toString('hex')}`)
}

function keyFor(seed) {
    return integer(keccak256(Buffer.from(seed, 'utf8')))
}

function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
    if (value && typeof value === 'object') {
        return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
    }
    return JSON.stringify(value)
}

function deterministicNonce(secret, digest) {
    const hmac = (key, data) => createHmac('sha256', key).update(data).digest()
    const privateBytes = Buffer.from(secret.toString(16).padStart(64, '0'), 'hex')
    let value = Buffer.alloc(32, 1)
    let key = Buffer.alloc(32, 0)
    key = hmac(key, Buffer.concat([value, Buffer.from([0]), privateBytes, digest]))
    value = hmac(key, value)
    key = hmac(key, Buffer.concat([value, Buffer.from([1]), privateBytes, digest]))
    value = hmac(key, value)
    for (;;) {
        value = hmac(key, value)
        const candidate = integer(value)
        if (candidate > 0n && candidate < n) return candidate
        key = hmac(key, Buffer.concat([value, Buffer.from([0])]))
        value = hmac(key, value)
    }
}

function signScan(request, response, secret) {
    const digest = keccak256(Buffer.from(canonicalJson({ type: 'scan', request, response }), 'utf8'))
    const nonce = deterministicNonce(secret, digest)
    const point = pointMultiply(nonce)
    const r = point.x % n
    let s = mod(inverse(nonce, n) * (integer(digest) + r * secret), n)
    let recovery = Number(point.y & 1n) | (point.x >= n ? 2 : 0)
    if (s > n / 2n) {
        s = n - s
        recovery ^= 1
    }
    const signature = `0x${r.toString(16).padStart(64, '0')}${s.toString(16).padStart(64, '0')}${recovery.toString(16).padStart(2, '0')}`
    return { digest: digest.toString('hex'), signature }
}

const sourceFixture = JSON.parse(await readFile(sourceFixturePath, 'utf8'))
const oneMatch = sourceFixture.scenarios.find(scenario => scenario.name === 'one match')
const sourceExchange = oneMatch.exchanges[0]
const sourceResponse = JSON.parse(sourceExchange.text)
const { signatures: authenticSignatures, ...authenticAnswer } = sourceResponse
const sourceEvent = structuredClone(authenticAnswer.events[0])
sourceEvent.requestTimestamp = timestamp
const rangeUrl = new URL('https://sequencer.example:8443/scan')
rangeUrl.searchParams.set('type', 'events')
rangeUrl.searchParams.set('emitter', endpoint)
rangeUrl.searchParams.set('from', '900')
rangeUrl.searchParams.set('to', '901')
const requestUrl = new URL('https://sequencer.example:8443/scan')
requestUrl.searchParams.set('type', 'requests')
requestUrl.searchParams.set('id', 'req-900')
const requestTemplateExchange = sourceFixture.scenarios.find(scenario => scenario.name === 'second emitter').exchanges.find(exchange => exchange.url.includes('/scan?type=requests&id=req-77'))
assert.ok(requestTemplateExchange, 'authentic Canton request-record shape is available')
const requestRecord = structuredClone(JSON.parse(requestTemplateExchange.text).requests[0])
requestRecord.id = 'req-900'
requestRecord.nonce = '900'
requestRecord.timestamp = timestamp
const sourceAnswer = { ...authenticAnswer, events: [sourceEvent] }
const responses = [
    sourceAnswer,
    { events: [sourceEvent], latestNonce: '900', isLatest: true, stateRoot },
    { requests: [requestRecord], stateRoot },
]
const urls = [sourceExchange.url, rangeUrl.toString(), requestUrl.toString()]
const requests = urls.map(url => Object.fromEntries(new URL(url).searchParams.entries()))
const keys = keySeeds.map(keyFor)
for (let index = 0; index < 2; index++) {
    const result = signScan(requests[0], authenticAnswer, keys[index])
    assert.equal(result.signature, authenticSignatures[index], `canonical-signature parity for committee key ${index + 1}`)
}
const exchanges = urls.map((url, index) => ({
    method: 'GET',
    url,
    headers: authorization,
    body: null,
    status: 200,
    response: {
        ...responses[index],
        signatures: keys.map(key => signScan(requests[index], responses[index], key).signature),
    },
}))
const fixture = {
    source: 'Synthetic clock-adjusted transcript derived from canton_sequencer.json one-match; all three responses use the original event with requestTimestamp and request-record timestamp fixed to 1700000000000 ms. Signatures use serializeJson({type,request,response}), secp.sign, and privateKeySeeds ve3-committee-1 and ve3-committee-2 from scripts/gasolina-parity/emit-ve3-sequencer.ts.',
    exchanges,
}
await writeFile(outputPath, `${JSON.stringify(fixture, null, 2)}\n`)
console.log(JSON.stringify({ outputPath, seeds: keySeeds, digests: exchanges.map(exchange => exchange.response.signatures.length ? signScan(requests[urls.indexOf(exchange.url)], responses[urls.indexOf(exchange.url)], keys[0]).digest : null) }, null, 2))
