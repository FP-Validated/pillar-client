import { GasolinaApiRequestV2Schema } from '@offchain-monorepo/gasolina-client/src/types'

type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

const base = (): { [key: string]: Json } => ({
    srcTxHash: '0xtx',
    lzMessageId: {
        pathwayId: { srcEid: 30101, dstEid: 30102, sender: '0xs', receiver: '0xr', srcChainName: 'ethereum', dstChainName: 'bsc' },
        nonce: 7,
        ulnSendVersion: 'V302',
    },
    signingContext: { protocolType: 'MESSAGE', expiration: 123, blockConfirmation: 1 },
    messageHash: '0xhash',
})

const set = (value: { [key: string]: Json }, path: string[], next: Json | undefined) => {
    let cursor: { [key: string]: Json } = value
    for (const key of path.slice(0, -1)) cursor = cursor[key] as { [key: string]: Json }
    const last = path[path.length - 1]
    if (next === undefined) delete cursor[last]
    else cursor[last] = next
    return value
}

const cases: Record<string, Json | undefined> = {
    emptyObject: {},
    array: [1],
    string: 'x',
    nullBody: null,
    missingSrcTxHash: set(base(), ['srcTxHash'], undefined),
    numericSrcTxHash: set(base(), ['srcTxHash'], 1),
    nullMessageHash: set(base(), ['messageHash'], null),
    lzMessageIdString: set(base(), ['lzMessageId'], 'x'),
    missingPathway: set(base(), ['lzMessageId', 'pathwayId'], undefined),
    pathwayStrings: set(set(base(), ['lzMessageId', 'pathwayId', 'srcEid'], '30101'), ['lzMessageId', 'pathwayId', 'sender'], 5),
    missingNonceAndVersion: set(set(base(), ['lzMessageId', 'nonce'], undefined), ['lzMessageId', 'ulnSendVersion'], undefined),
    floatNonce: set(base(), ['lzMessageId', 'nonce'], 7.5),
    boolChainName: set(base(), ['lzMessageId', 'pathwayId', 'dstChainName'], true),
    missingSigningContext: set(base(), ['signingContext'], undefined),
    signingContextArray: set(base(), ['signingContext'], [1]),
    badProtocolType: set(base(), ['signingContext', 'protocolType'], 'OTHER'),
    missingProtocolType: set(base(), ['signingContext', 'protocolType'], undefined),
    messageMissingFields: { ...base(), signingContext: { protocolType: 'MESSAGE' } },
    messageWrongTypes: { ...base(), signingContext: { protocolType: 'MESSAGE', expiration: '1', blockConfirmation: null, skipVId: 'no', dvnAddress: 1 } },
    readMissingMarkers: { ...base(), signingContext: { protocolType: 'READ', expiration: 1 } },
    readBadMarker: { ...base(), signingContext: { protocolType: 'READ', expiration: 1, resolvedTimestampTimeMarkers: [{ blockConfirmation: 1, isBlockNumber: true, chainName: 'x', blockNumber: '1' }] } },
    readMarkersObject: { ...base(), signingContext: { protocolType: 'READ', expiration: 1, resolvedTimestampTimeMarkers: {} } },
    everything: { srcTxHash: 1, lzMessageId: { pathwayId: { srcEid: 'a' }, nonce: 'b', ulnSendVersion: 'X' }, signingContext: { protocolType: 'MESSAGE' }, messageHash: false },
    bigVersion: set(base(), ['lzMessageId', 'ulnSendVersion'], 1e21),
    smallFloatVersion: set(base(), ['lzMessageId', 'ulnSendVersion'], 0.000001),
}

const out: Record<string, { body: Json | undefined; error: string | null }> = {}
for (const [name, body] of Object.entries(cases)) {
    const result = GasolinaApiRequestV2Schema.safeParse(body)
    out[name] = {
        body,
        error: result.success ? null : `Invalid request: ${result.error.issues.map((issue) => issue.message).join(', ')}`,
    }
}
process.stdout.write(JSON.stringify(out, null, 1) + '\n')
