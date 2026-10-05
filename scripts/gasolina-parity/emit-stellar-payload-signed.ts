// The Soroban calls upstream 1.2.66's Stellar `hasPayloadSigned` path makes, encoded by the
// same `@stellar/stellar-sdk` 16.0.1 upstream uses, and the return values it would decode.
//
// Upstream's Stellar endpoint/ULN SDKs cannot load offline: they import
// `@layerzerolabs/lz-v2-stellar-sdk`, whose `src/generated/*.js` contract bindings the
// snapshot does not carry. So the calls are built here from the contract signatures in
// `contracts/protocol/stellar/contracts` (CODE), with the argument encodings the generated
// client applies to those types (Address -> scvAddress, u32 -> scvU32, Bytes/BytesN<32> ->
// scvBytes), and every return value is passed through `scValToNative`, which is what the
// upstream code reads.
import { Address, Contract, StrKey, scValToNative, xdr } from '@stellar/stellar-sdk'

const { keccak_256 } = require('@noble/hashes/sha3')

const contracts = {
    endpoint: 'CCQLLRE5JBAWYCW3KTWOIWLMFDUOKROQVZNSALQMGOSXNW3ERUOWTZGK',
    uln: 'CCV4HEII3UC65THWGSRM2DVIJLB6HS6YMUHDTTHUECX2RHTP5FA2GOBA',
    views: 'CBCH6XLCAVY2KPWGJYDY4ATDHMJCNLISINKB5JAOHPAAXZXLTBMU43ZB',
}
const hex = (byte: string) => Buffer.from(byte.repeat(32), 'hex')
const receiver = hex('11')
const dvn = hex('22')
const otherLibrary = hex('33')
const sender = hex('aa')
const guid = hex('66')
const message = Buffer.from('deadbeef', 'hex')
const srcEid = 30101
const dstEid = 30600
const nonce = 7n
// PacketV1 header: version | nonce | srcEid | sender | dstEid | receiver.
const packetHeader = Buffer.concat([
    Buffer.from([1]),
    Buffer.from(nonce.toString(16).padStart(16, '0'), 'hex'),
    Buffer.from(srcEid.toString(16).padStart(8, '0'), 'hex'),
    sender,
    Buffer.from(dstEid.toString(16).padStart(8, '0'), 'hex'),
    receiver,
])
const payloadHash = Buffer.from(keccak_256(Buffer.concat([guid, message])) as Uint8Array)
const headerHash = Buffer.from(keccak_256(packetHeader) as Uint8Array)

const address = (bytes: Buffer) => new Address(StrKey.encodeContract(bytes)).toScVal()
const u32 = (value: number) => xdr.ScVal.scvU32(value)
const symbol = (name: string) => xdr.ScVal.scvSymbol(name)
const call = (contract: string, fn: string, args: xdr.ScVal[]) =>
    new Contract(contract)
        .call(fn, ...args)
        .body()
        .invokeHostFunctionOp()
        .hostFunction()
        .invokeContract()
        .toXDR('base64')
const struct = (fields: [string, xdr.ScVal][]) =>
    xdr.ScVal.scvMap(
        fields
            .sort(([a], [b]) => (a < b ? -1 : 1))
            .map(([key, val]) => new xdr.ScMapEntry({ key: symbol(key), val })),
    )
const value = (scVal: xdr.ScVal) => ({
    xdr: scVal.toXDR('base64'),
    native: JSON.parse(
        JSON.stringify(scValToNative(scVal), (_, v) => (typeof v === 'bigint' ? v.toString() : v)),
    ),
})
const ulnConfig = (confirmations: bigint) =>
    struct([
        ['confirmations', xdr.ScVal.scvU64(new xdr.Uint64(confirmations))],
        ['optional_dvn_threshold', u32(0)],
        ['optional_dvns', xdr.ScVal.scvVec([])],
        ['required_dvns', xdr.ScVal.scvVec([address(dvn)])],
    ])

const out = {
    producedBy: {
        upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
        encoder: '@stellar/stellar-sdk 16.0.1 (the version in the 1.2.66 lockfile)',
        notExecuted:
            'upstream EndpointV2StellarSdk/UlnStellarSdk need src/generated/*.js bindings absent from the snapshot',
    },
    inputs: {
        contracts,
        receiver: '0x' + receiver.toString('hex'),
        sender: '0x' + sender.toString('hex'),
        dvn: '0x' + dvn.toString('hex'),
        srcEid,
        dstEid,
        nonce: Number(nonce),
        guid: '0x' + guid.toString('hex'),
        message: '0x' + message.toString('hex'),
        packetHeader: '0x' + packetHeader.toString('hex'),
        payloadHash: '0x' + payloadHash.toString('hex'),
    },
    calls: {
        get_receive_library: call(contracts.endpoint, 'get_receive_library', [address(receiver), u32(srcEid)]),
        is_valid_receive_library: call(contracts.endpoint, 'is_valid_receive_library', [
            address(receiver),
            u32(srcEid),
            address(otherLibrary),
        ]),
        effective_receive_uln_config: call(contracts.uln, 'effective_receive_uln_config', [
            address(receiver),
            u32(srcEid),
        ]),
        confirmations: call(contracts.uln, 'confirmations', [
            address(dvn),
            xdr.ScVal.scvBytes(headerHash),
            xdr.ScVal.scvBytes(payloadHash),
        ]),
        uln_verifiable: call(contracts.views, 'uln_verifiable', [
            xdr.ScVal.scvBytes(packetHeader),
            xdr.ScVal.scvBytes(payloadHash),
        ]),
    },
    returns: {
        defaultLibrary: value(struct([['is_default', xdr.ScVal.scvBool(true)], ['lib', address(hex('55'))]])),
        overrideLibrary: value(struct([['is_default', xdr.ScVal.scvBool(false)], ['lib', address(otherLibrary)]])),
        valid: value(xdr.ScVal.scvBool(true)),
        invalid: value(xdr.ScVal.scvBool(false)),
        config15: value(ulnConfig(15n)),
        noConfirmations: value(xdr.ScVal.scvVoid()),
        confirmations14: value(xdr.ScVal.scvU64(new xdr.Uint64(14n))),
        confirmations15: value(xdr.ScVal.scvU64(new xdr.Uint64(15n))),
        verifying: value(xdr.ScVal.scvVec([symbol('Verifying')])),
        verified: value(xdr.ScVal.scvVec([symbol('Verified')])),
    },
    overrideLibraryStrkey: StrKey.encodeContract(otherLibrary),
}
process.stdout.write(JSON.stringify(out, null, 1) + '\n')
