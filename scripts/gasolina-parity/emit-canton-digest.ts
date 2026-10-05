const { PacketSerializer, PacketV1Codec } = require('@layerzerolabs/lz-v2-utilities')
const { STATIC_VE3_CONTRACT_ADDRESSES } = require('@layerzerolabs/ver-address')
const { hashVerify } = require('/tmp/gasolina-run/work/migrated/offchain-monorepo/apps/gasolina/src/app/sdks/gasolinaSdk/canton/hashes.ts')
const { computeCantonFingerprint, computeDecentralizedNamespace } = require('/tmp/gasolina-run/work/packages/vms/canton/common/src/client/utils.ts')

const asBytes32 = (value) => value.length === 66 ? value : '0x' + value.replace(/^0x/, '').padStart(64, '0')
const vectors = [
    { id: 'normal', message: '0xcafebabe', nonce: 42, guid: '0x' + '33'.repeat(32), sender: '0x' + '11'.repeat(32), receiver: '0x' + '22'.repeat(32), confirmations: 15, vid: 7, expiration: 1_234_567_890 },
    { id: 'empty-message', message: '0x', nonce: 1, guid: '0x' + '11'.repeat(32), sender: '0x' + 'de'.repeat(32), receiver: '0x' + '22'.repeat(32), confirmations: 1, vid: 3, expiration: 2_000_000_000 },
    { id: 'long-message', message: '0x' + 'a5'.repeat(4096), nonce: 9_876_543_210, guid: '0x' + 'ab'.repeat(32), sender: '0x' + '12'.repeat(32), receiver: '0x' + '44'.repeat(32), confirmations: 65_535, vid: 255, expiration: 4_000_000_000 },
]

const target = asBytes32(STATIC_VE3_CONTRACT_ADDRESSES.uln302)
const dvn = asBytes32('0x' + '11'.repeat(32))
const signerPublicKey = Buffer.from('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 'hex')
const keyFingerprint = computeCantonFingerprint(signerPublicKey)
const partyNamespace = computeDecentralizedNamespace([keyFingerprint])
const result = vectors.map((v) => {
    const packet = PacketSerializer.serialize({
        guid: v.guid,
        message: v.message,
        payload: v.message,
        version: 1,
        nonce: String(v.nonce),
        srcEid: 30_101,
        dstEid: 30_343,
        sender: asBytes32(v.sender),
        receiver: asBytes32(v.receiver),
    })
    const codec = PacketV1Codec.fromBytes(Buffer.from(packet.slice(2), 'hex'))
    const packetHeader = codec.header()
    const payloadHash = codec.payloadHash()
    const hashCallData = hashVerify({
        dvn,
        packetHeader: Buffer.from(packetHeader.slice(2), 'hex'),
        payloadHash,
        confirmations: BigInt(v.confirmations),
        target,
        vid: BigInt(v.vid),
        expiration: BigInt(v.expiration),
    })
    return { id: v.id, input: v, target, dvn, packetHeader, payloadHash, hashCallData, signerPublicKey: '0x' + signerPublicKey.toString('hex'), keyFingerprint, partyNamespace }
})

process.stdout.write(JSON.stringify({
    provenance: {
        upstream: 'Gasolina 1.2.66 source snapshot',
        entrypoints: [
            'apps/gasolina/src/app/sdks/gasolinaSdk/canton/hashes.ts:hashVerify',
            'packages/sdks/lz-v2-utilities: PacketSerializer/PacketV1Codec',
            'packages/contracts/lz-canton-sdk/src/contractGetters.ts:getUln302ContractAddress maps Uln302 to STATIC_VE3_CONTRACT_ADDRESSES.uln302',
            'packages/vms/canton/common/src/client/utils.ts:computeCantonFingerprint and computeDecentralizedNamespace',
            'packages/vms/canton/common/src/crypto.ts:SECP256K1_SPKI_DER_HEADER',
        ],
        signerInput: 'synthetic uncompressed secp256k1 generator public key; upstream Canton key fingerprint (not the Gasolina signer address) and party namespace functions executed',
        network: 'offline; no provider or signer invocation',
    },
    vectors: result,
}, null, 2) + '\n')