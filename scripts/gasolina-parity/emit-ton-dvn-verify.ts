// Reproduces the TON DVN verify payload with upstream's own cell encoders, so the
// Rust port's recorded BOCs can stop being recorded-only. Read-only: the two
// address derivations are pure (`contractAddress(workchain, init)` from
// @ton/core), and the DVN implementation address is supplied directly instead of
// being read through a provider, which is the only part of the real path that
// touches the network.
import { Address, Cell, TonClient } from '@ton/ton'

import {
    getUlnConnectionContractFromConstructor,
    getUlnContractFromConstructor,
} from '@monorepo/lz-ton-contracts'
import { buildDvnVerifyCallData } from '@monorepo/lz-ton-contracts/src/dvn'
import { addressToHex, TonProviders } from '@monorepo/common-ton'
import { LZMessageV2 } from '@monorepo/common-model'

// `provider.open` only wraps a contract whose address is already computed from its
// init state, so nothing here reaches a node. TonProviders carries v2/v3 clients
// that this path never calls.
const openOnly = { open: <T>(contract: T): T => contract }
const provider = {
    v2: openOnly as unknown as TonClient,
    v3: openOnly,
} as unknown as TonProviders

const ULN_MANAGER = 'EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH'

interface Vector {
    id: string
    srcEid: number
    dstEid: number
    sender: string
    receiver: string
    guid: string
    nonce: number
    message: string
    blockConfirmation: number
    expiration: number
    dvnImplementation: string
}

const VECTORS: Vector[] = [
    {
        id: 'vec-a',
        srcEid: 30101,
        dstEid: 30343,
        sender: '0x1111111111111111111111111111111111111111',
        receiver:
            '0:2222222222222222222222222222222222222222222222222222222222222222',
        guid: '0x3333333333333333333333333333333333333333333333333333333333333333',
        nonce: 42,
        message: '0xcafebabe',
        blockConfirmation: 15,
        expiration: 1234567890,
        dvnImplementation:
            '0:4444444444444444444444444444444444444444444444444444444444444444',
    },
    {
        id: 'vec-b-empty-message',
        srcEid: 30101,
        dstEid: 30343,
        sender: '0x00000000000000000000000000000000deadbeef',
        receiver:
            '0:2222222222222222222222222222222222222222222222222222222222222222',
        guid: '0x1111111111111111111111111111111111111111111111111111111111111111',
        nonce: 1,
        message: '0x',
        blockConfirmation: 1,
        expiration: 2000000000,
        dvnImplementation:
            '0:4444444444444444444444444444444444444444444444444444444444444444',
    },
    {
        // 200 bytes, so hexToCells has to split across cells on a non
        // byte-aligned 1023-bit boundary - the load-bearing path into packetHash.
        id: 'vec-c-large-multicell-message',
        srcEid: 30101,
        dstEid: 30343,
        sender: '0x1111111111111111111111111111111111111111',
        receiver:
            '0:2222222222222222222222222222222222222222222222222222222222222222',
        guid: '0x5555555555555555555555555555555555555555555555555555555555555555',
        nonce: 7,
        message: '0x' + '0123456789abcdef'.repeat(25),
        blockConfirmation: 20,
        expiration: 1700000000,
        dvnImplementation:
            '0:4444444444444444444444444444444444444444444444444444444444444444',
    },
]

const results = VECTORS.map((vector) => {
    const pathwayId = {
        srcEid: vector.srcEid,
        srcChainName: 'ethereum',
        dstEid: vector.dstEid,
        dstChainName: 'ton',
        sender: vector.sender,
        receiver: vector.receiver,
    }
    const lzMessage = {
        lzMessageId: { pathwayId, nonce: vector.nonce, ulnSendVersion: 'V302' },
        guid: vector.guid,
        message: vector.message,
        options: {},
    } as unknown as LZMessageV2

    const ulnManagerAddress = Address.parse(ULN_MANAGER)
    const uln = getUlnContractFromConstructor(provider, {
        path: pathwayId,
        ulnManagerAddress,
    })
    const ulnConnection = getUlnConnectionContractFromConstructor(provider, {
        path: pathwayId,
        ulnManagerAddress,
    })

    const { ulnCallData, dvnVerifyCallData, packetHash } =
        buildDvnVerifyCallData({
            uln,
            ulnConnection,
            lzMessage,
            blockConfirmation: vector.blockConfirmation,
            expiration: vector.expiration,
            dvnAddressImplementation: Address.parse(vector.dvnImplementation),
        })

    return {
        id: vector.id,
        input: vector,
        ulnManagerAddress: ULN_MANAGER,
        packetHash,
        targetContract: addressToHex(uln.address),
        ulnConnectionAddress: addressToHex(ulnConnection.address),
        ulnCallDataBoc: ulnCallData.toBoc().toString('hex'),
        dvnCallDataBoc: dvnVerifyCallData.toBoc().toString('hex'),
        hashCallData: dvnVerifyCallData.hash().toString('hex'),
    }
})


// The codec primitives in `cell.rs` are locked against one further BOC that is not
// one of the vectors above. Parsing it with @ton/core and reporting both the
// representation hash and the re-serialized bytes turns that lock into an
// upstream-checked claim too.
const CODEC_LOCK_BOC =
    'b5ee9c72410204010001570001ef65786563506172616d73815ee4ffc625ed4a7b82befffffffffffffffffffffffffffffffffffffffffffffccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc00000001c4fecc02652abd38461e7f7e3139969b96902727f10fbc612990b3ad243f4a6c8e3e6724f9a7973e010197000000004d644164647293ff2057bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0ac9e984a38af418a0481fd5fe59f44be3e53ad657c9d296f40be4fddaec930202016700556c6e566572696679615ee4ffcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000001e0300a700000000417474657374815ed897bfffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8561f69eed245ee440b8e885dc3d2c3cf862d6dd7edec8ec57fa2a6e9ae0db4000000000000001021da1ae04'

const codecLockCell = Cell.fromBoc(Buffer.from(CODEC_LOCK_BOC, 'hex'))[0]
const codecLock = {
    boc: CODEC_LOCK_BOC,
    reserializedBoc: codecLockCell.toBoc().toString('hex'),
    reprHash: codecLockCell.hash().toString('hex'),
}

process.stdout.write(
    JSON.stringify(
        {
            producedBy: {
                upstream: 'gasolina-audit',
                entrypoints: [
                    'packages/contracts/lz-ton-contracts/src/dvn.ts:buildDvnVerifyCallData',
                    'packages/contracts/lz-ton-contracts/src/uln.ts:buildULNCallData',
                    'packages/contracts/lz-ton-contracts/src/index.ts:getUlnContractFromConstructor',
                    'packages/contracts/lz-ton-contracts/src/index.ts:getUlnConnectionContractFromConstructor',
                ],
            },
            vectors: results,
            codecLock,
        },
        null,
        2,
    ) + '\n',
)
