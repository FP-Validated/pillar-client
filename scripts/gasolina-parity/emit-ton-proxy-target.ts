// Emits the DVN implementation address upstream resolves from a TON proxy storage
// cell, so the Rust port's decoder can be compared against it rather than only
// against itself.
//
// Read-only: no RPC, no signer, no network. `getImplementationContract` is two
// parts - a quorum-backed fetch of the storage cell, and a pure decode of it
// (`lz-ton-contracts/src/index.ts:634-666`). The fetch is stubbed with a recorded
// cell; what is compared is the decode, because that is the part whose output is
// signed as the DVN `ExecuteParams.target`.

import { Cell } from '@ton/core'

import { getCellName } from '@monorepo/common-ton'
import { lzDecodeClass } from '@monorepo/lz-ton-contracts/src/classes'
import { tonObjects } from '@layerzerolabs/lz-ton-sdk-v2'

// The cells the Rust tests decode, verbatim.
const CASES: { id: string; storageBoc: string; note: string }[] = [
    {
        id: 'proxy-admin-target',
        storageBoc:
            'te6cckEBAwEAwAABVwAAAHBmUHJveHmT/wBXv//////////////////////////////////////9AQHXd3JrQ29yU3RvcpP/IFe4Je////////////////////////////////////6qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAgBARERERERERERERERERERERERERERERERERERERERERET8w675',
        note: 'a Proxy cell: the admin is the implementation the DVN call targets',
    },
    {
        id: 'not-a-proxy',
        storageBoc: 'te6cckECAwEAAQIAAqcAAAAAUGFja2V0k/8k/9YV7gZ7/////////////////////////////////AAAAAAAACC+wF+gw+I94oCV5eVzBiOtBeGC+YH6RkkAD9WyGdOQI/oBAgDnAAAAAAAAcGF0aFFe4F+1J+4Ke/////////////////////////////////wAAdZUAAAAAAAAAAAAAAAAfdIx23kaOnRG9NA+p1cut8xXfsAAAdocd31gAUhdO0d0NZsNb/cGl/Maa9PSuNhVLE9z8bBSjX4AZAADAAAAAAAAAAAAAAAAAAAAAAAAABZUK6RjAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVPDPWw==',
        note: 'a live mainnet TON packet cell: upstream raises NotProxyError and falls back to the DVN address',
    },
]

const resolve = (storageBoc: string) => {
    const cell = Cell.fromBoc(Buffer.from(storageBoc, 'base64'))[0]
    const name = getCellName(cell)
    if (name !== tonObjects.Proxy.name) {
        // getImplementationContract turns this into NotProxyError and falls back to
        // the original address (index.ts:645-666).
        return { cellName: name, isProxy: false, target: null }
    }
    const decoded = lzDecodeClass('Proxy', cell) as any
    const admin = decoded.workerCoreStorage.admins[0]
    return {
        cellName: name,
        isProxy: true,
        target: admin.toRawString ? admin.toRawString() : String(admin),
    }
}

const main = () => {
    const cases = CASES.map((entry) => {
        try {
            return { ...entry, ...resolve(entry.storageBoc) }
        } catch (error) {
            return { ...entry, error: (error as Error).message.slice(0, 300) }
        }
    })
    process.stdout.write(
        JSON.stringify(
            {
                producedBy: {
                    upstream: 'gasolina-audit',
                    entrypoints: [
                        'packages/contracts/lz-ton-contracts/src/index.ts:getCellName',
                        'packages/contracts/lz-ton-contracts/src/index.ts:lzDecodeClass',
                        'packages/contracts/lz-ton-contracts/src/index.ts:getImplementationContract (decode half)',
                    ],
                    notCovered:
                        'the quorum fetch around the decode (fetchQuorumedStorageCell); the cell is supplied',
                },
                cases,
            },
            null,
            2,
        ) + '\n',
    )
}

main()
