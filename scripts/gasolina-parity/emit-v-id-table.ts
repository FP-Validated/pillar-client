// Upstream's own vId for every chain in Pillar's operational roster, so the Rust port
// can be checked against the real table instead of an arithmetic guess.
// Upstream rule: `packages/static-config/src/index.ts:211-243` - the vId is the
// EndpointV1 chain id, except for a fixed non-EVM list which uses V2 eid % 30000.
import * as fs from 'fs'
import * as path from 'path'

import { getVId } from '@monorepo/static-config'

// Produced from `pillar_config::layerzero_available_chain_names`, so both sides are
// asked about exactly the same chains. See scripts/gasolina-parity/README.md.
const roster: Record<string, string[]> = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'roster.json'), 'utf8'),
)

const out: Record<string, Record<string, string>> = {}
const failures: Record<string, Record<string, string>> = {}

for (const [environment, chainNames] of Object.entries(roster)) {
    out[environment] = {}
    failures[environment] = {}
    for (const chainName of chainNames) {
        try {
            out[environment][chainName] = getVId(chainName, environment)
        } catch (error) {
            failures[environment][chainName] = (error as Error).message.slice(
                0,
                120,
            )
        }
    }
}

process.stdout.write(
    JSON.stringify(
        {
            producedBy: {
                upstream: 'gasolina-audit',
                entrypoint: 'packages/static-config/src/index.ts:getVId',
            },
            vIdByChainName: out,
            unresolvable: failures,
        },
        null,
        2,
    ) + '\n',
)
