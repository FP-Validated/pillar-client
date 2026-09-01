// Upstream's own vId for every chain in Pillar's operational roster, so the Rust port
// can be checked against the real table instead of an arithmetic guess.
// Upstream rule: `packages/static-config/src/index.ts:211-243` - the vId is the
// EndpointV1 chain id, except for a fixed non-EVM list which uses V2 eid % 30000.
import * as fs from 'fs'
import * as path from 'path'

import { getVId } from '@monorepo/static-config'

// The roster is read back from the committed fixture this emitter regenerates, so
// both sides are asked about exactly the same chains and the script runs from a
// plain checkout. It previously read a `roster.json` beside itself that was never
// committed, which made this emitter unrunnable from the published tree.
//
// The chain set itself originates in `pillar_config::layerzero_available_chain_names`;
// to widen it, add the chains to the fixture's `vIdByChainName` and rerun - the
// Rust side asserts the table exhaustively in both directions, so a chain that
// upstream cannot resolve fails there rather than silently disappearing here.
// This script is run after being copied into the upstream pnpm workspace, so the
// in-tree relative path is only the default: set `PILLAR_V_ID_FIXTURE` to the
// absolute path when running from anywhere else.
const FIXTURE =
    process.env.PILLAR_V_ID_FIXTURE ??
    path.join(
        __dirname,
        '../../crates/pillar-runtime/tests/gasolina_parity/v_id_by_chain_name.json',
    )
const fixture: { vIdByChainName: Record<string, Record<string, string>> } =
    JSON.parse(fs.readFileSync(FIXTURE, 'utf8'))
const roster: Record<string, string[]> = Object.fromEntries(
    Object.entries(fixture.vIdByChainName).map(([environment, byChainName]) => [
        environment,
        Object.keys(byChainName),
    ]),
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
