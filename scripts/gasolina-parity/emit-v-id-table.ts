// Upstream's own vId for every chain in Pillar's available union, so the Rust port can
// be checked against the real table instead of an arithmetic guess.
// Upstream rule at gasolina-audit 1.2.66 (`packages/static-config/src/index.ts:191-195`,
// called from `apps/gasolina/src/app/hashCallDataBuilder/utils.ts`): the vId is the
// EndpointV2 id modulo 30000 for every chain.
import * as fs from 'fs'
import * as path from 'path'

import { getVId } from '@offchain-monorepo/static-config'

// The roster is `pillar_config::layerzero_available_chain_names` for each environment,
// written as `{ "<environment>": ["<chain>", ...] }` to `PILLAR_V_ID_ROSTER`. Without it
// the committed fixture's own chain names are re-asked, so a plain checkout still runs.
// The Rust side asserts the table exhaustively in both directions, so a chain upstream
// cannot resolve fails there rather than silently disappearing here.
const FIXTURE =
    process.env.PILLAR_V_ID_FIXTURE ??
    path.join(
        __dirname,
        '../../crates/pillar-runtime/tests/gasolina_parity/v_id_by_chain_name.json',
    )
const roster: Record<string, string[]> = process.env.PILLAR_V_ID_ROSTER
    ? JSON.parse(fs.readFileSync(process.env.PILLAR_V_ID_ROSTER, 'utf8'))
    : Object.fromEntries(
          Object.entries(
              (
                  JSON.parse(fs.readFileSync(FIXTURE, 'utf8')) as {
                      vIdByChainName: Record<string, Record<string, string>>
                  }
              ).vIdByChainName,
          ).map(([environment, byChainName]) => [environment, Object.keys(byChainName)]),
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
            failures[environment][chainName] = (error as Error).message.slice(0, 120)
        }
    }
}

process.stdout.write(
    JSON.stringify(
        {
            producedBy: {
                upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                entrypoint: 'packages/static-config/src/index.ts:getVId',
            },
            vIdByChainName: out,
            unresolvable: failures,
        },
        null,
        2,
    ) + '\n',
)
