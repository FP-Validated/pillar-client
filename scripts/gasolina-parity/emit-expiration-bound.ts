// Measures upstream 1.2.66's expiration window with the bootstrap's own bounds
// (`bootstrap.ts:40-41,95-96`): `App.validateExpiration` over a destination clock fixed
// at NOW, for expirations around both edges and a far-future value.
import { App } from '../src/app/app'

const NOW = 1_800_000_000
const WEEK = 60 * 60 * 24 * 7

const main = async () => {
    const seen: unknown[] = []
    const app = new App({
        rpcSdkFactory: {
            getSdk: () => ({
                getBlockTimestamp: async (blockTag: unknown, opts: unknown) => {
                    seen.push({ blockTag, opts })
                    return NOW
                },
            }),
        },
        maximumExpiration: WEEK,
        maximumExpirationGracePeriod: 30,
    } as any)
    const cases = [NOW - 31, NOW - 30, NOW, NOW + WEEK, NOW + WEEK + 1, 1_900_000_000]
    const results = []
    for (const expiration of cases) {
        try {
            await (app as any).validateExpiration('ethereum', expiration)
            results.push({ expiration, outcome: 'accepted' })
        } catch (error) {
            results.push({
                expiration,
                outcome: 'refused',
                class: (error as Error).constructor.name,
                message: (error as Error).message,
            })
        }
    }
    process.stdout.write(
        JSON.stringify(
            {
                producedBy: {
                    upstream: 'gasolina-audit 1.2.66 (manifest sha256 8ad87eb6...; archive comment 213cd500...)',
                    entrypoint: 'apps/gasolina/src/app/app.ts:App.validateExpiration',
                },
                now: NOW,
                maximumExpiration: WEEK,
                maximumExpirationGracePeriod: 30,
                results,
                timestampReads: seen,
            },
            null,
            1,
        ) + '\n',
    )
}

main().then(
    () => process.exit(0),
    (error) => {
        console.error(error)
        process.exit(1)
    },
)
