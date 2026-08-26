import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { createHash } from 'node:crypto'

const repoRoot = process.cwd()
const defaultSourceRoot = path.resolve(repoRoot, '../pillar-audit')
const explicitSourceRoot = process.env.PILLAR_AUDIT_ROOT

function isDirectory(candidatePath) {
    return fs.existsSync(candidatePath) && fs.statSync(candidatePath).isDirectory()
}

function fail(message) {
    console.error(`generate-layerzero-static-config: ${message}`)
    process.exit(1)
}

function resolveSourceRoot() {
    if (explicitSourceRoot) {
        const resolved = path.resolve(explicitSourceRoot)
        if (!isDirectory(resolved)) {
            fail(`PILLAR_AUDIT_ROOT does not exist or is not a directory: ${resolved}`)
        }
        return { root: resolved, mode: 'PILLAR_AUDIT_ROOT' }
    }

    if (!isDirectory(defaultSourceRoot)) {
        fail(`no source root found; set PILLAR_AUDIT_ROOT or provide ../pillar-audit: ${defaultSourceRoot}`)
    }
    return { root: defaultSourceRoot, mode: 'auto-detected' }
}

const sourceRootInfo = resolveSourceRoot()
const sourceRoot = sourceRootInfo.root
const lzDefinitionsRoot =
    process.env.LZ_DEFINITIONS_ROOT ??
    path.join(
        sourceRoot,
        'node_modules/.pnpm/@layerzerolabs+lz-definitions@3.1.2/node_modules/@layerzerolabs/lz-definitions',
    )
const outPath = path.join(repoRoot, 'crates/pillar-config/src/generated_layerzero_evm.rs')
const environments = ['mainnet', 'testnet', 'sandbox']
const contractNames = [
    // `Endpoint` is the V1 endpoint. It is needed because a V2 message can be
    // addressed to a V1 endpoint, and the receive library for those pathways is
    // read from it (TS: `endpoint/evm/endpointV1.ts:86-110`).
    'Endpoint', 'EndpointV2', 'EndpointV2View', 'ReadLib1002', 'ReadLib1002View',
    'ReceiveUln301', 'ReceiveUln301View', 'ReceiveUln302', 'ReceiveUln302View',
    'SendUln301', 'SendUln302', 'UltraLightNodeV2',
]
if (!isDirectory(lzDefinitionsRoot)) {
    fail(`lz-definitions root does not exist or is not a directory: ${lzDefinitionsRoot}`)
}
const require = createRequire(import.meta.url)
const lzDefinitions = require(lzDefinitionsRoot)

function deploymentConfigPath(environment) {
    return path.join(
        sourceRoot,
        `packages/static-config/src/deploymentConfig/${environment}/deploymentConfig.ts`,
    )
}

function sha256File(filePath) {
    return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex')
}
function readJsonFile(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'))
}


function lzDefinitionsProvenance(root) {
    const packageJsonPath = path.join(root, 'package.json')
    if (!fs.existsSync(packageJsonPath)) {
        fail(`lz-definitions package.json does not exist: ${packageJsonPath}`)
    }
    const packageJson = readJsonFile(packageJsonPath)
    return {
        version: typeof packageJson.version === 'string' ? packageJson.version : 'unavailable',
    }
}

function loadDeploymentConfig(environment) {
    const raw = fs.readFileSync(deploymentConfigPath(environment), 'utf8')
    const objectText = raw
        .replace(
            /^export const \w+: Record<string, Record<string, string>> = /,
            '',
        )
        .trim()
        .replace(/;$/, '')
    return Function(`return (${objectText})`)()
}

const deploymentConfigInputs = environments.map((environment) => {
    const filePath = deploymentConfigPath(environment)
    return {
        environment,
        path: filePath,
        sha256: sha256File(filePath),
    }
})

const entries = []
for (const environment of environments) {
    const deploymentConfig = loadDeploymentConfig(environment)
    for (const chainName of Object.keys(deploymentConfig).sort()) {
        const contracts = deploymentConfig[chainName]
        for (const contractName of contractNames) {
            const address = contracts[contractName]
            if (address) {
                entries.push([environment, chainName, contractName, address])
            }
        }
    }
}

const endpointEntries = []
const endpointStages = [lzDefinitions.Stage.MAINNET, lzDefinitions.Stage.TESTNET, lzDefinitions.Stage.SANDBOX]
const endpointVersions = [lzDefinitions.EndpointVersion.V1, lzDefinitions.EndpointVersion.V2]
for (const chainName of Object.values(lzDefinitions.EvmChain).sort()) {
    for (const stage of endpointStages) {
        for (const version of endpointVersions) {
            try {
                const endpointId = lzDefinitions.chainAndStageToEndpointId(
                    chainName,
                    stage,
                    version,
                )
                endpointEntries.push([stage, chainName, version.toUpperCase(), Number(endpointId)])
            } catch (error) {
                if (error instanceof Error) {
                    continue
                }
                throw error
            }
        }
    }
}

const provenance = {
    deploymentConfigInputs,
    lzDefinitions: lzDefinitionsProvenance(lzDefinitionsRoot),
    counts: {
        endpointEntries: endpointEntries.length,
        deploymentEntries: entries.length,
    },
}

const lines = [
    '// @generated by scripts/generate-layerzero-static-config.mjs',
    '// Provenance:',
    '// Upstream package: @layerzerolabs/lz-definitions',
    `// Upstream package version: ${provenance.lzDefinitions.version}`,
    '// Deployment config hashes:',
    ...provenance.deploymentConfigInputs.map(
        (input) => `// - ${input.environment} sha256:${input.sha256}`,
    ),
    `// Endpoint entries: ${provenance.counts.endpointEntries}`,
    `// Deployment entries: ${provenance.counts.deploymentEntries}`,
    '// Sources: upstream LayerZero deployment configuration and @layerzerolabs/lz-definitions.',
    '',
    'pub(crate) const LZ_EVM_ENDPOINT_IDS: &[(&str, &str, &str, u32)] = &[',
]

for (const [environment, chainName, endpointVersion, endpointId] of endpointEntries) {
    lines.push(
        `    ("${environment}", "${chainName}", "${endpointVersion}", ${endpointId}),`,
    )
}

lines.push(
    '];',
    '',
    'pub(crate) const LZ_EVM_DEPLOYMENT_ADDRESSES: &[(&str, &str, &str, &str)] = &[',
)

for (const [environment, chainName, contractName, address] of entries) {
    lines.push('    (')
    lines.push(`        "${environment}",`)
    lines.push(`        "${chainName}",`)
    lines.push(`        "${contractName}",`)
    lines.push(`        "${address}",`)
    lines.push('    ),')
}

lines.push('];', '')

fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(outPath, lines.join('\n'))
const provenanceReportPath = process.env.LZ_STATIC_CONFIG_PROVENANCE_REPORT
if (provenanceReportPath) {
    const resolvedReportPath = path.resolve(provenanceReportPath)
    fs.mkdirSync(path.dirname(resolvedReportPath), { recursive: true })
    fs.writeFileSync(
        resolvedReportPath,
        `${JSON.stringify({ ...provenance, generatedPath: outPath }, null, 2)}\n`,
    )
    console.log(`wrote LayerZero static config provenance report to ${resolvedReportPath}`)
}

console.log(`LayerZero upstream package version: ${provenance.lzDefinitions.version}`)
console.log(
    `wrote ${endpointEntries.length} LayerZero EVM endpoint entries and ${entries.length} deployment entries to ${outPath}`,
)
