import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'

const repoRoot = process.cwd()
const auditRoot = process.env.PILLAR_AUDIT_ROOT ?? path.resolve(repoRoot, '../pillar-audit')
const sourceCandidates = [
    process.env.LZ_TON_SDK_ROOT,
    path.join(auditRoot, 'node_modules/@layerzerolabs/lz-ton-sdk-v2'),
    path.resolve(repoRoot, 'local/ton-artifacts'),
].filter(Boolean)
const sourceRoot = sourceCandidates.find(isDirectory)
if (!sourceRoot) {
    fail(`no TON SDK root found; set LZ_TON_SDK_ROOT or PILLAR_AUDIT_ROOT (checked ${sourceCandidates.join(', ')})`)
}
const deprecatedRoot =
    process.env.LZ_TON_DEPRECATED_ROOT ??
    path.join(auditRoot, 'packages/contracts/lz-ton-contracts/deprecated-contracts')
const outPath = path.join(repoRoot, 'crates/pillar-config/src/generated_ton_layerzero.rs')

const NETWORK_TO_ENVIRONMENT = {
    'ton-mainnet': 'mainnet',
    'ton-testnet': 'testnet',
    'ton-sandbox-local': 'sandbox',
}

function isDirectory(candidatePath) {
    return fs.existsSync(candidatePath) && fs.statSync(candidatePath).isDirectory()
}

function fail(message) {
    console.error(`generate-ton-static-config: ${message}`)
    process.exit(1)
}

function readJsonFile(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'))
}

function directorySha256(dirPath) {
    const hash = createHash('sha256')
    const fileNames = fs.readdirSync(dirPath).sort()
    for (const fileName of fileNames) {
        hash.update(fileName)
        hash.update('\0')
        hash.update(fs.readFileSync(path.join(dirPath, fileName)))
        hash.update('\0')
    }
    return hash.digest('hex')
}

function escapeRustString(value) {
    return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

if (!isDirectory(sourceRoot)) {
    fail(`TON SDK root does not exist or is not a directory: ${sourceRoot}`)
}

const packageJsonPath = path.join(sourceRoot, 'package.json')
if (!fs.existsSync(packageJsonPath)) {
    fail(`TON SDK package.json not found: ${packageJsonPath}`)
}
const packageJson = readJsonFile(packageJsonPath)
const packageVersion = packageJson.version

const artifactsDir = path.join(sourceRoot, 'artifacts')
if (!isDirectory(artifactsDir)) {
    fail(`TON SDK artifacts directory does not exist: ${artifactsDir}`)
}

const artifactsSha256 = directorySha256(artifactsDir)
const deprecatedArtifactsDir = path.join(deprecatedRoot, 'artifacts')
const deprecatedDeploymentsRoot = path.join(deprecatedRoot, 'deployments')
if (!isDirectory(deprecatedArtifactsDir) || !isDirectory(deprecatedDeploymentsRoot)) {
    fail(`deprecated TON contracts root is incomplete: ${deprecatedRoot}`)
}
const deprecatedArtifactsSha256 = directorySha256(deprecatedArtifactsDir)

const artifactFileNames = fs
    .readdirSync(artifactsDir)
    .filter((fileName) => fileName.endsWith('.compiled.json'))
    .sort()

const codeCells = artifactFileNames.map((fileName) => {
    const contractName = fileName.replace(/\.compiled\.json$/, '')
    const artifact = readJsonFile(path.join(artifactsDir, fileName))
    if (typeof artifact.hex !== 'string' || artifact.hex.length === 0) {
        fail(`artifact ${fileName} is missing a "hex" code cell BOC`)
    }
    return { contractName, hex: artifact.hex.toLowerCase() }
})
codeCells.sort((a, b) => a.contractName.localeCompare(b.contractName))

for (const contractName of ['Uln', 'UlnConnection']) {
    const fileName = `${contractName}.compiled.json`
    const artifact = readJsonFile(path.join(deprecatedArtifactsDir, fileName))
    if (typeof artifact.hex !== 'string' || artifact.hex.length === 0) {
        fail(`deprecated artifact ${fileName} is missing a "hex" code cell BOC`)
    }
    codeCells.push({
        contractName: `Deprecated${contractName}`,
        hex: artifact.hex.toLowerCase(),
    })
}
codeCells.sort((a, b) => a.contractName.localeCompare(b.contractName))

const deploymentsRoot = path.join(sourceRoot, 'deployments')
if (!isDirectory(deploymentsRoot)) {
    fail(`TON SDK deployments directory does not exist: ${deploymentsRoot}`)
}

const deployments = []
for (const [networkDirName, environment] of Object.entries(NETWORK_TO_ENVIRONMENT)) {
    const networkDir = path.join(deploymentsRoot, networkDirName)
    if (!isDirectory(networkDir)) {
        fail(`TON SDK deployments network directory does not exist: ${networkDir}`)
    }
    const deploymentFileNames = fs
        .readdirSync(networkDir)
        .filter((fileName) => fileName.endsWith('.json'))
        .sort()
    for (const fileName of deploymentFileNames) {
        const deployment = readJsonFile(path.join(networkDir, fileName))
        if (typeof deployment.name !== 'string' || typeof deployment.address !== 'string') {
            fail(`deployment ${networkDirName}/${fileName} is missing "name" or "address"`)
        }
        deployments.push({ environment, contractName: deployment.name, address: deployment.address })
    }
}

for (const [networkDirName, environment] of Object.entries(NETWORK_TO_ENVIRONMENT)) {
    const deployment = readJsonFile(
        path.join(deprecatedDeploymentsRoot, networkDirName, 'UlnManager.json'),
    )
    if (typeof deployment.address !== 'string') {
        fail(`deprecated deployment ${networkDirName}/UlnManager.json is missing "address"`)
    }
    deployments.push({
        environment,
        contractName: 'DeprecatedUlnManager',
        address: deployment.address,
    })
}
deployments.sort((a, b) => {
    const environmentOrder = a.environment.localeCompare(b.environment)
    if (environmentOrder !== 0) return environmentOrder
    return a.contractName.localeCompare(b.contractName)
})

const lines = [
    '// @generated by scripts/generate-ton-static-config.mjs',
    '// Provenance:',
    `// Upstream package: ${packageJson.name}`,
    `// Upstream package version: ${packageVersion}`,
    `// Artifacts directory sha256: ${artifactsSha256}`,
    `// Deprecated artifacts directory sha256: ${deprecatedArtifactsSha256}`,
    `// Code cells: ${codeCells.length}`,
    `// Deployments: ${deployments.length}`,
    '// Source: public npm package @layerzerolabs/lz-ton-sdk-v2, extracted locally.',
    '',
    'pub const TON_CODE_CELLS: &[(&str, &str)] = &[',
]

for (const { contractName, hex } of codeCells) {
    lines.push(`    ("${escapeRustString(contractName)}", "${hex}"),`)
}

lines.push('];', '', 'pub const TON_DEPLOYMENTS: &[(&str, &str, &str)] = &[')

for (const { environment, contractName, address } of deployments) {
    lines.push('    (')
    lines.push(`        "${escapeRustString(environment)}",`)
    lines.push(`        "${escapeRustString(contractName)}",`)
    lines.push(`        "${escapeRustString(address)}",`)
    lines.push('    ),')
}

lines.push('];', '')

fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(outPath, lines.join('\n'))

console.log(`TON SDK upstream package: ${packageJson.name}@${packageVersion}`)
console.log(`TON SDK artifacts sha256: ${artifactsSha256}`)
console.log(`wrote ${codeCells.length} TON code cells and ${deployments.length} TON deployment entries to ${outPath}`)
