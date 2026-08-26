import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'

const repoRoot = process.cwd()
const sourceRoot = path.resolve(
    process.env.PILLAR_AUDIT_ROOT ?? path.join(repoRoot, '../pillar-audit'),
)
const officialMetadataUrl =
    'https://metadata.layerzero-api.com/v1/metadata/deployments'
const observedAt = new Date().toISOString()
const environments = ['mainnet', 'testnet']
const reportPath = path.resolve(
    process.env.LZ_ENVIRONMENT_PARITY_REPORT ??
        path.join(repoRoot, 'local/parity/layerzero-environment-report.json'),
)

function fail(message) {
    console.error(`check-layerzero-environment-parity: ${message}`)
    process.exit(1)
}

function readRequired(filePath) {
    if (!fs.existsSync(filePath)) fail(`missing input: ${filePath}`)
    return fs.readFileSync(filePath, 'utf8')
}

function sha256(raw) {
    return createHash('sha256').update(raw).digest('hex')
}

function parseTsObject(raw, filePath) {
    const assignment = raw.indexOf('=')
    if (assignment < 0) fail(`input has no assignment: ${filePath}`)
    const objectText = raw.slice(assignment + 1).trim().replace(/;$/, '')
    try {
        return Function(`"use strict"; return (${objectText})`)()
    } catch (error) {
        fail(`cannot parse ${filePath}: ${error instanceof Error ? error.message : error}`)
    }
}

function chainNamesPath(environment) {
    return path.join(
        sourceRoot,
        `packages/static-config/src/chainNames/${environment}.ts`,
    )
}

function deploymentPath(environment) {
    return path.join(
        sourceRoot,
        `packages/static-config/src/deploymentConfig/${environment}/deploymentConfig.ts`,
    )
}

function chainPathConnectionsPath(environment) {
    return path.join(
        sourceRoot,
        `packages/static-config/src/chainPathConnections/${environment}.ts`,
    )
}

function chainMetadataPath(environment) {
    return path.join(
        sourceRoot,
        `packages/static-config/src/staticDynamicConfigs/configs/chainMetadataConfig/${environment}/chainMetadataConfig.json`,
    )
}

function scanCapabilities(raw, environment, sourcePath) {
    const rows = []
    let version = null
    for (const [index, line] of raw.split('\n').entries()) {
        const versionMatch = line.match(/^\s*(V2|V301|V302|ReadV1002):\s*\{$/)
        if (versionMatch) {
            version = versionMatch[1]
            continue
        }
        const chainMatch = line.match(/^\s*([A-Za-z0-9_]+):\s*'([^']+)',?$/)
        if (version && chainMatch) {
            rows.push({
                environment,
                ulnVersion: version,
                chain: chainMatch[1],
                rawStatus: chainMatch[2],
                available: chainMatch[2] !== 'DEPRECATED',
                active: chainMatch[2] === 'ACTIVE',
                source: `${path.relative(sourceRoot, sourcePath)}:${index + 1}`,
                sourceLine: index + 1,
            })
        }
    }
    return rows
}

function parseGeneratedPillarConfig() {
    const raw = readRequired(
        path.join(repoRoot, 'crates/pillar-config/src/generated_layerzero_evm.rs'),
    )
    const addresses = new Map()
    const addressPattern = /\(\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\s*,?\s*\)/gs
    for (const match of raw.matchAll(addressPattern)) {
        addresses.set(`${match[1]}:${match[2]}:${match[3]}`, match[4])
    }
    const eids = new Map()
    const eidPattern = /\("([^"]+)", "([^"]+)", "([^"]+)", (\d+)\)/g
    for (const match of raw.matchAll(eidPattern)) {
        eids.set(`${match[1]}:${match[2]}:${match[3]}`, Number(match[4]))
    }
    const ethereumEndpoint = addresses.get('mainnet:ethereum:EndpointV2')
    if (
        addresses.size === 0 ||
        eids.size === 0 ||
        ethereumEndpoint?.toLowerCase() !==
            '0x1a44076050125825900e736c501f859c50fe728c'
    ) {
        fail(
            `generated Pillar config parser failed self-check: addresses=${addresses.size} eids=${eids.size} ethereumEndpoint=${ethereumEndpoint ?? 'missing'}`,
        )
    }
    return { rawSha256: sha256(raw), addresses, eids }
}

function optionalProviderConfig() {
    const inline = process.env.LAYERZERO_PROVIDER_CONFIG
    const filePath = process.env.LAYERZERO_PROVIDER_CONFIG_FILE_PATH
    if (!inline && !filePath) return null
    try {
        return JSON.parse(inline ?? readRequired(path.resolve(filePath)))
    } catch (error) {
        fail(`invalid provider config: ${error instanceof Error ? error.message : error}`)
    }
}

/**
 * The rollout gate lives in `crates/pillar-config/src/lib.rs`
 * (`layerzero_rollout_block_reason`). Parse it instead of restating it here: a
 * second copy silently drifts, and this report is what operators read to decide
 * what is safe to enable. A parse failure is fatal rather than "no chain is
 * blocked".
 */
function loadRolloutBlockRules() {
    const source = readRequired(
        path.resolve('crates/pillar-config/src/lib.rs'),
    )
    const start = source.indexOf('pub fn layerzero_rollout_block_reason(')
    if (start === -1) {
        fail('could not find layerzero_rollout_block_reason in pillar-config')
    }
    const end = source.indexOf('\npub fn ', start + 1)
    const body = source.slice(start, end === -1 ? source.length : end)

    const rules = []
    const arm = /\(([^)]*?)\)\s*=>\s*(?:\{\s*)?Some\(\s*\n?\s*"((?:[^"\\]|\\.)*)"/g
    let match
    while ((match = arm.exec(body)) !== null) {
        const [environments, chains] = match[1]
            .split(',')
            .map((part) => part.trim())
        if (!environments || !chains) continue
        const parseAlternatives = (text) =>
            text
                .split('|')
                .map((piece) => piece.trim().replace(/^"|"$/g, ''))
                .filter(Boolean)
        rules.push({
            environments: parseAlternatives(environments),
            chains: parseAlternatives(chains),
            reason: match[2],
        })
    }
    if (rules.length === 0) {
        fail('parsed no rollout-block rules from pillar-config')
    }
    return rules
}

const ROLLOUT_BLOCK_RULES = loadRolloutBlockRules()

function rolloutBlockReason(environment, chain) {
    const rule = ROLLOUT_BLOCK_RULES.find(
        (candidate) =>
            candidate.environments.includes(environment) &&
            candidate.chains.includes(chain),
    )
    return rule ? rule.reason : null
}

function officialDeployment(metadata, environment, chain) {
    const candidates = [
        `${chain}-${environment}`,
        chain,
        ...Object.keys(metadata).filter((key) =>
            key.toLowerCase().includes(chain.toLowerCase()) &&
            key.toLowerCase().includes(environment),
        ),
    ]
    for (const key of [...new Set(candidates)]) {
        const value = metadata[key]
        if (!value) continue
        const deployments = Array.isArray(value) ? value : value.deployments
        const v2 = deployments?.find((deployment) => Number(deployment.version) === 2)
        if (v2) return { key, jsonPath: `${key}.deployments[version=2]`, value: v2 }
    }
    return null
}

function pickMetadata(metadataByChain, chain) {
    const value = metadataByChain?.[chain]
    if (!value || typeof value !== 'object') return null
    return {
        finalities: value.finalities ?? null,
        avgBlockTime: value.avgBlockTime ?? null,
        maxEthGetLogsBlockRange: value.maxEthGetLogsBlockRange ?? null,
        supportsBlockPinning: value.supportsBlockPinning ?? null,
    }
}

let officialMetadata
try {
    const response = await fetch(officialMetadataUrl)
    if (!response.ok) fail(`official metadata HTTP ${response.status}`)
    officialMetadata = await response.json()
} catch (error) {
    fail(`cannot fetch official metadata: ${error instanceof Error ? error.message : error}`)
}

const pillar = parseGeneratedPillarConfig()
const providerConfig = optionalProviderConfig()
const tuples = []
const inputs = []
for (const environment of environments) {
    const capabilityFile = chainNamesPath(environment)
    const capabilityRaw = readRequired(capabilityFile)
    const deploymentFile = deploymentPath(environment)
    const deploymentRaw = readRequired(deploymentFile)
    const deployment = parseTsObject(deploymentRaw, deploymentFile)
    const connectionFile = chainPathConnectionsPath(environment)
    const connectionRaw = readRequired(connectionFile)
    const connections = parseTsObject(connectionRaw, connectionFile)
    const metadataFile = chainMetadataPath(environment)
    const metadataRaw = readRequired(metadataFile)
    const chainMetadata = JSON.parse(metadataRaw)
    inputs.push(
        { kind: 'chainNames', environment, sha256: sha256(capabilityRaw) },
        { kind: 'deploymentConfig', environment, sha256: sha256(deploymentRaw) },
        { kind: 'chainPathConnections', environment, sha256: sha256(connectionRaw) },
        { kind: 'chainMetadataConfig', environment, sha256: sha256(metadataRaw) },
    )

    const capabilities = scanCapabilities(capabilityRaw, environment, capabilityFile)
    for (const capability of capabilities) {
        if (!capability.available || !['V2', 'V302'].includes(capability.ulnVersion)) continue
        const chain = capability.chain
        const providerConfigured = providerConfig
            ? Object.prototype.hasOwnProperty.call(providerConfig, chain)
            : null
        const blockReason = rolloutBlockReason(environment, chain)
        const official = officialDeployment(officialMetadata, environment, chain)
        const gasolinaContracts = deployment[chain] ?? null
        const pillarContracts = gasolinaContracts
            ? Object.fromEntries(
                  Object.keys(gasolinaContracts).map((contractName) => [
                      contractName,
                      pillar.addresses.get(`${environment}:${chain}:${contractName}`) ?? null,
                  ]),
              )
            : null
        const addressVerdicts = gasolinaContracts
            ? Object.fromEntries(
                  Object.entries(gasolinaContracts).map(([contractName, address]) => [
                      contractName,
                      pillarContracts?.[contractName] == null
                          ? 'pillar-missing'
                          : pillarContracts[contractName].toLowerCase() === String(address).toLowerCase()
                            ? 'match'
                            : 'mismatch',
                  ]),
              )
            : null
        tuples.push({
            ...capability,
            providerConfigured,
            startupAdmission:
                blockReason != null
                    ? 'rollout-blocked'
                    : providerConfigured == null
                      ? 'not-evaluated'
                      : providerConfigured
                        ? 'admitted'
                        : 'required-provider-missing',
            rolloutBlocked: blockReason != null,
            rolloutBlockReason: blockReason,
            chainPathConnections: {
                topLevelKey: Object.prototype.hasOwnProperty.call(connections, chain),
                remoteChains: connections[chain] ?? null,
                gasolinaRuntimeConsumer: false,
                policy: 'report-only',
            },
            chainMetadata: pickMetadata(chainMetadata, chain),
            deployments: {
                gasolina: gasolinaContracts,
                pillar: pillarContracts,
                addressVerdicts,
                pinnedPackage: {
                    name: '@layerzerolabs/lz-definitions',
                    version: '3.1.2',
                    separatelyMaterialized: false,
                },
                official: official
                    ? {
                          url: officialMetadataUrl,
                          observedAt,
                          key: official.key,
                          jsonPath: official.jsonPath,
                          eid: official.value.eid ?? null,
                          endpointV2: official.value.endpointV2 ?? null,
                          receiveUln302: official.value.receiveUln302 ?? null,
                          sendUln302: official.value.sendUln302 ?? null,
                      }
                    : {
                          url: officialMetadataUrl,
                          observedAt,
                          key: null,
                          jsonPath: null,
                          eid: null,
                          endpointV2: null,
                          receiveUln302: null,
                          sendUln302: null,
                      },
            },
        })
    }
}

const requiredFieldsMissing = tuples.filter(
    (tuple) =>
        !tuple.source ||
        tuple.rawStatus == null ||
        tuple.chainPathConnections == null ||
        tuple.deployments?.official?.url !== officialMetadataUrl,
)
if (requiredFieldsMissing.length > 0) {
    fail(`${requiredFieldsMissing.length} tuples are missing required report fields`)
}

const report = {
    generatedAt: observedAt,
    sourceRoot,
    officialMetadataUrl,
    policy: {
        availableUnion: 'V2 + V302 where status != DEPRECATED',
        providerExtras: 'excluded from API/provider/SDK/signer surfaces',
        supportedUlnVersions: 'legacy EVM V2/V301 builders only',
        chainPathConnections: 'report-only; no Gasolina sign runtime consumer',
        // Generated from the parsed Rust rules so the prose can never disagree
        // with the tuples in this same report.
        rolloutGate: ROLLOUT_BLOCK_RULES.map(
            (rule) =>
                `${rule.chains.join('/')} on ${rule.environments.join('/')}: ${rule.reason}`,
        ),
    },
    inputs,
    pillarGeneratedConfigSha256: pillar.rawSha256,
    providerConfigEvaluated: providerConfig != null,
    tupleCount: tuples.length,
    tuples,
    signingCriticalMetadataReview: {
        status: 'recorded-request parity required',
        wholesaleMetadataPort: false,
    },
}
fs.mkdirSync(path.dirname(reportPath), { recursive: true })
fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`)
console.log(`wrote ${tuples.length} environment capability tuples to ${reportPath}`)
console.log(
    `rollout-blocked tuples: ${tuples.filter((tuple) => tuple.rolloutBlocked).length}; provider config evaluated: ${providerConfig != null}`,
)
