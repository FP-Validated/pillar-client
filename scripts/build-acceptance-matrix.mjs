#!/usr/bin/env node
// Builds audit/acceptance/acceptance-rows.{csv,md} from committed inputs only: the
// generated capability table, chain_bindings.json and the upstream-executed fixtures
// under crates/pillar-runtime/tests/gasolina_parity/. No network, no upstream checkout.
//
// A row is (environment, chain, role, ULN version) for every version the capability
// table lists as ACTIVE. Statuses are distinct kinds of evidence and never add up:
//   final-response        production HTTP answer compared with upstream's own server
//                         over recorded receipts (exact route evidence)
//   component-exact       an upstream-executed fixture covers this exact row at
//                         builder/resolver/refresh level (component evidence)
//   family                only another chain of the same family, role and version was
//                         executed; this row is reached by the same table-driven code
//                         (family inference, not evidence for this chain)
//   extension             deliberate, evidenced divergence from upstream (not parity)
//   upstream-unsupported  upstream throws for every contract role; both refuse
//   incomplete            rollout-gated, an open difference, or no executed evidence
//
// Usage: node scripts/build-acceptance-matrix.mjs [--check]
// --check regenerates in memory and fails if the committed files differ.

import fs from 'node:fs'
import path from 'node:path'

const repoRoot = process.cwd()
const FX = path.join(repoRoot, 'crates/pillar-runtime/tests/gasolina_parity')
const OUT = path.join(repoRoot, 'audit/acceptance')
const VERSIONS = ['V2', 'V301', 'V302', 'ReadV1002']
const ENVS = ['mainnet', 'testnet', 'sandbox']
const NON_EVM_FAMILY = new Set(['APTOS', 'INITIA', 'IOTAMOVE', 'SUI', 'SOLANA', 'STARKNET', 'TON', 'STELLAR', 'CANTON'])

const load = (name) => JSON.parse(fs.readFileSync(path.join(FX, name), 'utf8'))
const key = (...parts) => JSON.stringify(parts)

function capabilityPairs() {
    const source = fs.readFileSync(path.join(repoRoot, 'crates/pillar-config/src/generated_layerzero_environment.rs'), 'utf8')
    const pattern = /\("(\w+)", "(\w+)", "([\w-]+)", "(\w+)", \d+\)/g
    const pairs = new Map()
    for (const [, env, version, chain, status] of source.matchAll(pattern)) {
        const id = `${env}\u0000${chain}`
        if (!pairs.has(id)) pairs.set(id, { env, chain, status: {} })
        pairs.get(id).status[version] = status
    }
    return [...pairs.values()].sort((a, b) =>
        ENVS.indexOf(a.env) - ENVS.indexOf(b.env) || (a.chain < b.chain ? -1 : a.chain > b.chain ? 1 : 0))
}

const final = new Set()
for (const pathway of load('historical_smoke.json').pathways) {
    const request = typeof pathway.httpRequest === 'string' ? JSON.parse(pathway.httpRequest) : pathway.httpRequest
    let body = request.body ?? request
    body = typeof body === 'string' ? JSON.parse(body) : body
    const lz = body.lzMessageId
    const env = lz.pathwayId.srcChainName === 'ethereum' ? 'mainnet' : 'testnet'
    const version = lz.ulnSendVersion
    final.add(key(env, lz.pathwayId.srcChainName, 'src', version))
    final.add(key(env, lz.pathwayId.dstChainName, 'dst', version))
}

const component = new Map()
const addComponent = (k, name) => {
    if (!component.has(k)) component.set(k, [])
    component.get(k).push(name)
}
for (const row of load('evm_catalog_destination.json').rows) {
    for (const [version, arm] of Object.entries(row.arms)) {
        if (arm && typeof arm === 'object' && 'hashCallData' in arm) {
            addComponent(key(row.environment, row.chainName, 'dst', version), 'evm_catalog_destination')
        }
    }
}
for (const row of load('non_evm_destination.json').rows) {
    for (const [arm, outcome] of Object.entries(row.arms)) {
        const version = arm.split(':')[0]
        if (outcome && typeof outcome === 'object' && ['built', 'refused'].includes(outcome.outcome)) {
            addComponent(key(row.environment, row.chainName, 'dst', version), `non_evm_destination:${arm}=${outcome.outcome}`)
        }
    }
}
const ULNV2_APTOS = 'aptos_ulnv2_destination: production HTTP vs upstream routing/feather/builder/signer components (on-chain acceptance not observed)'
const EVM_SOURCE = 'evm_source_events SDK-level (12 replayed = 11 exact + 1 Pillar extension)'
for (const [k, name] of [
    [['mainnet', 'aptos', 'src', 'V2'], 'aptos_v1_source + v1_refresh'],
    [['mainnet', 'aptos', 'src', 'V301'], 'aptos_v301_source (recorded mainnet send)'],
    [['mainnet', 'bsc', 'src', 'V2'], 'v2_v3_route + v1_refresh'],
    [['mainnet', 'bsc', 'src', 'V301'], EVM_SOURCE],
    [['mainnet', 'bsc', 'src', 'V302'], `${EVM_SOURCE}; evm_options 32 vectors`],
    [['mainnet', 'bsc', 'src', 'ReadV1002'], `${EVM_SOURCE}; evm_options read vectors`],
    [['mainnet', 'solana', 'src', 'V302'], 'source_replay solana'],
    [['mainnet', 'tron', 'src', 'V302'], 'source_replay tron'],
    [['mainnet', 'ton', 'src', 'V302'], 'source_replay ton + ton-trace-quorum'],
    [['mainnet', 'aptos', 'src', 'V302'], 'move_source_events (36 scenarios: 28 exact, 8 movement V301 stricter)'],
    [['mainnet', 'movement', 'src', 'V302'], 'move_source_events (movement V302 rows exact)'],
    [['mainnet', 'initia', 'src', 'V302'], 'initia_source_events (17: 15 exact, 1 stricter, 1 text residual)'],
    [['mainnet', 'sui', 'src', 'V302'], 'sui_source_events (42: 34 exact, 8 stricter)'],
    [['mainnet', 'iotal1', 'src', 'V302'], 'sui_source_events (iotal1 half of 42 rows)'],
    [['mainnet', 'starknet', 'src', 'V302'], 'starknet_source_events (23: 22 exact, 1 stricter)'],
    [['mainnet', 'stellar', 'src', 'V302'], 'stellar_source_events (20: 18 exact, 2 stricter)'],
    [['mainnet', 'aptos', 'dst', 'V2'], ULNV2_APTOS],
    [['testnet', 'aptos', 'dst', 'V2'], ULNV2_APTOS],
]) {
    addComponent(key(...k), name)
}
for (const env of ENVS) {
    addComponent(key(env, 'canton', 'src', 'V302'), 'canton_sequencer resolve/confirmations (environment-independent sequencer logic)')
    addComponent(key(env, 'canton', 'dst', 'V302'), 'canton_sequencer payloadSigned + canton_digest + canton_sign')
}

const FAMILY_EXECUTED = new Map([
    [key('EVM', 'src', 'V302'), 'historical_smoke ethereum/sepolia; evm_signing_path uln_v3_verify'],
    [key('EVM', 'src', 'ReadV1002'), 'evm_signing_path uln_read_v1002_verify; evm_source_events bsc'],
    [key('EVM', 'src', 'V301'), 'evm_source_events bsc (EndpointV2EvmSdk.getLZSentEvent, SendUln301)'],
    [key('EVM', 'src', 'V2'), 'bsc v2_v3_route + v1_refresh'],
    [key('TRON', 'src', 'V302'), 'source_replay tron'],
])
for (const version of ['V2', 'V301', 'ReadV1002']) {
    FAMILY_EXECUTED.set(key('TRON', 'src', version),
        `EVM resolver (TRON runs the EVM PacketSent path); ${FAMILY_EXECUTED.get(key('EVM', 'src', version))}`)
}
const SAME_CHAIN_OTHER_ENV = new Map()
for (const [k, names] of component) {
    const [env, chain, role, version] = JSON.parse(k)
    SAME_CHAIN_OTHER_ENV.set(key(chain, role, version), `${env}: ${names.join('; ')}`)
}
const bindings = load('chain_bindings.json')
const BINDINGS = new Set(bindings.rows
    .filter((r) => !('error' in (r.roles?.EndpointV2 ?? { error: 1 })))
    .map((r) => key(r.environment, r.chainName)))
const UPSTREAM_UNBOUND = new Set(bindings.rows
    .filter((r) => r.roles && Object.keys(r.roles).length > 0 && Object.values(r.roles).every((v) => 'error' in v))
    .map((r) => key(r.environment, r.chainName)))

const MONINET_GATE = 'B1 rollout gate (ACTIVE; 8/10 addresses match metadata, 2 unpublished; no public RPC or EVM chainId)'
const GATES = new Map([
    [key('testnet', 'moninet', 'src'), MONINET_GATE],
    [key('testnet', 'moninet', 'dst'), MONINET_GATE],
    [key('testnet', 'ton', 'src'), 'B2 rollout gate; no TON testnet source evidence (the delivered packet is a '
        + 'destination check); mainnet source_replay ton only; awaits operator rollout decision'],
    [key('testnet', 'ton', 'dst'), 'B2 rollout gate; delivered arbsep->TON testnet packet (nonce 11): payload-signed check '
        + 'refuses VERIFIED over the real UlnConnection/Uln storage; signing path not run; '
        + 'awaits operator rollout decision'],
])
const GATE_EVIDENCE = new Map([[key('testnet', 'ton', 'dst'), [
    'onchain_provenance/ton_testnet_delivered_packet.json (toncenter storage, mc seqno 89204726/89204732)',
    'payload_signed::rebuilds_the_testnet_delivered_packet_cell',
    'payload_signed::derives_the_testnet_uln_connection_from_the_configured_uln_manager',
    'validation_payload_ton_tests::runtime_rpc_validation_checks_send_the_testnet_packet_and_reject_its_verified_state',
    'validation_payload_ton_tests::runtime_rpc_validation_checks_refuse_the_testnet_packet_over_its_real_storage',
]]])
const VID_EXTENSION = new Set(['doma', 'lineasep', 'zksyncsep'].map((c) => key('testnet', c)))
const VID_UNMEASURED = new Set([key('testnet', 'scroll')])
const CANTON_SOURCE = 'A2 ledger read + OAuth2 token implemented from common-canton 1.2.66 source; '
    + 'read executed against real Canton 3.5.19 with synthetic auth (no LayerZero DAR, no signing); '
    + 'needs operator OAuth2/ledger config; sandbox JWT auth not enabled'

const rows = []
for (const { env, chain, status: capability } of capabilityPairs()) {
    const family = bindings.chainTypes[chain]
    for (const version of VERSIONS) {
        if (capability[version] !== 'ACTIVE') continue
        for (const role of ['src', 'dst']) {
            const k = key(env, chain, role, version)
            const pair = key(env, chain)
            const evidence = [...(component.get(k) ?? [])]
            let status = null
            let note = ''
            if (UPSTREAM_UNBOUND.has(pair)) {
                status = 'upstream-unsupported'
                note = '1.2.66 throws for every contract role of this chain (chain_bindings); both refuse, texts differ; not parity'
            } else if (GATES.has(key(env, chain, role))) {
                status = 'incomplete'
                note = GATES.get(key(env, chain, role))
                evidence.push(...(GATE_EVIDENCE.get(key(env, chain, role)) ?? []))
            } else if (family === 'CANTON' && role === 'src') {
                status = 'incomplete'
                note = CANTON_SOURCE
            } else if (family === 'APTOS' && role === 'dst' && version === 'V2' && evidence.length === 0) {
                status = 'incomplete'
                note = 'A3 bounded to aptos mainnet/testnet; no upstream evidence for this row'
            } else if (role === 'dst' && VID_UNMEASURED.has(pair)) {
                status = 'incomplete'
                note = 'C1 vId unmeasured on chain'
            } else if (role === 'dst' && VID_EXTENSION.has(pair)) {
                status = 'extension'
                note = 'C1 signed vId is the on-chain DVN vid (dvn_vid.json), not upstream EndpointV2 % 30000'
            } else if (final.has(k)) {
                status = 'final-response'
            } else if (evidence.length > 0) {
                status = 'component-exact'
            } else if (role === 'src' && ['EVM', 'TRON'].includes(family) && FAMILY_EXECUTED.has(key(family, role, version))) {
                status = 'family'
                evidence.push(FAMILY_EXECUTED.get(key(family, role, version)))
                if (BINDINGS.has(pair)) evidence.push('chain_bindings (exact source contract identities)')
            } else if (SAME_CHAIN_OTHER_ENV.has(key(chain, role, version))) {
                status = 'family'
                evidence.push(`same chain, another environment - ${SAME_CHAIN_OTHER_ENV.get(key(chain, role, version))}`)
            } else {
                status = 'incomplete'
                note = 'no upstream-executed evidence for this role and version'
            }
            if (final.has(k)) {
                evidence.unshift('historical_smoke (production HTTP vs upstream startServer)')
                if (chain === 'solana') note = 'signer address compared with a local mnemonic; Azure has no 1.2.66 reference (C2)'
            }
            rows.push({ env, chain, type: family, role, version, status, evidence: evidence.join('; '), note })
        }
    }
}

const STATUSES = ['final-response', 'component-exact', 'family', 'extension', 'upstream-unsupported', 'incomplete']
const csvField = (value) => (/[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value)
const columns = Object.keys(rows[0])
const csv = [columns.join(','), ...rows.map((r) => columns.map((c) => csvField(r[c])).join(','))].join('\n') + '\n'

const counts = Object.fromEntries(STATUSES.map((s) => [s, rows.filter((r) => r.status === s).length]))
const byKind = new Map()
for (const r of rows) {
    const k = [r.type, r.role, r.version, r.status]
    const id = k.join('\u0000')
    byKind.set(id, { k, n: (byKind.get(id)?.n ?? 0) + 1 })
}
const compare = (a, b) => {
    for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1
    return 0
}
const md = [
    '# Acceptance rows (evidence-mapped)',
    '',
    'Generated by `node scripts/build-acceptance-matrix.mjs` from committed inputs; see `AUDIT.md`.',
    `Rows: every ACTIVE (environment, chain, ULN version) of the capability table (${new Set(rows.map((r) => key(r.env, r.chain, r.version))).size}) times both roles.`,
    'Only `final-response` is exact route evidence (production HTTP path). `component-exact` is component evidence.',
    '`family` is inference from another chain of the same family and is not evidence for the row itself.',
    '',
    '## Counts',
    '',
    ...STATUSES.map((s) => `- ${s}: ${counts[s]}`),
    `- total rows: ${rows.length}`,
    '',
    '## By family, role, version',
    '',
    '| family | role | version | status | rows |',
    '|---|---|---|---|---|',
    ...[...byKind.values()].sort((a, b) => compare(a.k, b.k)).map(({ k, n }) => `| ${k.join(' | ')} | ${n} |`),
    '',
    '## Incomplete, extension and upstream-unsupported rows',
    '',
    '| env | chain | role | version | status | note |',
    '|---|---|---|---|---|---|',
    ...rows.filter((r) => ['incomplete', 'extension', 'upstream-unsupported'].includes(r.status))
        .map((r) => `| ${r.env} | ${r.chain} | ${r.role} | ${r.version} | ${r.status} | ${r.note} |`),
    '',
].join('\n')

const outputs = { 'acceptance-rows.csv': csv, 'acceptance-rows.md': md }
if (process.argv.includes('--check')) {
    const stale = Object.entries(outputs)
        .filter(([name, text]) => !fs.existsSync(path.join(OUT, name)) || fs.readFileSync(path.join(OUT, name), 'utf8') !== text)
        .map(([name]) => name)
    if (stale.length > 0) {
        console.error(`stale: ${stale.join(', ')}; rerun without --check`)
        process.exit(1)
    }
} else {
    fs.mkdirSync(OUT, { recursive: true })
    for (const [name, text] of Object.entries(outputs)) fs.writeFileSync(path.join(OUT, name), text)
}
console.log(JSON.stringify({ rows: rows.length, ...counts }))
