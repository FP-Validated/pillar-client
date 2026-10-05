// Test-boundary loader for upstream comparisons. Every Gasolina-supported chain is in scope
// (2026-10-04); a module is replaced only where it needs generated artifacts the snapshot does
// not carry: Canton/Daml modules other than CANTON_PURE_ALLOWLIST (Daml/OpenAPI clients) and
// MISSING_GENERATED (Stellar contract bindings). Each is replaced, at the import edge from an
// included module, by a generated fail-closed module: every export is a function that records
// the call and throws, and every property read of the module object is recorded.
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { builtinModules, registerHooks } from 'node:module'

const root = fs.realpathSync('/tmp/gasolina-run/work')
const reportPath = process.env.BOUNDARY_REPORT
const genDirInput = process.env.BOUNDARY_GEN_DIR
if (!reportPath || !genDirInput) throw new Error('BOUNDARY_REPORT and BOUNDARY_GEN_DIR are required')
fs.mkdirSync(genDirInput, { recursive: true })
const genDir = fs.realpathSync(genDirInput)

const builtins = new Set(builtinModules.flatMap((name) => [name, name.replace(/^node:/, '')]))
const roots = new Map()
const ignored = new Set(['node_modules', '.git', 'dist', '.turbo'])
function scan(dir) {
    let entries
    try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch { return }
    for (const ent of entries) {
        if (!ent.isDirectory() || ignored.has(ent.name)) continue
        const full = path.join(dir, ent.name), manifest = path.join(full, 'package.json')
        if (fs.existsSync(manifest)) try { const pkg = JSON.parse(fs.readFileSync(manifest, 'utf8')); if (typeof pkg.name === 'string' && !roots.has(pkg.name)) roots.set(pkg.name, full) } catch {}
        scan(full)
    }
}
scan(root)
const pnpmRoot = path.join(root, 'node_modules/.pnpm')
const pnpmEntries = fs.readdirSync(pnpmRoot, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name)
const pnpmCache = new Map()
function compareVersions(a, b) {
    const aa = a.split('.').map((x) => Number.parseInt(x, 10) || 0), bb = b.split('.').map((x) => Number.parseInt(x, 10) || 0)
    for (let i = 0; i < Math.max(aa.length, bb.length); i++) if ((aa[i] || 0) !== (bb[i] || 0)) return (aa[i] || 0) - (bb[i] || 0)
    return 0
}
function conditionTarget(value, conditions) {
    if (typeof value === 'string') return value
    if (Array.isArray(value)) { for (const item of value) { const selected = conditionTarget(item, conditions); if (selected) return selected } return undefined }
    if (value && typeof value === 'object') {
        for (const condition of conditions) if (Object.hasOwn(value, condition)) { const selected = conditionTarget(value[condition], conditions); if (selected) return selected }
        if (Object.hasOwn(value, 'default')) return conditionTarget(value.default, conditions)
    }
}
function fromPnpm(request, conditions) {
    const parts = request.split('/')
    if (builtins.has(request) || request.startsWith('.') || request.startsWith('/') || request.startsWith('node:')) return undefined
    const packageName = request.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]
    let packageRoot = pnpmCache.get(packageName)
    if (packageRoot === undefined) {
        const candidates = []
        for (const entry of pnpmEntries) {
            const candidate = path.join(pnpmRoot, entry, 'node_modules', packageName)
            if (!fs.existsSync(candidate)) continue
            let version = '0.0.0'
            try { version = JSON.parse(fs.readFileSync(path.join(candidate, 'package.json'), 'utf8')).version || version } catch {}
            candidates.push({ candidate, version })
        }
        candidates.sort((a, b) => compareVersions(b.version, a.version))
        packageRoot = candidates[0]?.candidate || null
        pnpmCache.set(packageName, packageRoot)
    }
    if (!packageRoot) return undefined
    const subpathParts = parts.slice(packageName.startsWith('@') ? 2 : 1), subpath = subpathParts.join('/')
    let target
    try {
        const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'))
        if (pkg.exports !== undefined) {
            const key = subpath ? `./${subpath}` : '.', exp = pkg.exports
            if (typeof exp === 'string' || Array.isArray(exp) || Object.keys(exp || {}).some((k) => !k.startsWith('.'))) target = conditionTarget(exp, conditions)
            else if (exp && typeof exp === 'object') {
                target = conditionTarget(exp[key], conditions)
                if (!target) for (const [pattern, value] of Object.entries(exp)) {
                    const star = pattern.indexOf('*'); if (star < 0) continue
                    const prefix = pattern.slice(0, star), suffix = pattern.slice(star + 1)
                    if (key.startsWith(prefix) && key.endsWith(suffix)) { const replacement = key.slice(prefix.length, key.length - suffix.length); target = conditionTarget(value, conditions)?.replaceAll('*', replacement); if (target) break }
                }
            }
        }
        if (!target && !subpath) target = pkg.module || pkg.main
    } catch {}
    let resolved = target ? path.resolve(packageRoot, target) : subpath ? path.join(packageRoot, subpath) : undefined
    if (!resolved) return undefined
    if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) for (const name of ['index.js', 'index.mjs', 'index.cjs']) { const candidate = path.join(resolved, name); if (fs.existsSync(candidate)) return candidate }
    if (fs.existsSync(resolved)) return resolved
    if (!path.extname(resolved)) for (const ext of ['.js', '.mjs', '.cjs', '.json']) { const candidate = resolved + ext; if (fs.existsSync(candidate)) return candidate }
}
function sourceEntry(base, suffix) {
    const candidates = !suffix
        ? [path.join(base, 'src', 'index.ts')]
        : suffix.startsWith('src/')
          ? [`${path.join(base, suffix)}.ts`, path.join(base, suffix, 'index.ts')]
          : [`${path.join(base, 'src', suffix)}.ts`, path.join(base, 'src', suffix, 'index.ts'), exportedSource(base, suffix)]
    return candidates.find((p) => p && fs.existsSync(p))
}
// A workspace package's `exports` subpath points into its unbuilt `dist/`; the source the
// build would compile sits at the same path under `src/`.
function exportedSource(base, suffix) {
    try {
        const exp = JSON.parse(fs.readFileSync(path.join(base, 'package.json'), 'utf8')).exports
        const target = exp && typeof exp === 'object' ? conditionTarget(exp[`./${suffix}`], ['import', 'default']) : undefined
        if (target?.startsWith('./dist/')) return path.join(base, 'src', target.slice('./dist/'.length).replace(/\.(c|m)?js$/, '.ts'))
    } catch {}
}

const pnpmFallbacks = []
registerHooks({
    resolve(specifier, context, nextResolve) {
        let request = specifier
        if (request.startsWith('@monorepo/')) request = `@offchain-monorepo/${request.slice('@monorepo/'.length)}`
        const name = [...roots.keys()].sort((a, b) => b.length - a.length).find((candidate) => request === candidate || request.startsWith(`${candidate}/`))
        if (name) { const suffix = request === name ? '' : request.slice(name.length + 1), entry = sourceEntry(roots.get(name), suffix); if (entry) return { url: pathToFileURL(entry).href, shortCircuit: true } }
        try { return nextResolve(specifier, context) } catch {}
        const installed = fromPnpm(request, context.conditions || [])
        if (installed) {
            pnpmFallbacks.push({ request, parent: context.parentURL ? path.relative(root, fileURLToPath(context.parentURL)) : null, resolved: path.relative(root, installed) })
            return { url: pathToFileURL(installed).href, shortCircuit: true }
        }
        if (request.startsWith('.') && context.parentURL?.startsWith('file:')) {
            const parent = fileURLToPath(context.parentURL)
            if (parent.startsWith(root + path.sep)) { const base = path.resolve(path.dirname(parent), request); for (const candidate of [`${base}.ts`, path.join(base, 'index.ts')]) if (fs.existsSync(candidate)) return { url: pathToFileURL(candidate).href, shortCircuit: true } }
        }
        return nextResolve(specifier, context)
    },
})

const EXCLUDED_SEGMENT = /canton|daml/i
const CANTON_PURE_ALLOWLIST = new Set([
    'migrated/offchain-monorepo/apps/gasolina/src/app/sdks/gasolinaSdk/canton/hashes.ts',
    'migrated/offchain-monorepo/packages/adapters/gasolina-signer-adapter/src/canton/index.ts',
    'packages/vms/canton/common/src/client/utils.ts',
    'packages/vms/canton/common/src/crypto.ts',
    // The sequencer-facing SDKs: scan decoders, EndpointV2/Uln302 reads and confirmations.
    'migrated/offchain-monorepo/packages/sdks/lz-v2-sdk/src/canton/index.ts',
    'migrated/offchain-monorepo/packages/sdks/lz-v2-sdk/src/canton/types.ts',
    'migrated/offchain-monorepo/packages/sdks/lz-v2-sdk/src/canton/decoders.ts',
    'migrated/offchain-monorepo/packages/sdks/lz-v2-sdk/src/canton/events.ts',
    'migrated/offchain-monorepo/packages/sdks/lz-v2-sdk/src/canton/scan-event-types.ts',
    'migrated/offchain-monorepo/packages/sdks/lz-v2-sdk/src/endpoint/canton/index.ts',
    'migrated/offchain-monorepo/packages/sdks/lz-v2-sdk/src/uln/canton/index.ts',
    'migrated/offchain-monorepo/packages/sdks/rpc-sdk/src/canton/index.ts',
])
// Modules outside the Canton tree whose own generated artifacts are absent from the snapshot:
// `@layerzerolabs/lz-v2-stellar-sdk` re-exports `stellar contract bindings` output
// (`src/generated/*.js`, produced from contract WASM by `bindings.toml`), and the openzeppelin
// contracts package re-exports its typechain output (`./typechain`). Upstream's Stellar
// endpoint/ULN SDKs and the EVM altchain RPC sdk need them; nothing on the signing path does.
const MISSING_GENERATED = new Set([
    'contracts/protocol/stellar/sdk/src/index.ts',
    'migrated/offchain-monorepo/packages/contracts/openzeppelin/src/index.ts',
])
const excludedPath = (file) => {
    const rel = path.relative(root, file)
    if (rel.startsWith('..') || rel.split(path.sep).includes('node_modules')) return false
    if (MISSING_GENERATED.has(rel)) return true
    return !CANTON_PURE_ALLOWLIST.has(rel) && rel.split(path.sep).some((segment) => EXCLUDED_SEGMENT.test(segment.replace(/\.(c|m)?[jt]s$/, '')))
}
const unresolvedStarExports = []
function exportNames(file, seen = new Set()) {
    if (seen.has(file)) return []
    seen.add(file)
    let src
    try { src = fs.readFileSync(file, 'utf8') } catch { return [] }
    src = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"])\/\/.*$/gm, '$1')
    const names = new Set()
    for (const m of src.matchAll(/^\s*export\s+(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?(?:const\s+enum|class|function\*?|const|let|var|enum|namespace)\s+([A-Za-z_$][\w$]*)/gm)) names.add(m[1])
    if (/^\s*export\s+default\s/m.test(src)) names.add('default')
    for (const m of src.matchAll(/^\s*export\s+(type\s+)?\{([^}]*)\}/gm)) {
        if (m[1]) continue
        for (let part of m[2].split(',')) {
            part = part.trim()
            if (!part || part.startsWith('type ')) continue
            const pieces = part.split(/\s+as\s+/)
            names.add((pieces[1] || pieces[0]).trim())
        }
    }
    for (const m of src.matchAll(/^\s*export\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from/gm)) names.add(m[1])
    for (const m of src.matchAll(/^\s*export\s+\*\s+from\s+['"]([^'"]+)['"]/gm)) {
        const spec = m[1]
        if (!spec.startsWith('.')) { unresolvedStarExports.push({ file: path.relative(root, file), spec }); continue }
        const base = path.resolve(path.dirname(file), spec)
        const found = [`${base}.ts`, path.join(base, 'index.ts'), `${base}.js`, base].find((c) => fs.existsSync(c) && fs.statSync(c).isFile())
        if (found) for (const n of exportNames(found, seen)) names.add(n)
        else unresolvedStarExports.push({ file: path.relative(root, file), spec })
    }
    return [...names].sort()
}

const replaced = new Map()
const parentLoadedExcluded = []
function failClosedModule(file) {
    const rel = path.relative(root, file)
    let entry = replaced.get(rel)
    if (entry) return entry
    const sourceSha256 = fs.existsSync(file) ? crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') : null
    const names = fs.existsSync(file) ? exportNames(file) : []
    const out = path.join(genDir, `${rel.replaceAll(path.sep, '__')}.cjs`)
    fs.writeFileSync(out, `'use strict'
// GENERATED fail-closed replacement for ${rel} (excluded chain; never returns a value).
const MODULE = ${JSON.stringify(rel)}
const NAMES = ${JSON.stringify(names)}
const state = (globalThis.__excludedBoundary ||= { reads: [], calls: [] })
const where = () => new Error().stack.split('\\n').slice(3, 7).map((l) => l.trim())
const failClosed = (name) => function excludedChainAdapter() {
    state.calls.push({ module: MODULE, name, stack: where() })
    throw new Error('EXCLUDED_CHAIN_ADAPTER ' + MODULE + '#' + name + ': module needs generated artifacts absent from the snapshot')
}
const target = {}
for (const name of NAMES) target[name] = failClosed(name)
Object.defineProperty(target, '__esModule', { value: true })
module.exports = new Proxy(target, {
    get(t, key, receiver) {
        if (typeof key !== 'symbol' && key !== '__esModule') state.reads.push({ module: MODULE, name: String(key), stack: where() })
        return Reflect.get(t, key, receiver)
    },
})
`)
    entry = { module: rel, sourceSha256, exportNames: names, generated: path.relative(root, out), importers: [] }
    replaced.set(rel, entry)
    return entry
}

registerHooks({
    resolve(specifier, context, nextResolve) {
        const result = nextResolve(specifier, context)
        if (!result?.url?.startsWith('file:')) return result
        const file = fileURLToPath(result.url)
        if (!excludedPath(file)) return result
        const parent = context.parentURL?.startsWith('file:') ? fileURLToPath(context.parentURL) : null
        if (parent && excludedPath(parent)) parentLoadedExcluded.push({ parent: path.relative(root, parent), specifier })
        const entry = failClosedModule(file)
        const importer = parent ? path.relative(root, parent) : null
        if (!entry.importers.some((i) => i.importer === importer && i.specifier === specifier)) entry.importers.push({ importer, specifier })
        return { url: pathToFileURL(path.join(root, entry.generated)).href, format: 'commonjs', shortCircuit: true }
    },
})

process.on('exit', (code) => {
    const state = globalThis.__excludedBoundary || { reads: [], calls: [] }
    const report = {
        exitCode: code,
        excludedSegmentRegex: String(EXCLUDED_SEGMENT),
        replacedModules: [...replaced.values()].sort((a, b) => a.module.localeCompare(b.module)),
        cantonAllowedModules: [...CANTON_PURE_ALLOWLIST].sort(),
        reads: state.reads,
        calls: state.calls,
        excludedModuleLoadedFromExcludedParent: parentLoadedExcluded,
        unresolvedStarExports,
        pnpmFallbacks,
    }
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n')
    console.error(`EXCLUDED_BOUNDARY replaced=${report.replacedModules.length} reads=${state.reads.length} calls=${state.calls.length} pnpmFallbacks=${pnpmFallbacks.length}`)
})
