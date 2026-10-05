// Runs upstream's own tonTransactionTraceMessagesQuorumFn over the recorded mainnet
// TON trace and over variants that change only trace metadata or one security-relevant
// message field. The {transaction, children} tree is assembled here from the /events
// response's `trace` and `transactions`, the same shape TonClient3 hands the quorum fn.
// Input: crates/pillar-runtime/tests/gasolina_parity/source_replay/ton-v3-events.response.json
const fs = require('fs')
const { tonTransactionTraceMessagesQuorumFn } = require('/tmp/gasolina-run/work/migrated/offchain-monorepo/packages/multiprovider/src/ton.ts')

const response = JSON.parse(fs.readFileSync(process.env.TON_EVENTS_RESPONSE, 'utf8'))
const item = (response.traces ?? response.events)[0]
const tree = (node = item.trace) => ({
    transaction: item.transactions[node.tx_hash],
    children: node.children.map((child) => tree(child)),
})
const controllerBound = (trace) => {
    const found = []
    const walk = (node) => {
        if (node.transaction.in_msg?.opcode === '0xe33b9873') found.push(node.transaction)
        node.children.forEach(walk)
    }
    walk(trace)
    return found[0]
}

const variants = {
    recorded: () => {},
    metadataOnly: (trace) => {
        const walk = (node) => {
            node.transaction.finality = 'pending'
            node.transaction.emulated = true
            node.transaction.account_state_after = { hash: 'changed' }
            node.transaction.total_fees = '1'
            node.children.forEach(walk)
        }
        walk(trace)
    },
    seqnoAsNumber: (trace) => { const t = controllerBound(trace); t.mc_block_seqno = Number(t.mc_block_seqno) },
    seqnoStringVsNumber: (trace) => { const t = controllerBound(trace); t.mc_block_seqno = Number(t.mc_block_seqno) },
    seqnoChanged: (trace) => { const t = controllerBound(trace); t.mc_block_seqno = Number(t.mc_block_seqno) + 1 },
    missingInMsg: (trace) => { delete controllerBound(trace).in_msg },
    nullInMsg: (trace) => { controllerBound(trace).in_msg = null },
    missingTransaction: (trace) => { delete trace.transaction },
    missingChildren: (trace) => { delete trace.children },
    nonArrayChildren: (trace) => { trace.children = null },
    missingMessageContent: (trace) => { delete controllerBound(trace).in_msg.message_content },
    missingBody: (trace) => { delete controllerBound(trace).in_msg.message_content.body },
    bodyChanged: (trace) => {
        const t = controllerBound(trace)
        const raw = Buffer.from(t.in_msg.message_content.body, 'base64')
        raw[raw.length - 1] ^= 1
        t.in_msg.message_content.body = raw.toString('base64')
    },
    sourceChanged: (trace) => { const t = controllerBound(trace); t.in_msg.source = '0:' + '11'.repeat(32).toUpperCase() },
    destinationChanged: (trace) => { const t = controllerBound(trace); t.in_msg.destination = '0:' + '22'.repeat(32).toUpperCase() },
    hashChanged: (trace) => { const t = controllerBound(trace); t.in_msg.hash = 'AAAA' + t.in_msg.hash.slice(4) },
    bouncedNull: (trace) => { const t = controllerBound(trace); t.in_msg.bounced = null },
    bouncedTrue: (trace) => { const t = controllerBound(trace); t.in_msg.bounced = true },
    opcodeNull: (trace) => { const t = controllerBound(trace); t.in_msg.opcode = null },
    opcodeDecimal: (trace) => { const t = controllerBound(trace); t.in_msg.opcode = '3812333683' },
    childDropped: (trace) => { trace.children = trace.children.slice(0, -1) },
}

const out = {}
for (const [name, mutate] of Object.entries(variants)) {
    const trace = JSON.parse(JSON.stringify(tree()))
    mutate(trace)
    try {
        out[name] = { fingerprint: tonTransactionTraceMessagesQuorumFn(trace) }
    } catch (error) {
        out[name] = { error: String(error && error.message || error), errorClass: error?.constructor?.name ?? typeof error }
    }
}
process.stdout.write(JSON.stringify({
    provenance: {
        upstream: 'Gasolina 1.2.66 source snapshot',
        entrypoint: 'packages/multiprovider/src/ton.ts:tonTransactionTraceMessagesQuorumFn',
        input: 'recorded mainnet events response for tx 0xec1bd845…, offline',
    },
    variants: out,
}, null, 2) + '\n')
