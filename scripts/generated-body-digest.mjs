// Shared by the table generators and check-generated-config-integrity.mjs, so the digest a
// generator writes and the digest CI recomputes cannot drift apart.
import { createHash } from 'node:crypto'

export const BODY_DIGEST_PREFIX = '// Body sha256: '

function bodyStart(lines) {
    const start = lines.findIndex((line) => !line.startsWith('//'))
    return start < 0 ? lines.length : start
}

/** The text after the leading `//` header block: the part the body digest covers. */
export function generatedBody(text) {
    const lines = text.split('\n')
    return lines.slice(bodyStart(lines)).join('\n')
}

export function bodyDigest(body) {
    return createHash('sha256').update(body).digest('hex')
}

/** Returns the generator's output lines with the body digest as the last header line. */
export function withBodyDigest(lines) {
    const start = bodyStart(lines)
    const digest = bodyDigest(lines.slice(start).join('\n'))
    return [...lines.slice(0, start), `${BODY_DIGEST_PREFIX}${digest}`, ...lines.slice(start)]
}
