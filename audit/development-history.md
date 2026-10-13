# Development and security history

This is a retrospective reading guide to the original public Git history through
Pillar Client 2.6.2, source commit
[`3f39fba`](https://github.com/FP-Validated/pillar-client/commit/3f39fbad972794e5a9c598ea46a310334a4a4415).
It explains how the delivered work relates to the signing trust boundaries. It is
not an external audit report, certification, or a new account of past approvals.

## Scope and provenance

The public history starts at
[`cfa8564`](https://github.com/FP-Validated/pillar-client/commit/cfa8564b622fa14e40d9bb11a8a6d38f332ceea8),
"Initial public release." That commit imports a complete source snapshot; it is
not the beginning of all internal development. Private development, whether before
or after that baseline, is outside this chronology; its Git ancestry is not imported.

The [task map](development-history.json) groups all 153 commits reachable from the
source baseline into 79 retrospective tasks. Original commits, merge ancestry,
and tags remain authoritative and unchanged. Grouping related corrections or
separating a broad change is an editorial aid, not a replacement for Git evidence.
The map contains canonical source SHAs, not unpublished reconstructed commit IDs.

- **Objective** describes the engineering purpose of a group of changes, inferred
  retrospectively from its implementation and recorded explanations, not an
  original ticket or approval.
- **Delivered** means the change landed in the source history. It does not imply
  that every test, provider configuration, chain pathway, or deployment passed.
- **Verification** is attributed to a specific source and dated report. A release
  commit, passing fixture, or healthy pod is not proof of a live signing path.

Dates below follow the recorded commit author dates in KST. They are not
independently verified publication or deployment timestamps. Later changes can
replace earlier policy; use [SECURITY.md](../SECURITY.md) and the current source
for current behavior. Public commit dates do not establish when work was first
prepared, including for later consolidated changes such as `1f6d0e6`.

## 1. Establish the public baseline and parity evidence

**Period:** August 27-28, 2026.

**Objective:** make the signing path reviewable against source packets and
upstream outputs rather than relying on implementation-generated expectations.

**Delivered:**

- Bounded HTTP/1.1 connection handling and signing-stage/quorum observability.
- Packet-derived signing inputs, EndpointV1 `vId` lookup, and a reachable READ
  path. See
  [`340bf05`](https://github.com/FP-Validated/pillar-client/commit/340bf059a62475afd0b874f621d57465f94d5b20)
  and
  [`64e9638`](https://github.com/FP-Validated/pillar-client/commit/64e9638ee00f8381add89c8997283c65622737c8).
- Upstream-backed fixtures and historical-pathway comparisons through the service
  entrypoint, including the returned signature. See
  [`4820206`](https://github.com/FP-Validated/pillar-client/commit/48202066154c38428a7067cb1450125a13aa1436)
  and
  [`1fc3e4e`](https://github.com/FP-Validated/pillar-client/commit/1fc3e4ed511c343a293c54a30f76cdc60570eb01).
- Refusal of a superseded Stellar destination and removal of failed provider
  votes at that stage:
  [`439a77c`](https://github.com/FP-Validated/pillar-client/commit/439a77c0c41b96ed2dc9a49250c38c9b68f9fe2c).
  The historical refusal is not a statement of current Stellar support.

**Verification boundary:** recorded fixtures establish their particular byte and
behavior comparisons, not every chain or live upstream-service parity. Fixture
provenance and reproduction requirements are described in the
[parity tooling guide](../scripts/gasolina-parity/README.md).

## 2. Harden caller, credential, and HTTP boundaries

**Period:** September 1, 2026.

**Objective:** prevent request-controlled data and diagnostics from crossing
signing, provider-credential, or availability boundaries unchecked.

**Delivered:**

- Service-URL validation and fail-closed outbound path handling:
  [`451f716`](https://github.com/FP-Validated/pillar-client/commit/451f716c7595fc3c4c56533ba2f83b172a925d08).
- The V1 transaction-ID shape gate and caller-error classification introduced at
  that stage:
  [`a137f2d`](https://github.com/FP-Validated/pillar-client/commit/a137f2da3377b85bf6f4a989673d9fbefd75b2be).
- Seed-phrase redaction and zeroization of derived signing material:
  [`05d49b6`](https://github.com/FP-Validated/pillar-client/commit/05d49b6c2ac1cebe026c5c91f8f2a80ed0a1fe1b).
- Cached provider-health reports and a bounded HTTP header phase:
  [`7aa8944`](https://github.com/FP-Validated/pillar-client/commit/7aa894465fef718bf70f9905f89f75dd7773ffee).

**Verification boundary:** these source commits retain their original security
finding identifiers. The seed-storage fix was initially partial; later work
changed storage as well. A historical gate or error classification should not be
assumed to be the current API contract without checking subsequent changes.

## 3. Make operator policy explicit and track Solana compatibility

**Period:** September 3-12, 2026; version updates 2.2.0 and 2.3.0.

**Objective:** make authentication choices explicit while preserving the signer
identity and transaction formats the service advertises and reads.

**Delivered:**

- Separate controls for public signing routes and disabling authentication on all
  routes:
  [`75e9988`](https://github.com/FP-Validated/pillar-client/commit/75e998840c31774a7de93d3ff83a523191d9838f)
  and
  [`cef619a`](https://github.com/FP-Validated/pillar-client/commit/cef619a8b924288235cf0c451d9b1194dc5f1bfc).
- Solana address derivation from the advertised key:
  [`88746eb`](https://github.com/FP-Validated/pillar-client/commit/88746eb2df4c2bfd1cbcbdcfa6016432b0f0a9d9).
- Transaction version 1 support for Solana RPC reads:
  [`d972729`](https://github.com/FP-Validated/pillar-client/commit/d972729b06d705666d147ad45a7be729ddff8e8f).

**Verification boundary:** adding a configuration switch does not establish that
any deployment enabled it. Public-route modes still require the operator's
network-edge controls; see [operator responsibilities](../SECURITY.md).

## 4. Bind validation and execution to the same evidence

**Period:** September 22-23, 2026; version updates 2.4.0 and 2.4.1.

**Objective:** prevent a validated request from being signed against substituted
source evidence, a different block, or an unchecked policy verdict.

**Delivered:**

- Source-receipt binding, receive-library validation, extra-context verdicts, and
  HTTP/logging defenses, followed by corrections to over-broad refusal behavior:
  [`35789ae`](https://github.com/FP-Validated/pillar-client/commit/35789ae41fdda129b17441da024a82b222129921)
  and
  [`68e67df`](https://github.com/FP-Validated/pillar-client/commit/68e67df00d4b84b6a7b206112f391e622c99ee6c).
- Further protection of bearer credentials and mnemonic storage:
  [`7312d74`](https://github.com/FP-Validated/pillar-client/commit/7312d748102837e538bbdd18e73f9e6e3e0384d9).
- READ calls pinned to the block hash validated by readiness, with canonicality
  required and no fallback to a block number:
  [`addf054`](https://github.com/FP-Validated/pillar-client/commit/addf054ca6bedbeb74d331702a1cc1cc41fb5202).

**Verification boundary:** block-hash pinning is a deliberate upstream divergence
and requires EIP-1898 support from configured providers and proxies. Tests of the
pinning logic do not establish that a particular live proxy supports it.

## 5. Introduce bounded execution and durable audit controls

**Period:** October 5-6, 2026. The version update is `d3b2821`; the public
`v2.5.0` tag targets `f5868d0` and includes the CI/readiness fixes described below.

**Objective:** make request resource use, signing effects, provider trust, and
failure evidence explicit and auditable.

**Delivered:**

- Shared execution budgets, a durable signing-attempt audit, provider entity and
  strategy validation, chain-adapter changes, and an acceptance-evidence ledger:
  [`1f6d0e6`](https://github.com/FP-Validated/pillar-client/commit/1f6d0e6f2ce6379f8cdf1aca180fa182a45c3e68).
- Remediation of reported audit findings and isolation of audit readiness probes
  from signing transactions. The original findings and corrective changes are
  recorded in [Audit guide, section 10](../AUDIT.md#10-remediation-and-dated-test-status).
- CI/compiler corrections and regression coverage for expired readiness probes:
  [`f5868d0`](https://github.com/FP-Validated/pillar-client/commit/f5868d0428cf3edb585dca5a396c02e37d3d0ade).

**Verification boundary:** the audit guide preserves both failed CI runs and their
follow-up fixes; this was not an uninterrupted series of green releases. It also
separates disposable PostgreSQL/TLS tests from the Canton live-ledger test that
was not run. The durable audit is not an exactly-once execution guarantee.

## 6. Resolve provider compatibility and release 2.6.0

**Period:** October 8-9, 2026.

**Objective:** preserve valid signing paths while distinguishing provider failure,
source evidence changes, and unsupported requests.

**Delivered:**

- READ observation/refusal policies, resolver ordering and endpoint-ID behavior,
  Sui GraphQL reads, CI toolchain/builder pinning and image-artifact identification,
  landed through
  [`abe9d60`](https://github.com/FP-Validated/pillar-client/commit/abe9d60053ea582f0f0d1d0635f0f80523b5790d)
  and its preceding merges.
- The client-review corrections at
  [`b7fc3ab`](https://github.com/FP-Validated/pillar-client/commit/b7fc3ab41fec6632db69b3d8b33ceab10ff45525),
  including failed EVM receipt rereads classified as unavailable rather than a
  changed source binding.
- The 2.6.0 version update at
  [`09cec5c`](https://github.com/FP-Validated/pillar-client/commit/09cec5c3975aa743abb29f6783b115e0d93d3af6).

**Verification boundary:**
[the client retest](retest-2.6.0.md) and
[Audit guide, section 15](../AUDIT.md#15-2026-10-09-client-review-and-260-release)
record source-specific local/hosted checks and a dated rollout of `b7fc3ab`.
Those records do not establish deployment of later versions or independently
prove current live signing. The original reports are retained, not rewritten to
make this chronology appear uniform.

## 7. Close adversarial review findings and check every event page

**Period:** October 9-10, 2026; version updates 2.6.1 and 2.6.2.

**Objective:** keep malformed provider responses from voting or exhausting process
resources without excluding valid protocol inputs.

**Delivered:**

- Iterative readiness, READ, signer, configuration, and non-EVM corrections;
  bounded TON BoC cell/depth/graph handling and default receive-config
  serialization, plus CI build-provenance attestation and runtime-image hardening.
  Round-specific findings, reversals, and fixes remain in
  [Audit guide, section 16](../AUDIT.md#16-2026-10-09-full-review).
- The 2.6.1 version update:
  [`5aed3a0`](https://github.com/FP-Validated/pillar-client/commit/5aed3a0e6b6d6b7bf023a0cfbc87e5038e5187b2).
- Per-page error handling for Sui GraphQL and IotaL1 JSON-RPC event pagination:
  [`cbd1fa2`](https://github.com/FP-Validated/pillar-client/commit/cbd1fa23777c14382cf08e772ad0a59630142970),
  followed by the 2.6.2 version update at the source baseline.

**Verification boundary:** the audit guide records regression checks and hosted CI
for these specific sources. It is not evidence that every acceptance row or live
chain pathway was exercised. The default suite still skips external-input tests.

## Reading the audit evidence

Use this chronology and the task map to find the original changes, then consult:

- [Audit guide](../AUDIT.md): threat model, reproduction commands, ignored tests,
  dated review/test/deployment reports, and evidence-access limitations.
- [Security policy](../SECURITY.md): current trust boundaries, operator duties,
  upstream divergences, known caveats, and provenance/licensing uncertainty.
- [Changelog](../CHANGELOG.md): version-specific behavior and breaking changes.
- [Acceptance ledger](acceptance/acceptance-rows.md): coverage classifications,
  including incomplete and upstream-unsupported cases; counts are not test totals.

This document adds no new claim of historical verification or production rollout.
It does not replace original commit IDs with a reconstructed history, move release
tags, or publish private development history. Release provenance must be checked
against the original tag target and source tree, not inferred from a commit title.
