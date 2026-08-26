# Contributing

This service holds signing authority. A bug here can produce a valid signature
over an attestation nobody intended, so review here is stricter than the code
size suggests. Please read [SECURITY.md](SECURITY.md) before your first change,
including the [Known caveats](SECURITY.md#known-caveats).

If you think you have found a vulnerability, do not open a pull request or a
public issue. Follow the private reporting process in `SECURITY.md`.

## Before you open a pull request

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo audit
cargo deny check
```

CI runs the same set, plus a build against the MSRV in `rust-version`
(`Cargo.toml`) and a container build that asserts the binary refuses to start
without required configuration. Keep `Cargo.lock` in the commit that changes a
dependency.

Run clippy on the **latest stable** toolchain, not whatever you happen to have
installed. CI uses latest stable with `-D warnings`, so a new release that adds
a lint will fail a pull request that passes on an older compiler:

```bash
rustup update stable
cargo +stable clippy --workspace --all-targets -- -D warnings
```

## Rules that reviewers will hold you to

**Fail closed.** An unsupported `(chain, environment, ULN version)` combination
must return an error. Never fall back to a default address, a default endpoint
id, or a guessed encoding — a wrong signature is worse than a failed request.

**Cite upstream for protocol claims.** Any change that claims parity with the
upstream LayerZero TypeScript implementation must cite the exact upstream
`file:line` in a comment or the commit message. Deployment addresses and
endpoint ids additionally need a cross-check against LayerZero's live metadata
(`metadata.layerzero-api.com/v1/metadata/deployments`). A wrong trusted-emitter
address is a security bug, not a config typo.

**Do not overstate test evidence.** A test that asserts a value recorded in this
repository is named for what it does — `matches_recorded_vector` — not
`matches_ts_golden_vector`. Only call a fixture upstream-reproduced when it was
actually produced by running the upstream implementation, and say where that
output came from.

**Never hand-edit generated files.** `generated_layerzero_evm.rs` and
`generated_layerzero_environment.rs` in `pillar-config` come from the scripts in
`scripts/`. The check after touching a generator is that it reproduces a
byte-identical data region.

Regeneration currently needs a checkout of the upstream TypeScript service
(`PILLAR_AUDIT_ROOT`), which is not public. If your change needs regenerated
tables, open an issue describing the needed change and a maintainer will
regenerate them. Everything else in the workspace builds and tests from a plain
clone with no extra inputs.

**Keep the response envelope.** Every API response is
`{ "statusCode": ..., "body": ... }`. That shape is a compatibility contract
with existing operators; do not "clean it up".

**Keep layers where they are.** `pillar-runtime` is the composition root.
Configuration loading, provider health, LayerZero wiring, validation and signer
assembly belong there, not in `pillar-api` or `pillar-cli`.

**No live network in tests.** Unit tests use fixtures, fakes and recorded
request assertions. A test that reaches a public RPC endpoint will be rejected;
it makes the suite non-deterministic and leaks intent.

## Tests

Name tests for the behaviour they defend, not the function they call:
`rejects_*`, `uses_*`, `matches_recorded_*`, `fails_closed_*`. Async tests use
`#[tokio::test]`. Project tests live inline under `#[cfg(test)]` or in the
`src/tests*.rs` modules that are compiled only for `cargo test`.

Add a test when you change an observable contract or fix a bug — reproduce the
bug first, then fix it. Do not add tests that assert plumbing or source text.

## Commits

Conventional-commit prefixes (`feat:`, `fix:`, `chore:`, `docs:`). Explain why
the change is correct, and state what you ran to verify it. For anything that
touches signing, validation or address resolution, list the verification in the
commit body so it survives in `git log`.

User-visible changes get a `CHANGELOG.md` entry in the same commit.
