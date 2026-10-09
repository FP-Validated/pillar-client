# Base images are pinned by digest, and the builder uses the Rust release CI tests with.
# Refresh with: docker buildx imagetools inspect rust:1.98.1-bookworm
FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --locked --release -p pillar-cli --bin pillar

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime

ARG PILLAR_IMAGE_VERSION=unknown
ENV PILLAR_IMAGE_VERSION=${PILLAR_IMAGE_VERSION}
ENV SERVER_PORT=8080

# The immutable revision distinguishes build provenance from runtime configuration.
ARG VCS_REVISION=unknown
LABEL org.opencontainers.image.title="pillar" \
      org.opencontainers.image.description="LayerZero DVN client" \
      org.opencontainers.image.source="https://github.com/FP-Validated/pillar-client" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${PILLAR_IMAGE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REVISION}"

# No package install in the runtime stage: the CA bundle comes from the digest-pinned
# builder, and the healthcheck is the binary itself rather than curl.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin pillar

COPY --from=builder /app/target/release/pillar /usr/local/bin/pillar

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/pillar", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/pillar"]
