# Base images are pinned by digest so a rebuild of a given tag is reproducible.
# Refresh with: docker buildx imagetools inspect rust:1-bookworm
FROM rust:1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --locked --release -p pillar-cli --bin pillar

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime

ARG PILLAR_IMAGE_VERSION=unknown
ENV PILLAR_IMAGE_VERSION=${PILLAR_IMAGE_VERSION}
ENV SERVER_PORT=8080

# A signing service has to be traceable to the commit it was built from. The
# tag alone is not evidence: it can be moved, and it is not what the runtime
# reports. `GET /version` echoes PILLAR_IMAGE_VERSION, and the label below
# survives independently of both the tag and the Deployment's environment.
ARG VCS_REVISION=unknown
LABEL org.opencontainers.image.title="pillar" \
      org.opencontainers.image.description="LayerZero DVN client" \
      org.opencontainers.image.source="https://github.com/FP-Validated/pillar-client" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${PILLAR_IMAGE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REVISION}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin pillar

COPY --from=builder /app/target/release/pillar /usr/local/bin/pillar

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${SERVER_PORT}/ready" || exit 1

ENTRYPOINT ["/usr/local/bin/pillar"]
