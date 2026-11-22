# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for acta-server (~25 MB distroless runtime image)

FROM rust:slim-bookworm AS builder

WORKDIR /app

ENV CARGO_NET_RETRY=5 \
    CARGO_HTTP_MULTIPLEXING=false

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config ca-certificates && \
    rm -rf /var/var/lib/apt/lists/* /var/lib/apt/lists/*

# Only download a newer stable toolchain if the base image's rustc is older than MSRV 1.89.
RUN RUST_MINOR="$(rustc --version | awk '{split($2,v,"."); print v[2]}')" && \
    if [ "${RUST_MINOR:-0}" -lt 89 ]; then \
        rustup toolchain install stable --profile minimal && \
        rustup default stable; \
    fi

COPY Cargo.toml Cargo.lock* ./
COPY migrations ./migrations
COPY policies ./policies
COPY crates ./crates

# Cap parallel rustc jobs automatically on <= 10 GB RAM workers (e.g. e2-highcpu-8) to prevent OOM (exit 137).
RUN MEM_KB="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 16777216)" && \
    if [ "${MEM_KB}" -lt 11000000 ]; then \
        export CARGO_BUILD_JOBS=4; \
    fi && \
    if [ -f Cargo.lock ]; then \
        cargo build --release --locked --bin acta-server --bin acta-verify || \
        cargo build --release --bin acta-server --bin acta-verify; \
    else \
        cargo build --release --bin acta-server --bin acta-verify; \
    fi

# Distroless cc-debian12 provides minimal glibc + libgcc_s (~20 MB base)
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/target/release/acta-server /usr/local/bin/acta-server
COPY --from=builder /app/target/release/acta-verify /usr/local/bin/acta-verify
COPY --from=builder /app/policies/default.cedar /etc/acta/policies/default.cedar

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    ACTA_POLICY_PATH=/etc/acta/policies/default.cedar \
    ACTA_BIND_ADDR=0.0.0.0:8080 \
    MIN_CONFIDENCE=0.70 \
    DECISIVENESS_THRESHOLD=0.15 \
    MAX_INLINE_OMISSIONS=25

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/acta-server"]
