# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the GeistScope tool suite.
#
# Stage 1 builds every workspace binary in release mode and strips them.
# Stage 2 is a slim Debian runtime carrying ca-certificates plus all the
# binaries on $PATH. Default entrypoint is mg-harness — chat REPL when called
# with `chat`, or single-shot endpoint dispatch via `dispatch` / stdin.

FROM rust:1-bookworm AS builder

WORKDIR /build

# Copy only the crates workspace; tests/ and docs are not needed for the build
COPY crates ./crates

WORKDIR /build/crates
RUN cargo build --workspace --release --locked

# Strip everything down — keeps the final image ~150–250 MB depending on arch
RUN find target/release -maxdepth 1 -type f -executable \
        ! -name '*.so' ! -name '*.d' ! -name '*.rlib' \
        -exec strip {} +

# ---------------------------------------------------------------------------

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy each known workspace binary by name — being explicit avoids accidentally
# shipping cargo's build-script intermediates (.d files, fingerprint dirs, …)
COPY --from=builder /build/crates/target/release/mg-* /usr/local/bin/
COPY --from=builder /build/crates/target/release/ai-prioritize /usr/local/bin/
COPY --from=builder /build/crates/target/release/corpus-builder /usr/local/bin/
COPY --from=builder /build/crates/target/release/subdomain-enum /usr/local/bin/

# Engagements workspace lives here; mount a host directory for persistence
ENV MG_ENGAGEMENTS_DIR=/workspace/engagements
RUN mkdir -p /workspace/engagements
WORKDIR /workspace

# `docker run … chat <engagement>` works because mg-harness is the entrypoint
ENTRYPOINT ["mg-harness"]
CMD ["--help"]
