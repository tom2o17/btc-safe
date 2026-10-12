# btc-safe API. Build context: repo root. The web app is built by Dockerfile.web.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock clippy.toml ./
COPY crates ./crates
RUN cargo build --release --locked -p btc-safe-api && cp target/release/btc-safe-api /btc-safe-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home app
COPY --from=build /btc-safe-api /usr/local/bin/btc-safe-api
USER app
# Signet only: the binary refuses mainnet and checks the Esplora genesis hash at startup.
ENV CHAIN=esplora NETWORK=signet RUST_LOG=info,sqlx=warn
CMD ["btc-safe-api"]
