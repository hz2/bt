FROM rust:1.76-slim

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

WORKDIR /app

COPY . .

RUN cargo fetch

RUN cargo build --release

CMD ["sh", "-c", "cargo fmt -- --check && cargo clippy --all -- -D warnings && cargo test -- --nocapture"]
