FROM rust:1.76-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install required Rust components
RUN rustup component add rustfmt clippy

# Set working directory
WORKDIR /app

# Copy project source
COPY . .

# Pre-fetch dependencies
RUN cargo fetch

# Build for release
RUN cargo build --release

# Default command: run all checks and tests
CMD ["sh", "-c", "cargo fmt -- --check && cargo clippy --all -- -D warnings && cargo test -- --nocapture"]
