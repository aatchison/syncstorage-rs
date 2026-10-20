# Devcontainer image: upstream's toolchain and build packages, baked in at image build time.
# Rust 1.98.1 matches rust-version in Cargo.toml and RUST_VERSION in upstream CI
# (.github/workflows/main-workflow.yml), so fmt and clippy here behave as they do in CI.
FROM mcr.microsoft.com/devcontainers/rust:1-trixie

RUN rustup toolchain install 1.98.1 --profile minimal --component rustfmt --component clippy \
    && rustup default 1.98.1 \
    && rustc --version && cargo clippy --version

# The build dependencies upstream's Dockerfile installs
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        default-libmysqlclient-dev libpq-dev cmake pkg-config libssl-dev python3-dev clang \
    && rm -rf /var/lib/apt/lists/*
