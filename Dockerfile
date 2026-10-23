FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
# Cache dependencies separately; remove the placeholder package before real sources.
RUN mkdir src && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --locked --release \
    && cargo clean --release --package bloc
COPY src ./src
COPY templates ./templates
COPY assets ./assets
COPY migrations ./migrations
RUN cargo build --locked --release

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
ARG REVISION
ARG VERSION=0.0.1
LABEL org.opencontainers.image.source="https://github.com/rodalladea/bloc" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="bloc"
COPY --from=build /build/target/release/bloc /usr/local/bin/bloc
COPY LICENSE THIRD_PARTY_NOTICES.md assets/vendor/htmx-LICENSE /usr/share/licenses/bloc/
USER 65532:65532
ENV BLOC_BIND_ADDR=0.0.0.0:3000 RUST_LOG=info
EXPOSE 3000
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/bloc"]
