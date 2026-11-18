FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release -p keylite-native
RUN mkdir -p /data

FROM scratch
COPY --from=builder --chown=65532:65532 /src/target/release/keylite-native /keylite-native
COPY --from=builder --chown=65532:65532 /data /data
USER 65532:65532
WORKDIR /data
ENV KEYLITE_DB=/data/keylite.sqlite
ENV KEYLITE_LISTEN=0.0.0.0:8787
ENV KEYLITE_MAX_USERS=0
ENV KEYLITE_MAX_VAULTS_PER_USER=0
EXPOSE 8787
VOLUME ["/data"]
ENTRYPOINT ["/keylite-native"]
