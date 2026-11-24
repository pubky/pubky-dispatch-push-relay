# Standalone Pubky Dispatch reference push relay.
#
# Build:
#   docker build -t pubky-dispatch-push-relay .
#
# Run (local dev with no-op push sender):
#   docker run --rm -p 8080:8080 \
#     -e RELAY_ORIGIN=https://push.example.com \
#     -e PUSH_BACKEND=noop \
#     pubky-dispatch-push-relay

FROM rust:1.91.1-slim-bookworm AS build
WORKDIR /src

COPY Cargo.toml Cargo.lock clippy.toml ./
COPY migrations ./migrations
COPY src ./src

RUN cargo build --release --locked \
    && cp target/release/pubky-dispatch-push-relay /pubky-dispatch-push-relay \
    && mkdir -p /data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /pubky-dispatch-push-relay /usr/local/bin/pubky-dispatch-push-relay
COPY --from=build --chown=65532:65532 /data /var/lib/pubky-dispatch-push-relay

VOLUME ["/var/lib/pubky-dispatch-push-relay"]

ENV RELAY_BIND_ADDR=0.0.0.0:8080
ENV DATABASE_URL=/var/lib/pubky-dispatch-push-relay/push-relay.sqlite
ENV LOG_FORMAT=json

EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/pubky-dispatch-push-relay"]
