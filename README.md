# pubky-dispatch-push-relay

Standalone reference push notification relay for **Pubky Dispatch**.

`pubky-dispatch-push-relay` bridges Pubky Dispatch servers and mobile push gateways (Apple APNs HTTP/2 and Firebase Cloud Messaging HTTP v1) without storing message contents or Pubky identities.

---

## Privacy Model (Spec §15)

Pubky Dispatch separates inbox hosting from mobile push delivery so neither server sees the whole picture.

### What the relay learns

- **Handle bindings:** For each registered device, the relay stores `handle -> (platform, device_token, push_key, apns_env, created_at_ms, last_active_at_ms)`.
- **Same-registration grouping:** Multiple handles registered under the same `push_key` are visible as belonging to the same Dispatch push registration (for example, multiple devices for one app installation).
- **Wake timing and volume:** When Dispatch posts a valid webhook to `/v1/hook`, the relay observes which opaque handle was woken and at what time.
- **Transport metadata:** During `POST /v1/register`, the relay derives a client IP bucket (IPv4 `/32` or IPv6 `/64`) and hashes it with SHA-256 strictly for in-window rate limiting. On `POST /v1/hook`, the calling Dispatch server's IP is visible at the TCP/proxy layer; the relay does not record or log it.

### What the relay does NOT learn

- **No Pubky identities or profiles:** The relay never accepts, resolves, or stores any Pubky public key, identity, contact list, or user account.
- **No App IDs or message contents:** Webhooks carry only `{ v, handle, ts, nonce }`. The relay sees zero message payloads, senders, recipients, or event types.
- **No Dispatch credentials or plaintext:** The relay holds only the public half of each registration's `push_key` and never calls back to any Dispatch server.

### Provider timeout and what a wallet sees

Upstream APNs and FCM calls are bounded strictly below Pubky Dispatch's 5-second webhook timeout (`PROVIDER_TIMEOUT_MS`, default `3500` ms, maximum `4500` ms). If a provider does not answer in time, the relay responds `502`, preserves the handle, and Dispatch retries once with a fresh nonce. If the provider accepted the original push just after the relay's timeout elapsed, **a wallet may observe at most one duplicate wake** for that message; syncing from Dispatch is already idempotent.

---

## HTTP API

All JSON request bodies are capped at 16 KiB (`413 too_large`), parsed strictly (no UTF-8 BOM, no duplicate keys, safe integers `0..=2^53 - 1`, no trailing bytes), and guarded by a per-request deadline (`REQUEST_TIMEOUT_MS`, `408 request_timeout`) and concurrency semaphore (`MAX_CONCURRENT_REQUESTS`, `503 unavailable`).

### `POST /v1/register`

Registers a mobile device push token bound to the Ed25519 `push_key` minted by a user's Pubky Dispatch server.

**Request**

```http
POST /v1/register HTTP/1.1
Content-Type: application/json

{
  "platform": "apns",
  "device_token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "push_key": "L6IOM-v3HiTYgBIMYK5KXA6oVE6lcRcBsruRMkqbGjI",
  "apns_env": "production"
}
```

| Field | Type | Required | Constraints |
|---|---|---|---|
| `platform` | `"apns" \| "fcm"` | yes | Target mobile push gateway. |
| `device_token` | `string` | yes | 1..=4096 bytes, no whitespace or control chars. `apns`: even-length ASCII hex (`32..=512` chars). `fcm`: printable ASCII (`0x21..=0x7E`, `1..=4096` chars). |
| `push_key` | `b64(32)` | yes | Unpadded base64url (43 chars) encoding a canonical, non-small-order Ed25519 public key. |
| `apns_env` | `"production" \| "sandbox"` | no | Permitted only when `platform == "apns"` (defaults to `APNS_DEFAULT_ENV`, default `production`). Rejected with `400` for `fcm`. |

Unknown fields are rejected (`400`).

**Response (`200 OK`)**

```json
{
  "handle": "iUsOsTv5mB7OMLMdQZi8QA"
}
```

**Semantics, Idempotency, and Lifecycle**

- **Fresh random handles:** A new `(platform, device_token, push_key, apns_env)` tuple receives a fresh 128-bit cryptographically random opaque handle (`b64(16)`, 22 base64url chars).
- **Idempotent re-registration:** Re-submitting the exact same active `(platform, device_token, push_key, apns_env)` tuple returns the existing handle and refreshes its `last_active_at_ms`.
- **No handle redirection:** Registering a different `device_token`, `platform`, `apns_env`, or `push_key` always allocates a distinct handle and never overwrites or redirects an existing handle.
- **No unauthenticated delete endpoint:** Because `POST /v1/register` carries no device ownership proof or user account, there is intentionally no unauthenticated `DELETE` endpoint (otherwise anyone who observed a handle or device token could revoke a device's push delivery). Stale rows are cleaned up through three mechanisms:
  1. Idempotent re-registration (avoids creating duplicate rows when apps re-register on launch).
  2. Token-specific dead-token pruning on webhook delivery (APNs `410 Unregistered` / `400 BadDeviceToken`; FCM `UNREGISTERED` / token-specific `INVALID_ARGUMENT`).
  3. Automatic inactivity expiry after `REGISTRATION_TTL_DAYS` (default `90` days) with no valid webhook activity.

**Error Responses**

| HTTP Status | Error `code` | Meaning |
|---|---|---|
| `400` | `bad_request` | Malformed JSON, unknown fields, invalid `device_token`, invalid/small-order `push_key`, or `apns_env` supplied for `fcm`. |
| `408` | `request_timeout` | Client stalled while sending the request body past `REQUEST_TIMEOUT_MS`. |
| `413` | `too_large` | Body exceeded 16 KiB. |
| `429` | `rate_limited` | Per-IP (`REGISTER_IP_RATE_LIMIT_PER_MINUTE`), per-`push_key` (`REGISTER_KEY_RATE_LIMIT_PER_MINUTE`), or global (`REGISTER_RATE_LIMIT_PER_MINUTE`) limit exceeded. Includes `Retry-After` header and `retry_after` JSON field. |
| `429` | `quota_exceeded` | Active handles bound to this `push_key` reached `MAX_HANDLES_PER_PUSH_KEY` (default `32`). Existing handles are never evicted. |
| `503` | `unavailable` | Global `MAX_REGISTRATIONS` cap reached or server concurrency limit (`MAX_CONCURRENT_REQUESTS`) exceeded. |
| `500` | `internal_error` | Storage or CSPRNG failure. |

---

### `POST /v1/hook`

Called by a Pubky Dispatch server when a notifying entry or wake-eligible connect request arrives for an app.

**Request**

```http
POST /v1/hook HTTP/1.1
Content-Type: application/json
Dispatch-Signature: <b64(64)>

{"v":1,"handle":"iUsOsTv5mB7OMLMdQZi8QA","ts":"2026-01-01T00:06:00.000Z","nonce":"vX9AwGixjY0MiVA86rs3Gw"}
```

**Signature Input**

`Dispatch-Signature` carries an unpadded base64url 64-byte Ed25519 signature over length-prefixed concatenation (`lp(x1, ..., xn) = u32_be(len(x1)) || x1 || ...`):

```text
lp("pubky-dispatch/v1/push", relay_origin, raw_body_bytes)
```

- `relay_origin` is the configured `https://<host>` origin without port or path, preserving exact host casing as written in the relay URL (Wire Format §8.2).
- `raw_body_bytes` are the exact HTTP request body bytes received on the wire (never reserialized). Unknown JSON fields are ignored per Wire Format §1.1.

**Enforcement Order (Wire Format §8.3)**

Every webhook is validated strictly in order:

1. **Body validity (`400 bad_request`)** — Strict JSON with `v == 1`, string `handle`, RFC 3339 UTC `ts`, and canonical `b64(16)` `nonce`.
2. **Known active handle (`404 not_found`)** — `handle` must exist and not be past its inactivity TTL (any unknown string handle, including empty or control-character strings, yields `404`).
3. **Signature (`401 bad_signature`)** — Single `Dispatch-Signature` header passing strict four-step Ed25519 verification (`S < L`, canonical `A` and `R`, neither small-order, cofactorless `[S]B - [k]A == R`) with the `push_key` bound to the handle.
4. **Timestamp window (`401 stale_timestamp`)** — `ts` within inclusive ±5 minutes of the relay's clock.
5. **Replay protection (`409 nonce_replay` / `503 unavailable`)** — `nonce` unseen within the last 10 minutes. Nonces are recorded only after signature verification, persisted across restarts/failovers, and never evicted while still live (when full, new webhooks receive `503` while live replays still return `409`).
6. **Per-handle rate limit (`429 rate_limited`)** — Sliding 1-minute per-handle limit returning `Retry-After` header and `retry_after` JSON field.

**Delivery Responses**

- `200 OK` `{"delivered":true}` — Wake push accepted by APNs/FCM.
- `200 OK` `{"delivered":false,"pruned":true}` — Upstream reported token-specific permanent rejection (`410 Unregistered` or `400 BadDeviceToken` on APNs; `UNREGISTERED` or token-specific `400 INVALID_ARGUMENT` on FCM); handle was deleted so subsequent hooks return `404`.
- `502 upstream_error` — Any non-token upstream error, timeout, or active `Retry-After` backoff (handle is kept; Dispatch server retries).
- `503 unavailable` — Push backend not configured for the handle's platform, replay store at live-nonce capacity, or server at concurrency cap.

---

### Health & Metrics Endpoints

- `GET /health` and `GET /health/ready` — Readiness probe checking **both** database connectivity (`SELECT 1`) and configured push provider credential/signing readiness. Returns `200 {"status":"ok"}` when ready, `503 {"status":"unhealthy"}` if either storage or provider credentials fail. Stays outside the `/v1/*` concurrency semaphore.
- `GET /health/live` — Liveness probe returning `200 {"status":"ok"}` while the HTTP server loop is alive.
- `GET /metrics` — Exposed only when `METRICS_BIND_ADDR` is configured (intended for a loopback/internal interface, separate from public traffic). Exports Prometheus text format (`0.0.4`) with strictly closed enum labels (never device tokens, handles, push keys, or client IPs):
  - `push_relay_webhooks_total{outcome=...}` (`bad_request`, `unknown_handle`, `bad_signature`, `stale_timestamp`, `nonce_replay`, `replay_capacity_exceeded`, `rate_limited`, `delivered`, `pruned`, `upstream_failure`, `provider_timeout`, `provider_backoff`, `internal_error`)
  - `push_relay_registrations_total{outcome=...}` (`created`, `existing`, `bad_request`, `rate_limited_ip`, `rate_limited_key`, `rate_limited_global`, `quota_exceeded`, `capacity_exceeded`, `internal_error`)
  - `push_relay_provider_latency_seconds{platform="apns"|"fcm",outcome="delivered"|"pruned"|"error"|"timeout"|"backoff"}`

---

## Mobile Client Integration

Mobile apps follow the three-step Pubky Dispatch push flow:

1. **Start registration with Pubky Dispatch:** Call `PUT /v1/{identity}/push` on the user's Dispatch server with `relay_url` (e.g. `https://push.example.com/v1/hook`) and `handles: []`. Dispatch mints a registration-scoped Ed25519 `push_key` and returns its 32-byte public key (`b64(32)`).
2. **Register each device token with this relay:** Send `POST https://push.example.com/v1/register` with `platform`, `device_token`, `push_key`, and optional `apns_env`:
   - **iOS (APNs):** Hex-encode the device token bytes (`64` lowercase hex chars). Pass `"apns_env": "sandbox"` for debug/Xcode builds and `"apns_env": "production"` for TestFlight/App Store builds.
     - By default (`APNS_PUSH_MODE=alert`, required by Spec §9), the relay delivers a content-free generic visible notification (`apns-push-type: alert`, `apns-priority: 10`, `apns-collapse-id: pubky-dispatch-wake`, `mutable-content: 1`, fixed generic text `{"title":"New notification","body":"Open the app to view."}`) so an iOS Notification Service Extension can peek and decrypt locally without iOS silent-push throttling.
     - Silent background wakes (`APNS_PUSH_MODE=background`, `apns-push-type: background`, `apns-priority: 5`, `{"aps":{"content-available":1}}`) are an explicit opt-in; iOS throttles or drops silent pushes under Low Power Mode and background energy budgets.
   - **Android (FCM):** Pass the Firebase registration token with `"platform": "fcm"` and omit `apns_env`. The relay delivers a high-priority data-only HTTP v1 message (`{"data":{"type":"wake","v":"1"},"android":{"collapse_key":"pubky-dispatch-wake","priority":"HIGH"}}`) with no `notification` block so `FirebaseMessagingService.onMessageReceived` runs in background/Doze mode and coalesces offline bursts.
3. **Commit handles to Pubky Dispatch:** Call `PUT /v1/{identity}/push` with `relay_url`, `push_key`, and the app's active handle list (Dispatch enforces up to 8 handles per relay host per identity; the relay defaults `MAX_HANDLES_PER_PUSH_KEY` to `32` so OS token rotations do not lock out active devices before expiry).

Whenever iOS or Android rotates a device token, call `POST /v1/register` again with the current `push_key` and update Dispatch's handle list. Calling `POST /v1/register` again with the unchanged token and `push_key` safely returns the existing handle.

---

## Configuration

Every option below may be configured via environment variable (and CLI flag except inline credential secrets, which are environment-only so they never appear in `--help` or process command lines).

| Environment Variable | CLI Flag | Default | Description / Constraints |
|---|---|---|---|
| `RELAY_ORIGIN` | `--relay-origin` | *(required)* | Exact `https://<host>` origin verified in webhook signatures (no port, path, query, or userinfo; preserves host casing). |
| `RELAY_BIND_ADDR` | `--bind-addr` | `0.0.0.0:8080` | TCP socket address for public API and health probes. |
| `METRICS_BIND_ADDR` | `--metrics-bind-addr` | *(unset)* | Optional separate socket address for Prometheus `GET /metrics` (e.g. `127.0.0.1:9090`). Disabled when unset. |
| `DATABASE_URL` | `--database-url` | `./data/push-relay.sqlite` | `postgres://` or `postgresql://` selects PostgreSQL; any other path/URL (`sqlite://...`, `:memory:`) selects SQLite. Value hidden from `--help` and `Debug`. |
| `RATE_LIMIT_PER_MINUTE` | `--rate-limit-per-minute` | `60` | Maximum webhooks per handle per rolling 60 s window (`429`). |
| `REGISTER_IP_RATE_LIMIT_PER_MINUTE` | `--register-ip-rate-limit-per-minute` | `10` | Maximum `POST /v1/register` requests per client IP bucket per 60 s (`429`). |
| `REGISTER_KEY_RATE_LIMIT_PER_MINUTE` | `--register-key-rate-limit-per-minute` | `20` | Maximum `POST /v1/register` requests per `push_key` per 60 s (`429`). |
| `REGISTER_RATE_LIMIT_PER_MINUTE` | `--register-rate-limit-per-minute` | `120` | Global maximum `POST /v1/register` requests per 60 s (`429`). |
| `MAX_HANDLES_PER_PUSH_KEY` | `--max-handles-per-push-key` | `32` | Maximum active handles per `push_key` (`429 quota_exceeded`; never evicts). |
| `MAX_REGISTRATIONS` | `--max-registrations` | `1000000` | Maximum total active registrations before returning `503`. |
| `REGISTRATION_TTL_DAYS` | `--registration-ttl-days` | `90` | Days without a valid webhook before a registration expires (`>= 1`). |
| `NONCE_CACHE_MAX_ENTRIES` | `--nonce-cache-max-entries` | `100000` | Maximum live nonces retained in replay storage (`>= 1`; returns `503` when full). |
| `PROVIDER_TIMEOUT_MS` | `--provider-timeout-ms` | `3500` | Upstream APNs/FCM timeout in ms (`100..=4500`, strictly below Dispatch's 5000 ms timeout). |
| `REQUEST_TIMEOUT_MS` | `--request-timeout-ms` | `4500` | Overall `/v1/*` request deadline in ms (`>= 100`, slow-client protection). |
| `MAX_CONCURRENT_REQUESTS` | `--max-concurrent-requests` | `256` | Maximum concurrent `/v1/*` requests before shedding with `503` (`>= 1`). |
| `TRUSTED_PROXIES` | `--trusted-proxies` | `""` (empty) | Comma-separated CIDRs/IPs of reverse proxies trusted to supply forwarded client IP headers. Empty trusts no forwarded headers. |
| `TRUSTED_PROXY_HEADER` | `--trusted-proxy-header` | `x-forwarded-for` | Header inspected when TCP peer is in `TRUSTED_PROXIES`. |
| `PUSH_BACKEND` | `--push-backend` | `providers` | `providers` (APNs/FCM) or `noop` (local dev without mobile credentials). |
| `LOG_FORMAT` | `--log-format` | `json` | `json` or `pretty`. Filter level via `RUST_LOG` (default `pubky_dispatch_push_relay=info`). |
| `APNS_TEAM_ID` | `--apns-team-id` | *(unset)* | 10-character Apple Developer Team ID (`iss`). |
| `APNS_KEY_ID` | `--apns-key-id` | *(unset)* | 10-character APNs Auth Key ID (`kid`). |
| `APNS_BUNDLE_ID` | `--apns-bundle-id` | *(unset)* | iOS app bundle identifier (`apns-topic`). |
| `APNS_KEY_PATH` | `--apns-key-path` | *(unset)* | Path to APNs `.p8` PKCS#8 PEM file (mutually exclusive with `APNS_KEY_PEM`; Unix mode must be `0600` or stricter). |
| `APNS_KEY_PEM` | *(env only)* | *(unset)* | Inline APNs `.p8` PEM or base64-encoded PEM. |
| `APNS_DEFAULT_ENV` | `--apns-default-env` | `production` | Default APNs gateway (`production` or `sandbox`) when `apns_env` is omitted. |
| `APNS_PUSH_MODE` | `--apns-push-mode` | `alert` | `alert` (Spec §9 visible notification default) or `background` (opt-in silent wake; throttled by iOS). |
| `FCM_SERVICE_ACCOUNT_PATH` | `--fcm-service-account-path` | *(unset)* | Path to Google service account JSON file (mutually exclusive with `FCM_SERVICE_ACCOUNT_JSON`; Unix mode must be `0600` or stricter). |
| `FCM_SERVICE_ACCOUNT_JSON` | *(env only)* | *(unset)* | Inline Google service account JSON or base64-encoded JSON. |

---

## Safe Deployment Guide

### 1. TLS Termination

The relay serves plain HTTP on `RELAY_BIND_ADDR`. Always terminate TLS 1.2/1.3 at a reverse proxy or ingress controller (nginx, Envoy, Caddy, cloud load balancer) serving `RELAY_ORIGIN`:

- Forward traffic to `RELAY_BIND_ADDR` over loopback or an isolated private network.
- Configure `RELAY_ORIGIN` to the exact `https://<host>` that Dispatch servers call (preserving host casing).
- Disable client-IP access logging on `/v1/hook` at the proxy to preserve Dispatch server privacy.
- Do **not** expose `METRICS_BIND_ADDR` to the public internet; bind it to `127.0.0.1:9090` or an internal cluster-only network policy.

### 2. Trusted Proxy Headers

Per-IP rate limiting on `POST /v1/register` defaults to the direct TCP peer socket address (`TRUSTED_PROXIES=""`).

- When running behind a reverse proxy, set `TRUSTED_PROXIES` to the exact CIDR(s) or IP(s) of your proxy hop(s) (for example `TRUSTED_PROXIES=10.0.0.0/8,127.0.0.1/32`).
- **Never** configure `TRUSTED_PROXIES=0.0.0.0/0` or `::/0`; doing so allows any client to spoof `X-Forwarded-For` and bypass per-IP rate limits.
- When the TCP peer is trusted, the relay walks `TRUSTED_PROXY_HEADER` (default `x-forwarded-for`) **right-to-left**, discarding trusted proxy hops and selecting the rightmost untrusted client address. IPv6 clients are bucketed by `/64`, and all addresses are SHA-256 hashed before hitting rate-limit storage.
- Pair application-level registration limits with edge/WAF rate limiting on `POST /v1/register`.

### 3. Verified Database TLS (PostgreSQL)

When deploying with PostgreSQL over any non-loopback network, enforce certificate verification in `DATABASE_URL` (`sqlx` uses `rustls` with WebPKI roots):

```text
DATABASE_URL=postgres://relay:<password>@pg.internal:5432/push_relay?sslmode=verify-full&sslrootcert=/etc/relay/pg-ca.crt
```

Do not use `sslmode=disable` outside local loopback testing, and inject `DATABASE_URL` via a secret manager / environment variable rather than CLI flags.

### 4. Credential File Permissions

Prefer mounting APNs `.p8` and FCM service account JSON files as read-only secrets owned by the relay user (`nonroot`, UID `65532` in the container image) with mode `0600` (`chmod 0600` or `0400`):

- On Unix, the relay inspects permissions on the opened file descriptor and **refuses to start** if group or world bits are set (`mode & 0o077 != 0`).
- Both APNs P-256 and FCM RSA (`>= 2048` bits) keys are parsed and self-tested at startup so invalid or undersized keys fail before serving traffic.
- Inline credentials (`APNS_KEY_PEM`, `FCM_SERVICE_ACCOUNT_JSON`) are read only from environment variables into zeroizing buffers and are never accepted on the command line.

### 5. Scaling Matrix (SQLite vs PostgreSQL)

Schema updates are managed via versioned, SHA-256 checksum-verified SQL migrations under `migrations/sqlite/` and `migrations/postgres/` recorded in `schema_migrations` (serialized under `BEGIN IMMEDIATE` on SQLite and `pg_advisory_xact_lock` on PostgreSQL).

| State | SQLite (single instance) | PostgreSQL (multi-replica) |
|---|---|---|
| `registrations` (handles, caps, TTL) | Durable WAL SQLite (`STRICT`) | Shared WAL-logged PostgreSQL table (atomic `pg_advisory_xact_lock`) |
| `webhook_nonces` (10-minute replay) | Durable WAL SQLite (`boot_id` + wall & monotonic expiry; survives restart; `503` when full) | Shared WAL-logged PostgreSQL table using DB `clock_timestamp()` (immune to replica clock skew/failover; `503` when full) |
| Rate limits (hook + register IP/key/global) | Instance-local bounded in-memory sliding windows (fail-closed) | Shared WAL-logged PostgreSQL `rate_limit_buckets` using DB `clock_timestamp()` |
| Provider JWT / OAuth2 token cache | Instance-local (with generation-guarded refresh) | Instance-local per replica (with generation-guarded refresh) |
| Provider `Retry-After` backoff | Instance-local monotonic backoff | Instance-local per replica (each replica backs off on upstream `429`/`503`) |
| Concurrency cap (`MAX_CONCURRENT_REQUESTS`) | Instance-local semaphore | Instance-local per replica |
| Prometheus `/metrics` counters & histograms | Instance-local (scraped per instance) | Instance-local per replica (aggregated by Prometheus) |

**Do not** point multiple replicas at the same SQLite file; use PostgreSQL whenever running more than one replica.

### Local Development & Container Usage

```bash
# Local development with no-op push sender
RELAY_ORIGIN=https://push.example \
PUSH_BACKEND=noop \
LOG_FORMAT=pretty \
DATABASE_URL=:memory: \
METRICS_BIND_ADDR=127.0.0.1:9090 \
cargo run
```

```bash
# Build and run distroless non-root container (PostgreSQL multi-replica example)
docker build -t pubky-dispatch-push-relay .

docker run --rm -p 8080:8080 -p 127.0.0.1:9090:9090 \
  -v /run/secrets/apns.p8:/run/secrets/apns.p8:ro \
  -v /run/secrets/fcm.json:/run/secrets/fcm.json:ro \
  -e RELAY_ORIGIN=https://push.example.com \
  -e METRICS_BIND_ADDR=0.0.0.0:9090 \
  -e DATABASE_URL="postgres://relay:secret@pg.internal:5432/push_relay?sslmode=verify-full" \
  -e TRUSTED_PROXIES="10.0.0.0/8" \
  -e APNS_TEAM_ID=TEAM123456 \
  -e APNS_KEY_ID=KEY1234567 \
  -e APNS_BUNDLE_ID=com.example.app \
  -e APNS_KEY_PATH=/run/secrets/apns.p8 \
  -e FCM_SERVICE_ACCOUNT_PATH=/run/secrets/fcm.json \
  pubky-dispatch-push-relay
```

---

## Security

### What a stolen `push_key` allows

- **Allows:** Signing valid `POST /v1/hook` requests for any handle bound to that `push_key`, causing the relay to deliver content-free wake pushes to those registered devices up to `RATE_LIMIT_PER_MINUTE` (wake spam / battery drain).
- **Does NOT allow:** Reading message contents, learning Pubky identities, reading stored device tokens, triggering handles bound to any other `push_key`, or redirecting existing handles to different tokens. Rotating the `push_key` in Dispatch and re-registering devices cuts off the compromised key.

### What a stolen relay database allows

- **Allows:** Reading the `registrations` table (`handle`, `platform`, `device_token`, public `push_key`, `apns_env`, timestamps), recent 10-minute nonces, and rate-limit buckets. An attacker can correlate devices that share a `push_key` and inspect device tokens.
- **Does NOT allow:** Forging webhooks to the relay (requires the Dispatch server's private `push_key`), sending direct APNs or FCM notifications to those device tokens (requires the relay's Apple `.p8` key or Google service account private key, which are never stored in the database), or identifying any Pubky user or reading message payloads.

### What the relay must never log

Structured logs, `Debug` implementations, `--help` output, error responses, and Prometheus metric labels must **never** contain:

- Mobile `device_token` values
- Opaque push `handle` values
- `push_key` public keys or webhook `Dispatch-Signature` values
- APNs `.p8` private keys, APNs bearer JWTs, FCM service account private keys, or Google OAuth2 access tokens
- `DATABASE_URL` passwords or credentials
- Raw client or Dispatch server IP addresses
- Arbitrary upstream provider error message strings (only fixed error classes such as `apns_unregistered`, `http_5xx`, `timeout`, or `backoff` are logged)

---

## Development & Verification

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo audit
```

Run the PostgreSQL and multi-replica integration suite locally against a PostgreSQL instance:

```bash
TEST_DATABASE_URL=postgres://relay:relay@127.0.0.1:5432/relay_test \
REQUIRE_POSTGRES_TESTS=1 \
cargo test --test postgres --locked
```

## License

MIT — see [LICENSE](LICENSE).
