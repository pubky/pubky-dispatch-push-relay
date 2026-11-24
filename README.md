# pubky-dispatch-push-relay

Standalone reference push notification relay for **Pubky Dispatch**.

`pubky-dispatch-push-relay` bridges Pubky Dispatch servers and mobile push gateways (Apple APNs HTTP/2 and Firebase Cloud Messaging HTTP v1) without ever seeing message contents or Pubky identities.

## Architecture & Privacy Model

Pubky Dispatch separates inbox hosting from mobile push credentials:

1. **Identity-free storage.** The relay only stores `handle -> (platform, device_token, push_key, apns_env, created_at)`. It never accepts, resolves, or stores any Pubky identity, App ID, or user profile.
2. **Cryptographic handle binding.** Each `POST /v1/register` call generates a fresh 128-bit cryptographically random opaque handle (`b64(16)`) bound to a single registration's Ed25519 `push_key`. Re-registering a device token always issues a new handle and never overwrites or redirects an existing handle.
3. **Content-free wake pushes.** Webhooks carry only `{ v, handle, ts, nonce }` — zero message metadata or payload. The relay dispatches a content-free wake signal (`{"aps":{"content-available":1}}` on APNs, high-priority data-only `{"type":"wake","v":"1"}` on FCM); the mobile app wakes up and fetches encrypted entries directly from its Pubky Dispatch server.
4. **No PII or source-IP logging.** Request handlers and structured logs never record source IP addresses, handles, device tokens, push keys, or signatures. Sensitive fields are redacted in all `Debug` implementations.
5. **Automatic dead-token pruning.** When APNs (`410 Unregistered`, `400 BadDeviceToken` / `DeviceTokenNotForTopic`) or FCM (`404 UNREGISTERED` / invalid registration token) reports a dead token, the relay immediately deletes the handle from storage.

## HTTP API

### `POST /v1/register`

Registers a mobile device push token bound to an Ed25519 `push_key` minted by the user's Pubky Dispatch server.

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
| `device_token` | `string` | yes | Non-empty, no whitespace/control chars. For `apns`: even-length ASCII hex (`32..=512` chars). For `fcm`: printable ASCII (`1..=4096` chars). |
| `push_key` | `b64(32)` | yes | Unpadded base64url (43 chars) encoding a canonical, non-small-order Ed25519 public key. |
| `apns_env` | `"production" \| "sandbox"` | no | Valid only for `platform: "apns"`. Defaults to `APNS_DEFAULT_ENV` (`production`). Rejected for `fcm`. |

**Response (`200 OK`)**

```json
{
  "handle": "iUsOsTv5mB7OMLMdQZi8QA"
}
```

Errors: `400 bad_request` (invalid JSON, unknown fields, invalid token, invalid/small-order key), `413 too_large`, `429 rate_limited` (global registration limit exceeded, with `Retry-After`), `503 unavailable` (registration store capacity cap reached).

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

The `Dispatch-Signature` header carries an unpadded base64url 64-byte Ed25519 signature over length-prefixed concatenation (`lp(x1, ..., xn) = u32_be(len(x1)) || x1 || ...`):

```text
lp("pubky-dispatch/v1/push", relay_origin, raw_body_bytes)
```

where `relay_origin` is the relay's canonical `https://<host>` origin (without port or path, e.g. `https://push.example.com`) and `raw_body_bytes` are the exact HTTP request body bytes as received.

**Enforcement Order (Wire Format §8.3)**

Every webhook is validated strictly in order:

1. **Body validity (`400 bad_request`)** — Strict JSON (no BOM, no duplicate keys, safe integers `0..=2^53 - 1`, no trailing data), `v == 1`, non-empty `handle`, valid RFC 3339 UTC `ts`, and valid `b64(16)` `nonce`.
2. **Known handle (`404 not_found`)** — Handle must exist in storage.
3. **Signature (`401 bad_signature`)** — Single `Dispatch-Signature` header must pass strict four-step Ed25519 verification (`S < L`, canonical `A` and `R`, neither small-order, cofactorless equation `[S]B - [k]A == R`) with the `push_key` bound to the handle and the relay's configured `RELAY_ORIGIN`.
4. **Timestamp window (`401 stale_timestamp`)** — `ts` must be within ±5 minutes of the relay's clock.
5. **Replay protection (`409 nonce_replay`)** — `nonce` must not have been seen in the last 10 minutes (bounded-memory TTL cache).
6. **Per-handle rate limit (`429 rate_limited`)** — Sliding 1-minute per-handle limit (returns `Retry-After` header and `retry_after` JSON field).

**Responses**

- `200 OK` `{"delivered":true}` — Wake push accepted by APNs/FCM.
- `200 OK` `{"delivered":false,"pruned":true}` — Upstream reported an invalid/unregistered device token; handle was deleted so subsequent hooks return `404`.
- `502 upstream_error` — Transient APNs/FCM error (handle kept; Dispatch server retries).
- `503 unavailable` — Push backend not configured for the handle's platform.

---

### `GET /health`

Readiness and liveness probe verifying storage connectivity.

- `200 OK` `{"status":"ok"}`
- `503 Service Unavailable` `{"status":"unhealthy"}`

---

## Mobile & Bitkit Integration Guide

Mobile apps (such as Bitkit) follow the three-step Pubky Dispatch push registration flow:

### 1. Start registration with Pubky Dispatch

The app calls `PUT /v1/{identity}/push` on its Pubky Dispatch server with its `relay_url` (e.g. `https://push.example.com/v1/hook`) and `handles: []` (no `push_key`). Dispatch mints a fresh registration-scoped Ed25519 `push_key` and returns its 32-byte public key (`b64(32)`).

### 2. Register the device token with this relay

Each device obtains its native push token and sends it together with that `push_key` to `POST https://push.example.com/v1/register`:

- **iOS (APNs):**
  - Encode the `Data` from `application(_:didRegisterForRemoteNotificationsWithDeviceToken:)` as lowercase hex (64 characters).
  - Set `"platform": "apns"`.
  - Pass `"apns_env": "sandbox"` for Xcode/debug builds and `"apns_env": "production"` for TestFlight/App Store builds.
  - Default relay behavior sends silent background wakes (`apns-push-type: background`, `apns-priority: 5`, `{"aps":{"content-available":1}}`). Enable `remote-notification` under Background Modes, wake on `application(_:didReceiveRemoteNotification:fetchCompletionHandler:)`, and sync the Dispatch feed.
  - If your iOS app uses a **Notification Service Extension** to fetch and decrypt notifications for visible banners, set `APNS_PUSH_MODE=alert` on the relay to deliver content-free `mutable-content: 1` wake pushes (`apns-push-type: alert`, `apns-priority: 10`).

- **Android (FCM):**
  - Obtain the registration token via `FirebaseMessaging.getInstance().token`.
  - Set `"platform": "fcm"` and omit `apns_env`.
  - The relay sends a high-priority **data-only** FCM HTTP v1 message (`{"data":{"type":"wake","v":"1"},"android":{"collapse_key":"pubky-dispatch-wake","priority":"HIGH"}}`) with no `notification` block, ensuring `FirebaseMessagingService.onMessageReceived` runs even when the app is backgrounded or in Doze mode and coalescing bursts while offline. Trigger a background feed sync when `remoteMessage.data["type"] == "wake"`.

### 3. Commit handles to Pubky Dispatch

The app sends `PUT /v1/{identity}/push` with the `relay_url`, the `push_key`, and the merged list of handles across its devices (up to 8 handles per relay host per identity).

### Token refresh & provider migration

- Whenever iOS (`didRegisterForRemoteNotificationsWithDeviceToken`) or Android (`onNewToken`) issues a new device token, call `POST /v1/register` again with the current `push_key` to receive a new handle, replace the device's entry in the app's handle list, and update `PUT /v1/{identity}/push`.
- After rotating the push key or migrating to a new Pubky Dispatch server, start a new registration (step 1) and register each device against the new `push_key` (step 2). Old handles remain cryptographically bound to the old key and cannot be triggered by another server.

---

## Configuration

All options can be passed via environment variables or CLI flags (`--help` prints all flags).

| Environment Variable | Default | Description |
|---|---|---|
| `RELAY_ORIGIN` | *(required)* | Canonical public origin (`https://<host>`, no port or path) verified in webhook signatures. |
| `RELAY_BIND_ADDR` | `0.0.0.0:8080` | TCP socket address to bind the HTTP listener. |
| `DATABASE_URL` | `./data/push-relay.sqlite` | Backend auto-selected by URL: `postgres://` or `postgresql://` enables PostgreSQL multi-replica mode; any other path/URL (`./data/push-relay.sqlite`, `sqlite://...`, `:memory:`) uses SQLite. |
| `RATE_LIMIT_PER_MINUTE` | `60` | Maximum wake pushes per handle per rolling 60-second window. |
| `REGISTER_RATE_LIMIT_PER_MINUTE` | `120` | Global maximum `POST /v1/register` requests per rolling 60-second window (`429` with `Retry-After` when exceeded). |
| `MAX_REGISTRATIONS` | `1000000` | Maximum total registrations stored before rejecting new registrations with `503`. |
| `NONCE_CACHE_MAX_ENTRIES` | `100000` | Maximum entries retained in the in-memory 10-minute nonce replay cache (SQLite mode). |
| `PUSH_BACKEND` | `providers` | `providers` (APNs/FCM) or `noop` (for local development without Apple/Google credentials). |
| `LOG_FORMAT` | `json` | `json` or `pretty`. Filter level controlled via `RUST_LOG`. |
| `APNS_TEAM_ID` | — | 10-character Apple Developer Team ID (`iss`). |
| `APNS_KEY_ID` | — | 10-character APNs Auth Key ID (`kid`). |
| `APNS_BUNDLE_ID` | — | iOS app bundle ID (`apns-topic`). |
| `APNS_KEY_PATH` | — | Path to APNs `.p8` PKCS#8 PEM private key file (mutually exclusive with `APNS_KEY_PEM`). |
| `APNS_KEY_PEM` | — | Inline APNs `.p8` PEM or base64-encoded PEM. |
| `APNS_DEFAULT_ENV` | `production` | Default APNs gateway (`production` or `sandbox`) when `apns_env` is omitted. |
| `APNS_PUSH_MODE` | `background` | `background` (`content-available: 1`) or `alert` (`mutable-content: 1` for iOS NSE). |
| `FCM_SERVICE_ACCOUNT_PATH` | — | Path to Google Cloud service account JSON file (mutually exclusive with `FCM_SERVICE_ACCOUNT_JSON`). |
| `FCM_SERVICE_ACCOUNT_JSON` | — | Inline Google service account JSON or base64-encoded JSON. |

---

## Running Locally

### Local development (no-op push sender)

```bash
RELAY_ORIGIN=https://push.example \
PUSH_BACKEND=noop \
LOG_FORMAT=pretty \
DATABASE_URL=:memory: \
cargo run
```

### Docker

```bash
docker build -t pubky-dispatch-push-relay .

docker run --rm -p 8080:8080 \
  -v relay-data:/var/lib/pubky-dispatch-push-relay \
  -e RELAY_ORIGIN=https://push.example.com \
  -e APNS_TEAM_ID=TEAM123456 \
  -e APNS_KEY_ID=KEY1234567 \
  -e APNS_BUNDLE_ID=to.bitkit.app \
  -e APNS_KEY_PEM="$APNS_P8_BASE64" \
  -e FCM_SERVICE_ACCOUNT_JSON="$FCM_SA_BASE64" \
  pubky-dispatch-push-relay
```

---

## Production Deployment

### Multi-Replica Stateless Deployment (PostgreSQL)

Point `DATABASE_URL` at a shared PostgreSQL instance (`postgres://...` or `postgresql://...`) to run multiple stateless replicas behind a load balancer without needing Redis:

```bash
docker run --rm -p 8080:8080 \
  -e RELAY_ORIGIN=https://push.example.com \
  -e DATABASE_URL=postgres://relay:secret@postgres.internal:5432/push_relay \
  -e APNS_TEAM_ID=TEAM123456 \
  -e APNS_KEY_ID=KEY1234567 \
  -e APNS_BUNDLE_ID=to.bitkit.app \
  -e APNS_KEY_PEM="$APNS_P8_BASE64" \
  -e FCM_SERVICE_ACCOUNT_JSON="$FCM_SA_BASE64" \
  pubky-dispatch-push-relay
```

When running on PostgreSQL:

- **`registrations`** persists handle mappings and enforces `MAX_REGISTRATIONS` atomically across all replicas using a transaction-scoped advisory lock (`pg_advisory_xact_lock`).
- **`webhook_nonces` (`UNLOGGED`)** provides atomic cross-replica 10-minute nonce replay protection (`409`) without WAL overhead.
- **`rate_limit_buckets` (`UNLOGGED`)** provides atomic cross-replica sliding-window rate limiting (`429`) for both per-handle hooks and global registrations.
- Each replica's existing 60-second background sweep task prunes expired rows from both `UNLOGGED` tables automatically.

### Unauthenticated `/v1/register` Hardening

Because `POST /v1/register` is intentionally unauthenticated (clients submit only a device token and an opaque `push_key` with no user account), combine application-level and edge protections in production:

- **Application limits:** Tune `REGISTER_RATE_LIMIT_PER_MINUTE` (default `120`) and `MAX_REGISTRATIONS` (default `1000000`) to bound write throughput and disk usage.
- **Ingress per-IP rate limiting:** Apply per-IP rate limiting to `POST /v1/register` at your reverse proxy or CDN edge (for example, nginx `limit_req_zone` / `limit_req` or Cloudflare Rate Limiting Rules) while disabling IP access-log retention on `/v1/hook` to preserve relay privacy.

---

## Storage Backends

Persistence, replay protection, and rate limiting sit behind clean async traits (`RegistrationStore`, `ReplayStore`, and `RateLimitStore`):

- **SQLite (default):** Zero-config single-instance mode using WAL journal mode (`STRICT` table) with fast bounded in-memory replay cache and rate limiters.
- **PostgreSQL (`DATABASE_URL=postgres://...` / `postgresql://...`):** Stateless multi-replica mode sharing persistent registrations plus `UNLOGGED` replay and rate-limit tables over a single `sqlx` connection pool (TLS via `rustls`).

## Development & Verification

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo doc --no-deps
```

To run the PostgreSQL and multi-replica integration tests locally against a Postgres instance:

```bash
TEST_DATABASE_URL=postgres://relay:relay@127.0.0.1:5432/relay_test \
REQUIRE_POSTGRES_TESTS=1 \
cargo test --test postgres
```

## License

MIT — see [LICENSE](LICENSE).
