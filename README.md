# OTP Authentication Service

A production-quality, email-based OTP authentication service built with Django, Redis, Celery, and PostgreSQL.

---

## Table of Contents

1. [Setup](#setup)
2. [Project structure](#project-structure)
3. [API endpoints](#api-endpoints)
4. [Design decisions and rationale](#design-decisions-and-rationale)
5. [Assumptions](#assumptions)
6. [Trade-offs considered](#trade-offs-considered)
7. [Edge cases handled](#edge-cases-handled)
8. [Failure scenarios](#failure-scenarios)
9. [Email normalisation](#email-normalisation)
10. [Improvements before production](#improvements-before-production)

---

## Setup

### Prerequisites

- Docker and Docker Compose

### Quick start

```bash
cp .env.example .env          # review and keep defaults for local dev
docker compose up --build
```

The stack starts four services:

| Service    | Role                                      | Port  |
|------------|-------------------------------------------|-------|
| `postgres` | PostgreSQL 15 database                    | 5432  |
| `redis`    | Redis 7 — OTP storage, rate limiting, broker | 6379  |
| `web`      | Django dev server                         | 8000  |
| `worker`   | Celery worker (email send + audit logging)| —     |

Django's `depends_on` with `healthcheck` conditions ensures the web and worker containers wait for Postgres and Redis to pass their health checks before starting.

### Verify it works

```bash
# Request an OTP
curl -s -X POST http://localhost:8000/api/v1/auth/otp/request \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'

# The OTP is logged by the Celery worker — check the worker container:
docker compose logs worker

# Verify the OTP (replace 123456 with the logged value)
curl -s -X POST http://localhost:8000/api/v1/auth/otp/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "otp": "123456"}'
```

### API documentation

- OpenAPI schema: <http://localhost:8000/api/v1/schema/>
- Swagger UI: <http://localhost:8000/api/v1/docs/>

### Running the test suite

```bash
# Inside the repo (with .venv active)
pip install -r requirements-dev.txt
pytest

# Or inside Docker
docker compose run --rm web pytest
```

### Environment variables

All settings are driven by environment variables. Copy `.env.example` to `.env` — every variable is documented there. Key variables:

| Variable                  | Description                                 |
|---------------------------|---------------------------------------------|
| `SECRET_KEY`              | Django secret key                           |
| `DEBUG`                   | `True` for development, `False` for prod    |
| `ALLOWED_HOSTS`           | Comma-separated list of allowed hostnames   |
| `DATABASE_URL`            | PostgreSQL DSN                              |
| `REDIS_URL`               | Redis connection URL                        |
| `CELERY_BROKER_URL`       | Celery broker (same Redis instance)         |
| `CELERY_RESULT_BACKEND`   | Celery result backend                       |

---

## Project structure

```
config/                     Django project configuration
  settings/
    base.py                 INSTALLED_APPS, middleware, logging
    db.py                   DATABASES — reads DATABASE_URL from env
    cache.py                Redis connection via django-redis
    drf.py                  REST_FRAMEWORK + SPECTACULAR_SETTINGS
    jwt.py                  SIMPLE_JWT lifetimes and algorithm
    celery_settings.py      CELERY_BROKER_URL, result backend
    local.py                Dev: imports all setting modules
    test.py                 Test: SQLite in-memory, eager Celery tasks
  celery.py                 Celery app instance + autodiscover_tasks
  urls.py                   Root URL config

apps/accounts/              Authentication domain
  models.py                 Custom User (email as username field)
  serializers.py            OTPRequestSerializer, OTPVerifySerializer
  views.py                  RequestOTPView, VerifyOTPView (thin)
  urls.py
  utils.py                  normalize_email()
  tasks.py                  send_otp_email Celery task
  services/
    redis_keys.py           Single source of truth for key names + TTLs
    redis_client.py         Raw Redis client accessor (test-injectable)
    otp_service.py          Generate / hash / store / validate OTP
    rate_limit_service.py   Atomic Lua-script rate limiting
    auth_service.py         Orchestrates request + verify flows

apps/audit/                 Audit logging domain
  models.py                 AuditLog (UUID PK, JSONField metadata)
  serializers.py
  filters.py                FilterSet: email, event, created_from, created_to
  views.py                  AuditLogListView (JWT-protected)
  urls.py
  tasks.py                  log_audit_event Celery task
```

**Why two apps?**  
`accounts` owns everything related to identity and authentication — OTP lifecycle, rate limiting, JWT issuance. `audit` owns the audit trail. Keeping them separate means the audit domain can evolve independently (different retention policies, different permissions, potential extraction into a separate service) without touching authentication code.

**Why a services layer?**  
Views and serializers handle HTTP concerns only. Business logic lives in `services/`. This makes the logic testable without the HTTP layer and keeps views trivially thin — each view calls one service method and maps the result to a response.

---

## API endpoints

### `POST /api/v1/auth/otp/request`

Request body: `{ "email": "user@example.com" }`

| Status | Meaning |
|--------|---------|
| 202    | OTP generated and queued for delivery |
| 400    | Validation error (missing or malformed email) |
| 429    | Rate limit exceeded — `Retry-After` header gives the wait time in seconds |

### `POST /api/v1/auth/otp/verify`

Request body: `{ "email": "user@example.com", "otp": "123456" }`

| Status | Meaning |
|--------|---------|
| 200    | Success — returns `{ access, refresh, user }` |
| 400    | Wrong OTP, expired OTP, or missing OTP (generic message — no enumeration) |
| 423    | Account locked after 5 failed attempts |

### `GET /api/v1/audit/logs`

Requires `Authorization: Bearer <access_token>`.

Query parameters: `email`, `event`, `from` (ISO 8601), `to` (ISO 8601), `page`.

| Status | Meaning |
|--------|---------|
| 200    | Paginated list of audit log entries |
| 401    | Missing or invalid JWT |

---

## Design decisions and rationale

### OTP overwrite on new request

When a user requests a second OTP before the first has expired, the new code is stored with `SETEX`, which unconditionally overwrites the existing key and resets the TTL to 5 minutes. The old code is immediately invalid.

**Why:** The alternative — queuing multiple valid codes — would widen the attack surface. An adversary who intercepts an older code could still use it. Overwrite-on-request is the simplest policy that keeps exactly one valid code in existence at any time. It does mean a user who requests a second OTP before receiving the first cannot use the first; this is an acceptable UX trade-off given the 5-minute TTL.

### Hashing OTPs at rest

The plaintext OTP is never written to Redis. Only the SHA-256 hex digest is stored. On verification, the submitted OTP is hashed with the same function and compared to the stored digest.

**Why:** If Redis were compromised (e.g., via an exposed port, a misconfigured cloud security group, or a Redis vulnerability), an attacker reading the store would obtain digests, not usable codes. SHA-256 is sufficient here because the input space is small (10^6 values for 6-digit numeric OTPs) and the codes expire in 5 minutes — the window for a preimage attack is negligible.

### Atomic rate limiting via Lua script

Rate limiting uses a Lua script that performs `INCR` and (on first increment) `EXPIRE` in a single atomic operation on the Redis server:

```lua
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
```

**Why not a pipeline?** A Redis pipeline sends multiple commands in one network round-trip but does not make them atomic — two concurrent callers can both execute `INCR` and both set `EXPIRE`, or one can read a stale count before the other's `INCR` lands. Lua scripts run atomically on the Redis server: no other client can interleave commands while the script is executing.

**Why not `EXPIRE NX` directly after `INCR` in a pipeline?** Same issue — the two commands are still separate, not atomic.

### Atomic one-time-use OTP validation via GETDEL

OTP validation uses `GETDEL` (or an equivalent Lua GET+DEL script for older Redis versions) to fetch and delete the key in a single atomic operation.

**Why:** Without atomicity, two concurrent verify requests for the same valid OTP could both call `GET` before either calls `DEL`, both receive the stored hash, and both return 200. `GETDEL` eliminates this window: only one of the two concurrent callers receives the hash — the other gets `nil`.

See `test_concurrent_verify_only_one_succeeds` in `apps/accounts/tests/test_views.py` for a direct test of this property using `threading.Barrier` to synchronise two threads at the moment of verification.

### Lockout response code: 423

The spec offers a choice between 423 and 429. This implementation uses **423 Locked**.

**Why:** 429 means "too many requests" and is the right code for rate limiting (which this service also uses for OTP requests). 423 means "the resource is locked" — it more precisely describes the state: the account is locked due to repeated failures, not simply hammered with traffic. The distinction matters for clients that handle 429 (back off and retry) differently from 423 (present a lockout UI and do not retry automatically).

### JWT lifetimes

| Token   | Lifetime |
|---------|----------|
| Access  | 60 minutes |
| Refresh | 7 days |

**Why:** 60 minutes is short enough to limit the blast radius of a leaked access token while long enough for a normal user session. 7 days balances session persistence with rotation frequency. Both values are configurable via `SIMPLE_JWT` in `config/settings/jwt.py`.

### Custom User model

`apps.accounts.User` extends `AbstractUser` with `username = None` and `email` as the `USERNAME_FIELD`. Django's built-in `AbstractUser` provides battle-tested password hashing, permissions, and admin integration. No custom fields were needed beyond email-as-identifier, so extending the built-in model is preferable to writing a model from scratch.

---

## Assumptions

1. **No real email delivery required.** The spec explicitly states to log the OTP instead of sending it via a provider. `send_otp_email` is a Celery task that logs to stdout/stderr.

2. **Single Redis database.** OTP storage, rate limiting, and Celery broker all use the same Redis instance (different logical databases could be used in production for isolation).

3. **Numeric OTPs only.** The spec says "6-digit numeric OTP". The serializer enforces `isdigit()` validation and `min_length=6, max_length=6`.

4. **`+`-tag normalisation applies to all domains.** The spec says to strip `+` tags. This is applied universally, not only for `@gmail.com`, to close the rate-limit evasion vector across all providers.

5. **Audit logs are append-only.** There is no delete or update endpoint for audit records.

---

## Trade-offs considered

### 423 vs 429 for lockout

As noted above, 423 more precisely describes the locked state. The trade-off is that 423 is less commonly handled by HTTP clients than 429. The choice was made in favour of semantic accuracy.

### Storing OTP hash vs plaintext

Hashing adds one SHA-256 call on request and one on verify — negligible overhead. The security benefit (Redis breach does not expose usable codes) clearly outweighs this cost.

### Gmail-style normalisation vs no normalisation

Stripping `+` tags closes an abuse vector: without it, an attacker could bypass the per-email rate limit by sending to `target+1@example.com`, `target+2@example.com`, etc. The cost is that a user who uses `+` tags for inbox filtering cannot have separate OTP identities per tag — but that is not a realistic use case for authentication.

Dot stripping (e.g., treating `j.smith@gmail.com` and `jsmith@gmail.com` as the same identity) was deliberately not implemented. It is Gmail-specific behaviour; applying it universally would incorrectly merge distinct addresses on other domains.

### OTP overwrite vs multiple valid codes

Discussed above. Overwrite is stricter and simpler to reason about.

---

## Edge cases handled

### Multiple OTP requests before a previous OTP expires

Each new `POST /api/v1/auth/otp/request` calls `SETEX` on the same Redis key (`otp:code:{normalized_email}`). This atomically replaces the stored hash and resets the TTL to 5 minutes. The old code is immediately invalid — only the most recently issued code will ever verify successfully.

### Concurrent OTP verification requests

Two concurrent `POST /api/v1/auth/otp/verify` requests for the same valid OTP race to call `GETDEL` on the same Redis key. Because `GETDEL` is atomic, exactly one caller receives the stored hash; the other receives `nil`. This guarantees that a valid OTP can only be redeemed once, regardless of concurrency.

See `test_concurrent_verify_only_one_succeeds` for the test. It uses `threading.Barrier(2)` so both threads enter the verify handler simultaneously, then asserts that exactly one response is 200 and exactly one is 400.

### IP extraction behind a proxy

`get_client_ip()` in `apps/accounts/views.py` checks `HTTP_X_FORWARDED_FOR` first and falls back to `REMOTE_ADDR`. The `X-Forwarded-For` header can contain a comma-separated list (added by each proxy in the chain); only the first entry (the original client IP) is used. In production, you should also configure Django's `SECURE_PROXY_SSL_HEADER` and `USE_X_FORWARDED_HOST` and trust only known proxy IPs.

### Wrong code consumes the OTP key

`validate_otp` uses `GETDEL`, which atomically fetches and deletes the key on every call — regardless of whether the submitted code matches. This means a wrong guess invalidates the current OTP; the user must request a fresh one before retrying. The 5-failure lockout is the primary anti-brute-force mechanism: an attacker gets at most 5 attempts per 15-minute window.

---

## Failure scenarios

### Redis unavailable

Redis holds the OTP, the rate-limit counters, and the failure counters. If Redis is unreachable:

- `POST /api/v1/auth/otp/request` — the OTP cannot be stored, so the service raises an unhandled exception and returns 500. **This is intentional.** Authentication cannot proceed without Redis; failing loudly is safer than silently issuing an OTP that can never be verified.
- `POST /api/v1/auth/otp/verify` — same: the GETDEL cannot execute, so the service returns 500.

In production, add connection-level retries with a short timeout and a circuit breaker. Alert on Redis connectivity errors immediately.

### Celery / broker unavailable

If the Celery broker (Redis) is unavailable when `.delay()` is called:

- The OTP has already been generated and stored in Redis. The core authentication flow is unaffected.
- `send_otp_email.delay()` will raise a connection error; the OTP is never delivered to the user.
- `log_audit_event.delay()` will also fail; the audit record is lost.

**What to add in production:**
- Celery retry policies (`autoretry_for`, `max_retries`, `retry_backoff`) on both tasks so transient broker outages are recovered automatically.
- A dead-letter queue (e.g., a Redis list or a dedicated queue with a Celery `on_failure` handler) so failed tasks can be replayed.
- A synchronous fallback for `send_otp_email` — if the broker is unreachable, log the OTP directly so the operator can relay it out-of-band. In a real deployment this would be replaced by a direct SMTP/SES/Postmark call that does not go through Celery.

---

## Email normalisation

Implemented in `apps/accounts/utils.normalize_email()`. Applied consistently everywhere an email address touches Redis or the database: in both serializers' `validate_email` methods.

### Algorithm

1. Lowercase the entire address.
2. Split on `@`; take the local part and the domain.
3. If the local part contains `+`, discard everything from `+` onwards.
4. Reconstruct `local@domain`.

Dots in the local part are **not** stripped. Dot-stripping is a Gmail-specific quirk (`j.smith@gmail.com` == `jsmith@gmail.com`) that does not apply to other providers. Applying it universally would incorrectly merge `j.smith@company.com` and `jsmith@company.com`, which are two distinct users.

### Why strip `+` tags

Without normalisation, an adversary can bypass the per-email rate limit (3 requests / 10 minutes) by appending different `+` tags: `target+1@example.com`, `target+2@example.com`, … each maps to a different Redis key and a fresh counter. After normalisation, all of these collapse to `target@example.com` and share the same counter.

The cost: a legitimate user who routes `user+service@example.com` to a separate inbox cannot use that tag as a distinct OTP identity on this service. For an authentication context this is acceptable — email tags are a filtering convenience, not an identity mechanism.

### Examples

| Input                    | Normalised              |
|--------------------------|-------------------------|
| `TEST@EXAMPLE.COM`       | `test@example.com`      |
| `test+123@example.com`   | `test@example.com`      |
| `test+tag@gmail.com`     | `test@gmail.com`        |
| `test.x@example.com`     | `test.x@example.com`    |
| `first.last@company.com` | `first.last@company.com`|
| `A+B+C@Example.COM`      | `a@example.com`         |

---

## Improvements before production

1. **Real email delivery.** Replace the `logger.info` in `send_otp_email` with a call to AWS SES, Postmark, or SendGrid. Add Celery retry logic (`autoretry_for=(Exception,), max_retries=3, retry_backoff=True`).

2. **Structured logging.** Replace the root logger with a JSON formatter (e.g., `python-json-logger`) and ship logs to a log aggregation service. Include `request_id`, `email` (hashed or masked), `event`, and `latency` in every log line.

3. **Metrics and alerting.** Instrument rate-limit hits, lockouts, and OTP verification failures with counters (Prometheus / CloudWatch). Alert when the lockout rate exceeds a baseline — it signals a credential-stuffing or enumeration campaign.

4. **OTP strength.** A 6-digit numeric OTP has 10^6 possible values. With a 5-minute TTL and a 5-failure lockout, brute force is impractical (an attacker gets 5 guesses per 15-minute lockout window against 10^6 values). For higher-assurance flows, consider an 8-digit OTP or an alphanumeric code to increase the space.

5. **Refresh token delivery.** The refresh token is currently returned in the JSON body, making it accessible to JavaScript. In a browser-facing deployment, set the refresh token as an `HttpOnly`, `Secure`, `SameSite=Strict` cookie so it is invisible to JavaScript and cannot be stolen via XSS.

6. **Secret rotation.** The `SECRET_KEY` signs sessions and CSRF tokens; the JWT signing key signs tokens. Add a rotation procedure that generates a new key, keeps the old key valid for one TTL period (to allow in-flight tokens to expire naturally), then removes it.

7. **HTTPS only.** Set `SECURE_SSL_REDIRECT = True`, `SESSION_COOKIE_SECURE = True`, and `CSRF_COOKIE_SECURE = True`. Terminate TLS at a load balancer or reverse proxy (nginx, AWS ALB).

8. **`ALLOWED_HOSTS` hardening.** Replace `'*'` (dev default) with the exact production domain(s). Set via the `ALLOWED_HOSTS` environment variable.

9. **Database connection pooling.** Use `django-db-geventpool` or PgBouncer to avoid exhausting PostgreSQL connections under load.

10. **Celery retry and dead-letter policy.** As noted in [Failure scenarios](#failure-scenarios), add `autoretry_for`, `max_retries`, and a dead-letter handler to both Celery tasks so transient failures are recovered without data loss.

11. **Rate-limit header standards.** Supplement the `Retry-After` header with the draft [RateLimit headers](https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-ratelimit-headers) (`RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`) for better client integration.
