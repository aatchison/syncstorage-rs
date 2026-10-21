# Configuration
Rust uses environment variables for a number of configuration options. Some of these include:

| variable | value | description |
| --- | --- | --- |
| **RUST_LOG** | *debug*, *info*, *warn*, *error* | minimum Rust error logging level |
| **RUST_TEST_THREADS** | 1  | maximum number of concurrent threads for testing. |

In addition, Sync server configuration options can either be specified as environment variables (prefixed with **SYNC_***) or in a configuration file using the `--config` option.

For example the following are equivalent:
```bash
$ SYNC_HOST=0.0.0.0 SYNC_MASTER_SECRET="SuperSikkr3t" SYNC_SYNCSTORAGE__DATABASE_URL=mysql://scott:tiger@localhost/syncstorage cargo run
```

```bash
$ cat syncstorage.local.toml
host = "0.0.0.0"
master_secret = "SuperSikkr3t"

[syncstorage]
database_url = "mysql://scott:tiger@localhost/syncstorage"
$ cargo run -- --config syncstorage.local.toml
```

Options can be mixed between environment variables and configuration.  Environment variables have higher precedence.

## Options
The following configuration options are available.

### Server Settings

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_HOST"></span>SYNC_HOST | 127.0.0.1 | Host address to bind the server to |
| <span id="SYNC_PORT"></span>SYNC_PORT | 8000 | Server port to bind to |
| <span id="SYNC_MASTER_SECRET"></span>SYNC_MASTER_SECRET | None, required | Secret used to derive auth secrets |
| <span id="SYNC_ENVIRONMENT"></span>SYNC_ENVIRONMENT | dev | Environment name ("dev", "stage", "prod") |
| <span id="SYNC_HUMAN_LOGS"></span>SYNC_HUMAN_LOGS | false | Enable human-readable logs |
| <span id="SYNC_ACTIX_KEEP_ALIVE"></span>SYNC_ACTIX_KEEP_ALIVE | None | HTTP keep-alive header value in seconds |
| <span id="SYNC_WORKER_MAX_BLOCKING_THREADS"></span>SYNC_WORKER_MAX_BLOCKING_THREADS | 512 | The maximum number of blocking threads in the worker threadpool. This threadpool is used by Actix-web to handle blocking operations. |

### CORS

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_CORS_ALLOWED_ORIGIN"></span>SYNC_CORS_ALLOWED_ORIGIN | * | Allowed origins for CORS requests |
| <span id="SYNC_CORS_MAX_AGE"></span>SYNC_CORS_MAX_AGE | 1728000 | CORS preflight cache seconds (20 days) |
| <span id="SYNC_CORS_ALLOWED_METHODS"></span>SYNC_CORS_ALLOWED_METHODS | ["DELETE", "GET", "POST", "PUT"] | Allowed methods |
| <span id="SYNC_CORS_ALLOWED_HEADERS"></span>SYNC_CORS_ALLOWED_HEADERS | See source | Allowed headers for CORS requests |

### Syncstorage Database

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_SYNCSTORAGE__DATABASE_URL"></span>SYNC_SYNCSTORAGE__DATABASE_URL | mysql://root@127.0.0.1/syncstorage | Database connection URL |
| <span id="SYNC_SYNCSTORAGE__DATABASE_POOL_MAX_SIZE"></span>SYNC_SYNCSTORAGE__DATABASE_POOL_MAX_SIZE | 10 | Max database connections |
| <span id="SYNC_SYNCSTORAGE__DATABASE_POOL_CONNECTION_TIMEOUT"></span>SYNC_SYNCSTORAGE__DATABASE_POOL_CONNECTION_TIMEOUT | 30 | Pool timeout in seconds |
| <span id="SYNC_SYNCSTORAGE__DATABASE_POOL_CONNECTION_LIFESPAN"></span>SYNC_SYNCSTORAGE__DATABASE_POOL_CONNECTION_LIFESPAN | None | Max connection age in seconds |
| <span id="SYNC_SYNCSTORAGE__DATABASE_POOL_CONNECTION_MAX_IDLE"></span>SYNC_SYNCSTORAGE__DATABASE_POOL_CONNECTION_MAX_IDLE | None | Max idle time in seconds |
| <span id="SYNC_SYNCSTORAGE__DATABASE_POOL_SWEEPER_TASK_INTERVAL"></span>SYNC_SYNCSTORAGE__DATABASE_POOL_SWEEPER_TASK_INTERVAL | 30 | How often, in seconds, a background task runs to evict idle database connections (Spanner only) |
| <span id="SYNC_SYNCSTORAGE__DATABASE_SPANNER_ROUTE_TO_LEADER"></span>SYNC_SYNCSTORAGE__DATABASE_SPANNER_ROUTE_TO_LEADER | false | Send leader-aware headers to Spanner |
| <span id="SYNC_SYNCSTORAGE__SPANNER_EMULATOR_HOST"></span>SYNC_SYNCSTORAGE__SPANNER_EMULATOR_HOST | None | Spanner emulator host (e.g., localhost:9010) |

### Syncstorage Limits

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_SYNCSTORAGE__LIMITS__MAX_POST_BYTES"></span>SYNC_SYNCSTORAGE__LIMITS__MAX_POST_BYTES | 2,621,440 | Max BSO payload size per request |
| <span id="SYNC_SYNCSTORAGE__LIMITS__MAX_POST_RECORDS"></span>SYNC_SYNCSTORAGE__LIMITS__MAX_POST_RECORDS | 100 | Max BSO count per request |
| <span id="SYNC_SYNCSTORAGE__LIMITS__MAX_RECORD_PAYLOAD_BYTES"></span>SYNC_SYNCSTORAGE__LIMITS__MAX_RECORD_PAYLOAD_BYTES | 2,621,440 | Max individual BSO payload size |
| <span id="SYNC_SYNCSTORAGE__LIMITS__MAX_REQUEST_BYTES"></span>SYNC_SYNCSTORAGE__LIMITS__MAX_REQUEST_BYTES | 2,625,536 | Max Content-Length for requests |
| <span id="SYNC_SYNCSTORAGE__LIMITS__MAX_TOTAL_BYTES"></span>SYNC_SYNCSTORAGE__LIMITS__MAX_TOTAL_BYTES | 262,144,000 | Max BSO payload size per batch |
| <span id="SYNC_SYNCSTORAGE__LIMITS__MAX_TOTAL_RECORDS"></span>SYNC_SYNCSTORAGE__LIMITS__MAX_TOTAL_RECORDS | 10,000 | Max BSO count per batch |
| <span id="SYNC_SYNCSTORAGE__LIMITS__MAX_QUOTA_LIMIT"></span>SYNC_SYNCSTORAGE__LIMITS__MAX_QUOTA_LIMIT | 2,147,483,648 | Max storage quota per user (2 GB) |
| <span id="SYNC_SYNCSTORAGE__LIMITS__COLLECTIONS"></span>SYNC_SYNCSTORAGE__LIMITS__COLLECTIONS | unset | Optional per-collection limit overrides, as a JSON object mapping collection name -> limits object (e.g. `{"newtab-images":{"max_record_payload_bytes":20971520,"max_post_bytes":26214400,"max_request_bytes":26218496}}`). Supported override fields: `max_record_payload_bytes`, `max_post_bytes`, `max_request_bytes`. Any field left unset inherits the corresponding global limit. |

### Syncstorage Features

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_SYNCSTORAGE__ENABLED"></span>SYNC_SYNCSTORAGE__ENABLED | true | Enable syncstorage service |
| <span id="SYNC_SYNCSTORAGE__ENABLE_QUOTA"></span>SYNC_SYNCSTORAGE__ENABLE_QUOTA | false | Enable quota tracking (Spanner only) |
| <span id="SYNC_SYNCSTORAGE__ENFORCE_QUOTA"></span>SYNC_SYNCSTORAGE__ENFORCE_QUOTA | false | Enforce quota limits (Spanner only) |
| <span id="SYNC_SYNCSTORAGE__REQUIRE_COLLECTION_DELETE_CONFIRMATION"></span>SYNC_SYNCSTORAGE__REQUIRE_COLLECTION_DELETE_CONFIRMATION | false | Require `X-Confirm-Delete: 1` header for collection deletion. Without the header, an HTTP 200 is returned without deletion. |
| <span id="SYNC_SYNCSTORAGE__GLEAN_ENABLED"></span>SYNC_SYNCSTORAGE__GLEAN_ENABLED | true | Enable Glean telemetry |
| <span id="SYNC_SYNCSTORAGE__LBHEARTBEAT_TTL"></span>SYNC_SYNCSTORAGE__LBHEARTBEAT_TTL | None | Load balancer heartbeat period in seconds |
| <span id="SYNC_SYNCSTORAGE__LBHEARTBEAT_TTL_JITTER"></span>SYNC_SYNCSTORAGE__LBHEARTBEAT_TTL_JITTER | 25 | Jitter percentage for the load balancer heartbeat period |
| <span id="SYNC_SYNCSTORAGE__STATSD_LABEL"></span>SYNC_SYNCSTORAGE__STATSD_LABEL | syncstorage | StatsD metrics label prefix |

### Syncstorage Payload Off-load

Off-loads large BSO payloads to a Google Cloud Storage bucket, storing the
object URL in the `payload_link` column instead of the inline `payload`
column. Supported on the Spanner backend only: setting
`SYNC_SYNCSTORAGE__GCS_PAYLOAD_BUCKET` or
`SYNC_SYNCSTORAGE__GCS_PAYLOAD_OFFLOAD_COLLECTIONS` on a mysql or postgres
backend fails startup, since those backends have no `payload_link` column and
would silently drop the payload.

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_SYNCSTORAGE__GCS_PAYLOAD_BUCKET"></span>SYNC_SYNCSTORAGE__GCS_PAYLOAD_BUCKET | unset | GCS bucket for off-loaded payloads. Unset disables off-load. |
| <span id="SYNC_SYNCSTORAGE__GCS_PAYLOAD_OFFLOAD_COLLECTIONS"></span>SYNC_SYNCSTORAGE__GCS_PAYLOAD_OFFLOAD_COLLECTIONS | unset | Comma-separated collection names whose payloads are off-loaded. Empty disables off-load for all collections. |
| <span id="SYNC_SYNCSTORAGE__GCS_PAYLOAD_PREFIX"></span>SYNC_SYNCSTORAGE__GCS_PAYLOAD_PREFIX | v1 | The prefix for off-loaded GCS object names. The server formats each object name as `{prefix}/{fxa_uid}/{uuid}`. |
| <span id="SYNC_SYNCSTORAGE__GCS_PAYLOAD_MAX_CONCURRENCY"></span>SYNC_SYNCSTORAGE__GCS_PAYLOAD_MAX_CONCURRENCY | 4 | The maximum number of concurrent GCS payload uploads and downloads within one batch request. This value must be greater than zero. |
| <span id="SYNC_SYNCSTORAGE__GCS_ENDPOINT"></span>SYNC_SYNCSTORAGE__GCS_ENDPOINT | unset | A test-only override for the GCS endpoint URL, for example a mock server or a fake-gcs-server instance. If set, the server uses anonymous credentials. Do not set this variable in production. |

### Tokenserver Database

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_TOKENSERVER__DATABASE_URL"></span>SYNC_TOKENSERVER__DATABASE_URL | mysql://root@127.0.0.1/tokenserver | Tokenserver database URL |
| <span id="SYNC_TOKENSERVER__DATABASE_POOL_MAX_SIZE"></span>SYNC_TOKENSERVER__DATABASE_POOL_MAX_SIZE | 10 | Max tokenserver DB connections |
| <span id="SYNC_TOKENSERVER__DATABASE_POOL_CONNECTION_TIMEOUT"></span>SYNC_TOKENSERVER__DATABASE_POOL_CONNECTION_TIMEOUT | 30 | Pool timeout in seconds |

### Tokenserver Features

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_TOKENSERVER__INIT_NODE_URL"></span>SYNC_TOKENSERVER__INIT_NODE_URL | None | The storage node URL, protocol + host, to insert into the `nodes` table on startup. This is the origin where the service is hosted, e.g. "http://localhost:8000". |
| <span id="SYNC_TOKENSERVER__INIT_NODE_CAPACITY"></span>SYNC_TOKENSERVER__INIT_NODE_CAPACITY | 100000 | The storage node capacity of the server specified by `SYNC_TOKENSERVER__INIT_NODE_URL`. Only used if `SYNC_TOKENSERVER__INIT_NODE_URL` is set. |
| <span id="SYNC_TOKENSERVER__ENABLED"></span>SYNC_TOKENSERVER__ENABLED | false | Enable tokenserver service |
| <span id="SYNC_TOKENSERVER__RUN_MIGRATIONS"></span>SYNC_TOKENSERVER__RUN_MIGRATIONS | false | Run DB migrations on startup |
| <span id="SYNC_TOKENSERVER__NODE_TYPE"></span>SYNC_TOKENSERVER__NODE_TYPE | spanner | Storage backend type reported in token response for telemetry. Valid values: "mysql", "postgres", "spanner" |
| <span id="SYNC_TOKENSERVER__STATSD_LABEL"></span>SYNC_TOKENSERVER__STATSD_LABEL | syncstorage.tokenserver | StatsD metrics label prefix |
| <span id="SYNC_TOKENSERVER__TOKEN_DURATION"></span>SYNC_TOKENSERVER__TOKEN_DURATION | 3600 | Token TTL (1 hour) |
| <span id="SYNC_TOKENSERVER__FXA_WEBHOOK_ENABLED"></span>SYNC_TOKENSERVER__FXA_WEBHOOK_ENABLED | false | Enable the FxA webhook endpoint. When disabled, the route is not registered. |
| <span id="SYNC_TOKENSERVER__FXA_WEBHOOK_METRICS_ONLY"></span>SYNC_TOKENSERVER__FXA_WEBHOOK_METRICS_ONLY | false | Run the FxA webhook handler in metrics-only mode. Received events are counted but not processed. Only used if `FXA_WEBHOOK_ENABLED` is true. |
| <span id="SYNC_TOKENSERVER__FXA_WEBHOOK_SET_CLIENT_ID"></span>SYNC_TOKENSERVER__FXA_WEBHOOK_SET_CLIENT_ID | None | Expected `aud` of FxA Security Event Tokens. Required for account event webhooks. |
| <span id="SYNC_TOKENSERVER__FXA_WEBHOOK_SET_ISSUER"></span>SYNC_TOKENSERVER__FXA_WEBHOOK_SET_ISSUER | None | Expected `iss` of FxA Security Event Tokens. Required for account event webhooks. |
| <span id="SYNC_TOKENSERVER__ALLOW_NEW_USERS"></span>SYNC_TOKENSERVER__ALLOW_NEW_USERS | true | Whether new users may be created. When disabled, only previously registered users can use the tokenserver service. |

### Tokenserver+FxA Integration

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN"></span>SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN | api-accounts.stage.mozaws.net | FxA email domain |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL"></span>SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL | https://oauth.stage.mozaws.net | FxA OAuth server URL |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_REQUEST_TIMEOUT"></span>SYNC_TOKENSERVER__FXA_OAUTH_REQUEST_TIMEOUT | 10 | OAuth request timeout in seconds |
| <span id="SYNC_TOKENSERVER__FXA_METRICS_HASH_SECRET"></span>SYNC_TOKENSERVER__FXA_METRICS_HASH_SECRET | secret | Secret for hashing metrics to maintain anonymity |
| <span id="SYNC_TOKENSERVER__ADDITIONAL_BLOCKING_THREADS_FOR_FXA_REQUESTS"></span>SYNC_TOKENSERVER__ADDITIONAL_BLOCKING_THREADS_FOR_FXA_REQUESTS | 1 | Number of additional blocking threads to add to the threadpool for OAuth verification requests to FxA |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__KTY"></span>SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__KTY | None | Primary JWK key type (e.g., "RSA") |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__ALG"></span>SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__ALG | None | Primary JWK algorithm (e.g., "RS256") |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__KID"></span>SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__KID | None | Primary JWK key ID |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__FXA_CREATED_AT"></span>SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__FXA_CREATED_AT | None | Primary JWK creation timestamp |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__USE"></span>SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__USE | None | Primary JWK use (e.g., "sig") |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__N"></span>SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__N | None | Primary JWK modulus (RSA public key component) |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__E"></span>SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__E | None | Primary JWK exponent (RSA public key component) |
| <span id="SYNC_TOKENSERVER__FXA_OAUTH_SECONDARY_JWK"></span>SYNC_TOKENSERVER__FXA_OAUTH_SECONDARY_JWK__* | None | Secondary JWK (same structure as primary) |
| <span id="SYNC_TOKENSERVER__OAUTH_PROVIDER"></span>SYNC_TOKENSERVER__OAUTH_PROVIDER | fxa | Identity provider: `fxa` or `oidc` (a generic OpenID Connect provider such as Keycloak). `oidc` needs a build without `py_verifier`, never falls back to FxA's `/v1/verify`, and requires `OIDC_ISSUER_URL`, `OIDC_AUDIENCE` and `OIDC_ALLOWED_CLIENTS` |
| <span id="SYNC_TOKENSERVER__OIDC_ISSUER_URL"></span>SYNC_TOKENSERVER__OIDC_ISSUER_URL | None | OIDC issuer URL, e.g. `http://keycloak:7080/realms/sync`. Tokens must carry it as `iss`; keys come from `{OIDC_ISSUER_URL}/protocol/openid-connect/certs` |
| <span id="SYNC_TOKENSERVER__OIDC_AUDIENCE"></span>SYNC_TOKENSERVER__OIDC_AUDIENCE | None | Audience that OIDC access tokens must include in `aud` |
| <span id="SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS"></span>SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS | None | Comma-separated client IDs (a list in a TOML config file) whose OIDC access tokens are accepted, matched exactly against `azp` |

#### OIDC mode (Keycloak)

With `OAUTH_PROVIDER=oidc`, Tokenserver accepts an access token only if it is:

- an RFC 9068 access token, with header `typ: at+jwt` (Keycloak client option `access.token.header.type.rfc9068`), signed with RS256 and carrying an unexpired `exp`
- issued by `iss` exactly equal to `OIDC_ISSUER_URL`, or to `OIDC_ISSUER_URL` without one trailing `/` (Keycloak's `iss` has none)
- for an `aud` that contains `OIDC_AUDIENCE` (in Keycloak, an audience mapper)
- issued to a client listed in `OIDC_ALLOWED_CLIENTS`, as `azp` (a token without `azp` is rejected)
- granted the `https://identity.mozilla.com/apps/oldsync` scope, in a space-separated `scope`

No generation claim is part of the OIDC token contract, and revocation doesn't need one: in this deployment, don't map an `fxa-generation` claim (no Keycloak mapper for it). Tokenserver still reads the claim if a token carries one, as in FxA mode, and a mapped claim changes how retirement works. The OIDC-mode check that refuses a retired user (generation `MAX_GENERATION`, `i64::MAX`) applies only to tokens without a generation; a token with one is left to the same generation checks as in FxA mode, which refuse it only if its generation is lower than the stored one. So a retired user whose token carries `i64::MAX` (for example from a user attribute the user can edit) is accepted again, and a token carrying a higher generation than the stored one also raises the stored generation, after which tokens with lower values are refused.

The signing keys are fetched from `{OIDC_ISSUER_URL}/protocol/openid-connect/certs` on every request, with no cache. If that fetch fails, Tokenserver returns 503; tokens that the fetched keys don't verify get 401.

Of the FxA settings above, these still apply: `FXA_EMAIL_DOMAIN` (users are keyed as `<sub>@<FXA_EMAIL_DOMAIN>`), `FXA_METRICS_HASH_SECRET`, and `FXA_OAUTH_REQUEST_TIMEOUT` (the JWKS request timeout). Startup fails if `FXA_WEBHOOK_ENABLED`, `FXA_OAUTH_PRIMARY_JWK` or `FXA_OAUTH_SECONDARY_JWK` is set in OIDC mode (so Keycloak keys can't be pinned through them), or if `OIDC_ISSUER_URL`, `OIDC_AUDIENCE` or `OIDC_ALLOWED_CLIENTS` is set without `OAUTH_PROVIDER=oidc`.

`keycloak/realm-export.json` is a realm for local development only; don't use it in a deployment.

##### Revocation

Revocation never involves FxA. A user is cut off by revoking their sessions in Keycloak, which then refuses to refresh their tokens. `tools/keycloak_revoker` covers the cases Keycloak leaves half done: it polls the realm's stored events and calls the Keycloak admin API, and retires deleted users in the Tokenserver database. See `tools/keycloak_revoker/README.md` for how to deploy it. The realm must store events: `eventsEnabled` with at least `UPDATE_CREDENTIAL` and `DELETE_ACCOUNT` in `enabledEventTypes` (`UPDATE_PASSWORD` is deprecated in Keycloak 26 and not required, but acted on when stored), `eventsExpiration` of at least a few days (the dev realm keeps 7), and `adminEventsEnabled`; the revoker checks this when it starts, and again hourly while it runs (`REVOKER_RECHECK_INTERVAL`). Keycloak expires admin events separately, after the realm attribute `adminEventsExpiration`, which the revoker can't read: it must be unset or at least `eventsExpiration`, or its value must be given to the revoker as `REVOKER_ADMIN_EVENTS_EXPIRATION`. Otherwise an outage of the revoker longer than the admin-event retention loses admin password resets and deletions without an error. The dev realm also stores `UPDATE_PASSWORD`, and `LOGOUT` for auditing only.

| Case | Who cuts the sessions off |
| --- | --- |
| User disabled | Keycloak, natively: every refresh fails |
| User deleted (by an admin, or by the user through the `delete_account` action) | Keycloak, natively. The revoker also retires the Tokenserver user `<sub>@<FXA_EMAIL_DOMAIN>` |
| Password reset by an admin (`reset-password`, or `PUT /users/{id}` with a `credentials` array) | The revoker. Keycloak on its own ends no session at all. The revoker treats every admin update of a user as a possible password change, so an admin's profile edit signs the user out too |
| Password changed by the user (account console, or the forgot-password email flow) | The revoker. Keycloak's "Sign out from other devices" ends online sessions only, and only if it is ticked; the revoker ends every session either way |
| Admin "Sign out" | Keycloak ends the online sessions, and sets the user's `notBefore` (in whole seconds), so it refuses existing offline tokens as stale, apart from those issued in the same second as the sign-out. The offline sessions themselves stay; the revoker deletes them, which closes that window |

For a password change the revoker signs the user out of every session and then revokes their offline sessions of the Thunderbird clients. So whether or not Thunderbird is allowed `offline_access`, its sessions are covered by the revoker. Its `--reconcile` mode retires Tokenserver users whose Keycloak user no longer exists, for deletions whose events were missed. Tokenserver refuses a retired user's access token with 401 `invalid-generation` (when, as in this contract, the token carries no generation), so a deleted user's unexpired access token stops working as soon as the revoker has retired them.

The revoker relies on event times: run NTP on the Keycloak nodes and the revoker's host, and keep its `REVOKER_OVERLAP` (60 s by default) well above the worst clock skew between them.

Nothing is pushed to Tokenserver or the storage nodes. A client cut off this way keeps the access token and Sync token it already holds until they expire. The worst-case time from the event to losing access is:

```text
revoker poll interval + poll duration + Keycloak access-token lifespan + TOKEN_DURATION
```

The poll duration is normally well under a second, but each of its Keycloak requests (two event queries, then a few per event acted on) may take up to `REVOKER_ATTEMPTS` × `REVOKER_TIMEOUT` plus 1 + 2 + 4 s of retry backoff with the defaults, and a poll that fails is repeated after another interval, up to `REVOKER_MAX_FAILURES` times before the revoker exits.

We recommend a realm `accessTokenLifespan` of 300 s or less, and `SYNC_TOKENSERVER__TOKEN_DURATION` of 300–900 s rather than the default 3600. With the revoker's default 15 s poll, that is a cut-off within about 10–20 minutes. Shorter lifetimes mean more token refreshes and more Tokenserver requests from each client.

### StatsD Metrics

| Env Var | Default Value | Description |
| --- | --- | --- |
| <span id="SYNC_STATSD_HOST"></span>SYNC_STATSD_HOST | localhost | StatsD server hostname |
| <span id="SYNC_STATSD_PORT"></span>SYNC_STATSD_PORT | 8125 | StatsD server port |
| <span id="SYNC_INCLUDE_HOSTNAME_TAG"></span>SYNC_INCLUDE_HOSTNAME_TAG | false | Include hostname in metrics tags |
