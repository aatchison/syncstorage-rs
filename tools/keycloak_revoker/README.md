# Keycloak revoker

Revokes Keycloak sessions and retires Tokenserver users in response to Keycloak
events, for a Tokenserver in OIDC mode (`SYNC_TOKENSERVER__OAUTH_PROVIDER=oidc`)
with Keycloak as its identity provider. FxA plays no part in it. See the
"Revocation" part of the OIDC mode section in `docs/src/config.md` for where it
fits.

Keycloak has no webhook, so the revoker polls the realm's stored events
(`GET /admin/realms/<realm>/events` and `/admin-events`) and acts on them:

| Keycloak event | What the revoker does |
| --- | --- |
| User event `UPDATE_PASSWORD`, or `UPDATE_CREDENTIAL` with `details.credential_type` `password` (the user changed their password) | `POST /users/{id}/logout`, then `DELETE /users/{id}/consents/{client}` for each Thunderbird client, which revokes the offline sessions too. Done whether or not the user ticked "Sign out from other devices" |
| Admin event `ACTION users/{id}/reset-password` | The same |
| Admin event `ACTION users/{id}/logout` | `DELETE /users/{id}/consents/{client}` for each Thunderbird client: Keycloak's sign-out leaves offline sessions alive |
| Admin event `DELETE users/{id}`, user event `DELETE_ACCOUNT` | Retires the Tokenserver user `{id}@{SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN}`, with `retire_user` from `tools/tokenserver/database.py` |
| Disabling a user (admin event `UPDATE users/{id}`), and every other event | Nothing. Keycloak refuses a disabled user's refreshes by itself |

Keycloak also emits `UPDATE_CREDENTIAL` when a user sets up OTP or WebAuthn
(`credential_type` `otp`, `webauthn`, ...); those are ignored, so the user isn't
signed out everywhere, including the browser they just made the change in. A
password change emits both `UPDATE_PASSWORD` and `UPDATE_CREDENTIAL`; handling
it twice is harmless.

Before the first poll the revoker looks up every client in
`REVOKER_OFFLINE_CLIENTS` (`GET /clients?clientId=`) and exits if one isn't in
the realm: revoking the consent of a client that doesn't exist revokes nothing.
Keycloak's own 404s for a user who no longer exists (`User not found`) or has no
consent or offline session for the client (`Consent nor offline token not
found`) count as done; any other 404, including `Client not found`, fails the
poll. A 5xx response or a network error is retried with exponential backoff;
if it persists, the poll fails and the cursor stays where it was, so the next
poll handles the same events again. Every action can safely be repeated.

## Cursor

The cursor file records the time of the newest event handled. Each poll asks
for events from that time minus `REVOKER_OVERLAP` seconds, so an event Keycloak
stored late is still seen; the IDs of the events handled in that window are kept
in the file so that none is handled twice. When the file doesn't exist, the
revoker starts from the current time: older events are never handled. The file
is written only after every event of a poll has been handled. It holds event IDs
and times, no user data.

## Reconcile

`--reconcile` retires every active Tokenserver user `<sub>@<FXA_EMAIL_DOMAIN>`
for which Keycloak's `GET /users/{sub}` returns 404. It catches deletions whose
events the revoker never saw: it was down for longer than the realm keeps
events, or it was deployed after them. Run it once when deploying the revoker,
and then regularly, for example nightly.

Retirement can't be undone, so reconcile retires nobody when Keycloak's answers
look wrong:

- `GET /users/count` must return 200 with a number other than 0
- the revoker's own service-account user (its token's `sub`) must be found
- a user counts as gone only on Keycloak's own `404 {"error":"User not found"}`;
  any other answer, such as a 404 from a proxy that hides `/admin/`, stops the run
- it retires at most `REVOKER_RECONCILE_MAX` users, and at most 10 % of the
  active Tokenserver users of `FXA_EMAIL_DOMAIN`, in one run. If more are gone it
  retires none and fails; once you have checked that Keycloak really lost them,
  run `--reconcile --force`

## Settings

All from environment variables.

| Variable | Default | |
| --- | --- | --- |
| `REVOKER_KEYCLOAK_URL` | (required) | Keycloak's base URL, e.g. `https://keycloak.example.com` |
| `REVOKER_REALM` | (required) | The realm |
| `REVOKER_CLIENT_ID` | `keycloak-revoker` | The revoker's confidential client, see below |
| `REVOKER_CLIENT_SECRET_FILE` | | A file holding the client's secret. Takes precedence over `REVOKER_CLIENT_SECRET` |
| `REVOKER_CLIENT_SECRET` | | The client's secret, if there is no file |
| `REVOKER_OFFLINE_CLIENTS` | `SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS` | Comma-separated IDs of the clients Thunderbird signs in with, whose offline sessions are revoked |
| `REVOKER_CURSOR_FILE` | (required) | The cursor file. Its directory must be writable |
| `REVOKER_INTERVAL` | 15 | Seconds between polls |
| `REVOKER_OVERLAP` | 60 | Seconds each poll looks back before the cursor |
| `REVOKER_TIMEOUT` | 10 | HTTP timeout in seconds |
| `REVOKER_ATTEMPTS` | 4 | Attempts per Keycloak request on a 5xx or network error |
| `REVOKER_RECONCILE_MAX` | 10 | The most users one `--reconcile` retires without `--force` |
| `REVOKER_LOG_LEVEL` | `INFO` | |
| `SYNC_TOKENSERVER__DATABASE_URL` | (required) | The Tokenserver database, as for Tokenserver |
| `SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN` | (required) | The same value as Tokenserver's |

The logs name Keycloak user IDs only; they never contain emails or the client
secret.

## Keycloak setup

The realm must store events:

- `eventsEnabled: true`, with at least `UPDATE_CREDENTIAL`, `UPDATE_PASSWORD`,
  `DELETE_ACCOUNT` and `LOGOUT` in `enabledEventTypes`
- `eventsExpiration` comfortably longer than the revoker could be down (the dev
  realm keeps 604800 s, 7 days). Events hold user IDs and IP addresses; choose a
  retention that fits your privacy policy. `--reconcile` covers deletions
  whatever the retention
- `adminEventsEnabled: true`. `adminEventsDetailsEnabled` isn't needed

The revoker authenticates as the service account of a confidential client with
only the client-credentials grant, whose service account has the
`realm-management` roles `view-events`, `view-users`, `manage-users` and
`view-clients`. `view-clients` is for the startup lookup of the offline clients:
with `query-clients` alone Keycloak 26.2 answers that lookup with an empty list.
It also lets the account read every client's configuration, secrets included.
The dev realm, `keycloak/realm-export.json`, has such a client, `keycloak-revoker`,
without a secret: `keycloak/start-services.sh` generates one into
`/tmp/syncstorage-test-secrets/keycloak-revoker-secret`.

## Running it

From this directory:

```shell
poetry install --without dev
poetry run python revoker.py               # poll forever
poetry run python revoker.py --once        # poll once
poetry run python revoker.py --reconcile   # reconcile once
poetry run python revoker.py --reconcile --force   # without the cap
```

Run a single instance: two revokers sharing a cursor file would only repeat each
other's (idempotent) work, but there is no locking.

## Tests

- `tests/`: unit tests, against a fake Keycloak and a fake Tokenserver database:
  `poetry run pytest tests`, from this directory
- `live/`: tests against a real Keycloak, Tokenserver and database, for each way
  of cutting a user off with an online and an offline session. Run by
  `keycloak/run-suite.sh`, which provides their settings
