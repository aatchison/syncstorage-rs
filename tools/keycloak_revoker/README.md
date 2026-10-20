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
| User event `UPDATE_CREDENTIAL` or `UPDATE_PASSWORD` (the user changed their password) | `POST /users/{id}/logout`, then `DELETE /users/{id}/consents/{client}` for each Thunderbird client, which revokes the offline sessions too. Done whether or not the user ticked "Sign out from other devices" |
| Admin event `ACTION users/{id}/reset-password` | The same |
| Admin event `ACTION users/{id}/logout` | `DELETE /users/{id}/consents/{client}` for each Thunderbird client: Keycloak's sign-out leaves offline sessions alive |
| Admin event `DELETE users/{id}`, user event `DELETE_ACCOUNT` | Retires the Tokenserver user `{id}@{SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN}`, with `retire_user` from `tools/tokenserver/database.py` |
| Disabling a user (admin event `UPDATE users/{id}`), and every other event | Nothing. Keycloak refuses a disabled user's refreshes by itself |

`UPDATE_CREDENTIAL` is acted on for any credential type, so adding or changing
an OTP device also ends the user's sessions.

A 404 from Keycloak (the user, or their offline session, is already gone) counts
as done. A 5xx response or a network error is retried with exponential backoff;
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
and then regularly, for example nightly. It refuses to run against a realm with
no users at all.

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
`realm-management` roles `view-events`, `view-users` and `manage-users`.

## Running it

From this directory:

```shell
poetry install --without dev
poetry run python revoker.py               # poll forever
poetry run python revoker.py --once        # poll once
poetry run python revoker.py --reconcile   # reconcile once
```

Run a single instance: two revokers sharing a cursor file would only repeat each
other's (idempotent) work, but there is no locking.

## Tests

Unit tests, against a fake Keycloak and a fake Tokenserver database, are in
`tests/`: `poetry run pytest tests`, from this directory.
