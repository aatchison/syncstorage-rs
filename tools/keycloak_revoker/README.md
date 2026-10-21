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
| Admin event `UPDATE users/{id}` (`PUT /users/{id}`: an admin or a script set a password through its `credentials` array, disabled the user, or edited their profile) | The same. The event doesn't say whether a password was set, so every update counts as one; see below |
| Admin event `ACTION users/{id}/logout` | `DELETE /users/{id}/consents/{client}` for each Thunderbird client. Keycloak's sign-out ends the online sessions and sets the user's `notBefore` to the current second, which makes older refresh and offline tokens stale; but it leaves the offline sessions in place, and an offline token issued in the same second as the sign-out still works. Deleting the offline sessions closes that window |
| Admin event `DELETE users/{id}`, user event `DELETE_ACCOUNT` | Retires the Tokenserver user `{id}@{SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN}`, with `retire_user` from `tools/tokenserver/database.py` |
| Every other event | Nothing |

Acting on every admin `UPDATE users/{id}` over-revokes: an admin who edits a
user's profile, attributes or required actions also signs them out
of every session, and Thunderbird has to sign in again. That is the accepted
trade-off, as a password set through `PUT /users/{id}` would otherwise leave
every existing session working. Keycloak refuses a disabled user's refreshes by
itself; the revoker's sign-out adds nothing there but does no harm.

Keycloak also emits `UPDATE_CREDENTIAL` when a user sets up OTP or WebAuthn
(`credential_type` `otp`, `webauthn`, ...); those are ignored, so the user isn't
signed out everywhere, including the browser they just made the change in. A
password change emits both `UPDATE_PASSWORD` and `UPDATE_CREDENTIAL`; handling
it twice is harmless.

Before the first poll the revoker checks every client in
`REVOKER_OFFLINE_CLIENTS` and exits if one isn't in the realm: revoking the
consent of a client that doesn't exist revokes nothing. The check is the same
`DELETE users/{id}/consents/{client}`, for the revoker's own service-account
user, which never has a consent or offline session: Keycloak answers
`404 {"error":"Client not found"}` for a missing client and `204` or
`404 {"error":"Consent nor offline token not found"}` for one that exists, so
nothing changes and no role beyond `manage-users` is needed. Any other answer
stops the revoker too.

Keycloak's own 404s for a user who no longer exists (`User not found`) or has no
consent or offline session for the client (`Consent nor offline token not
found`) count as done; any other 404, including `Client not found`, fails the
poll. A 5xx response or a network error is retried with exponential backoff;
if it persists, the poll fails and the cursor stays where it was, so the next
poll handles the same events again. Every action can safely be repeated.

## Cursor

The cursor file records the time of the newest event handled, but never later
than the revoker's own clock (less a second) at that poll. Each poll asks for
events from that time minus `REVOKER_OVERLAP` seconds, so an event Keycloak
stored late is still seen; the IDs of the events handled in that window are kept
in the file so that none is handled twice. The file is written only after every
event of a poll has been handled. It holds event IDs and times, no user data.

The revoker refuses to start when the file doesn't exist, and exits 1 with
`no cursor file: first deployment? Run with --init-cursor`: starting afresh
would skip every event since its last poll, and a missing file is as likely to
be a wiped state directory, a lost volume or a changed `REVOKER_CURSOR_FILE` as
a first deployment. `--init-cursor` (or `REVOKER_INIT_CURSOR=1`) creates a new
cursor at the current time minus `REVOKER_OVERLAP`; older events are never
handled. It fails if the file already exists, so it can't restart a cursor by
mistake when left in place.

Keycloak stamps each event with the clock of the node that stored it, and sorts
and filters events by that time only. Run NTP on every Keycloak node and on the
revoker's host, and keep `REVOKER_OVERLAP` well above the worst clock difference
between any two of them plus the time Keycloak takes to store an event: an
event stamped more than `REVOKER_OVERLAP` before the cursor is never seen.

## Lost events

Keycloak deletes stored events after the realm's `eventsExpiration`, and a realm
that stores no events gives the revoker nothing to do. So that this never
happens unnoticed, the revoker exits non-zero, with an error that says why:

- at startup, unless `GET /events/config` shows `eventsEnabled` and
  `adminEventsEnabled`, with `UPDATE_PASSWORD`, `UPDATE_CREDENTIAL` and
  `DELETE_ACCOUNT` listed in `enabledEventTypes`
- before a poll, if the last poll that handled every event started longer ago
  than `eventsExpiration` (the cursor file records when). Password changes in
  that gap may never be acted on. Sign every user out (the realm's "Sign out
  all active sessions", which sets the realm's `notBefore`), run `--reconcile`
  for the deletions, then delete the cursor file and start the revoker once
  with `--init-cursor`
- at startup, if the cursor file is missing (see "Cursor"). If the revoker ran
  before, treat it as a gap: take the same steps, then start it with
  `--init-cursor`
- when polling forever, after `REVOKER_MAX_FAILURES` polls in a row have failed:
  for example Keycloak is gone for good, or a role was taken away and every
  call gets 403

`--once` exits non-zero whenever its poll fails. See "Alerting" under "Deployment".

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
  active Tokenserver users of `FXA_EMAIL_DOMAIN` (rounded down, but at least 1),
  in one run: `min(REVOKER_RECONCILE_MAX, max(1, active // 10))`. So with 3
  active users it retires 1, with 25 it retires 2, and with 200 it retires
  `REVOKER_RECONCILE_MAX` (10). If more are gone it retires none and fails; once
  you have checked that Keycloak really lost them, run `--reconcile --force`

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
| `REVOKER_INIT_CURSOR` | 0 | `1`: the same as `--init-cursor`. Remove it again once the cursor exists |
| `REVOKER_INTERVAL` | 15 | Seconds between polls |
| `REVOKER_OVERLAP` | 60 | Seconds each poll looks back before the cursor, and a first start before the current time. Must exceed the worst clock skew, see "Cursor" |
| `REVOKER_TIMEOUT` | 10 | HTTP timeout in seconds |
| `REVOKER_ATTEMPTS` | 4 | Attempts per Keycloak request on a 5xx or network error |
| `REVOKER_MAX_FAILURES` | 5 | When polling forever, exit after this many failed polls in a row |
| `REVOKER_RECONCILE_MAX` | 10 | The most users one `--reconcile` retires without `--force`, whatever 10 % of the active users is (see "Reconcile") |
| `REVOKER_LOG_LEVEL` | `INFO` | |
| `SYNC_TOKENSERVER__DATABASE_URL` | (required) | The Tokenserver database, as for Tokenserver |
| `SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN` | (required) | The same value as Tokenserver's |

The logs name Keycloak user IDs only; they never contain emails or the client
secret. Each action is logged with the event it was for, for example
`revoke-all-sessions: keycloak user <id>, for user event UPDATE_PASSWORD`.

## Keycloak setup

The realm must store events:

- `eventsEnabled: true`, with at least `UPDATE_CREDENTIAL`, `UPDATE_PASSWORD`
  and `DELETE_ACCOUNT` in `enabledEventTypes`. The dev realm also stores
  `LOGOUT`, for auditing only: the revoker doesn't use it
- `eventsExpiration` comfortably longer than the revoker could be down (the dev
  realm keeps 604800 s, 7 days). Events hold user IDs and IP addresses; choose a
  retention that fits your privacy policy. `--reconcile` covers deletions
  whatever the retention
- `adminEventsEnabled: true`. `adminEventsDetailsEnabled` isn't needed

The revoker authenticates as the service account of a confidential client with
only the client-credentials grant, whose service account has the
`realm-management` roles `view-events`, `view-users` and `manage-users`, and no
others. In particular it needs no `view-clients`, which would let it read every
client's configuration, secrets included: the startup check of the offline
clients goes through the consent endpoint (see above). The service account
needs no realm roles, not even the default ones.

Keycloak's admin API checks the roles in the service account's token. Set
`fullScopeAllowed: false` on the client, which keeps every other role out of
those tokens, and give it these three roles as its scope: in the admin console,
the client's "Client scopes" tab, its dedicated scope, "Scope"; in a realm
export, `clientScopeMappings`. Without them every admin call gets 403.

The dev realm, `keycloak/realm-export.json`, has such a client, `keycloak-revoker`,
without a secret: `keycloak/start-services.sh` generates one into
`/tmp/syncstorage-test-secrets/keycloak-revoker-secret`.

## Running it

From this directory:

```shell
poetry install --only main                 # without the test and lint tools
poetry run python revoker.py --once --init-cursor   # first deployment only
poetry run python revoker.py               # poll forever
poetry run python revoker.py --once        # poll once
poetry run python revoker.py --reconcile   # reconcile once
poetry run python revoker.py --reconcile --force   # without the cap
```

Run a single instance: two revokers sharing a cursor file would only repeat each
other's (idempotent) work, but there is no locking.

## Deployment

### Process manager

Run the poller under a process manager that restarts it when it exits, and
alerts when it keeps failing; run `--reconcile` from a timer. With systemd, for
example (paths and the alert unit are placeholders):

```ini
# /etc/systemd/system/keycloak-revoker.service
[Unit]
Description=Keycloak revoker for Tokenserver
Wants=network-online.target
After=network-online.target
# Five failed runs within 10 minutes leave the unit failed, which alerts
StartLimitIntervalSec=600
StartLimitBurst=5
OnFailure=alert@%n.service

[Service]
User=keycloak-revoker
WorkingDirectory=/opt/syncstorage-rs/tools/keycloak_revoker
# Mode 600: holds the database URL with its password, see below
EnvironmentFile=/etc/keycloak-revoker/env
LoadCredential=client-secret:/etc/keycloak-revoker/client-secret
Environment=REVOKER_CLIENT_SECRET_FILE=%d/client-secret
# REVOKER_CURSOR_FILE=/var/lib/keycloak-revoker/cursor in the env file
StateDirectory=keycloak-revoker
ExecStart=/opt/syncstorage-rs/tools/keycloak_revoker/.venv/bin/python revoker.py
Restart=on-failure
RestartSec=30
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/keycloak-revoker-reconcile.service
[Unit]
Description=Keycloak revoker: retire Tokenserver users deleted in Keycloak
OnFailure=alert@%n.service

[Service]
Type=oneshot
User=keycloak-revoker
WorkingDirectory=/opt/syncstorage-rs/tools/keycloak_revoker
EnvironmentFile=/etc/keycloak-revoker/env
LoadCredential=client-secret:/etc/keycloak-revoker/client-secret
Environment=REVOKER_CLIENT_SECRET_FILE=%d/client-secret
ExecStart=/opt/syncstorage-rs/tools/keycloak_revoker/.venv/bin/python revoker.py --reconcile

# /etc/systemd/system/keycloak-revoker-reconcile.timer
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

The `.venv` comes from `POETRY_VIRTUALENVS_IN_PROJECT=true poetry install --only
main`, run as the service user.

On the first deployment, create the cursor with the unit's own environment,
through a temporary drop-in, then remove it:

```shell
systemctl edit keycloak-revoker      # add: [Service] Environment=REVOKER_INIT_CURSOR=1
systemctl start keycloak-revoker     # creates /var/lib/keycloak-revoker/cursor, then polls
systemctl revert keycloak-revoker    # drop the setting again
```

Then run the reconcile service once. Don't leave `REVOKER_INIT_CURSOR=1` (or
`--init-cursor` in `ExecStart`) in place: once the cursor exists every restart
would fail, and the setting is what keeps a lost cursor from going unnoticed.

### Alerting

The revoker exits non-zero, with an error naming the cause, on a bad setting,
when the startup checks fail, on an event gap longer than the realm's
retention, and after `REVOKER_MAX_FAILURES` failed polls in a row (see "Lost
events"); `--reconcile` exits non-zero when it refuses to retire users. Alert
on every such exit, not only on the unit ending up failed: restarting doesn't
fix an event gap or a missing role, and the gap needs the steps under "Lost
events" before the revoker may run again. Until then sessions that should
have been revoked keep working.

### Tokenserver database account

The revoker reads the `users` table and retires users with an `UPDATE` of it,
nothing else. Give it its own MySQL account rather than Tokenserver's:

```sql
CREATE USER 'keycloak_revoker'@'%' IDENTIFIED BY 'YOUR_PASSWORD_HERE';
GRANT SELECT, UPDATE ON tokenserver_rs.users TO 'keycloak_revoker'@'%';
```

and set `SYNC_TOKENSERVER__DATABASE_URL` to
`mysql://keycloak_revoker:YOUR_PASSWORD_HERE@host:3306/tokenserver_rs`. The
live tests run the revoker with an account with only these grants.

### The client secret

`manage-users` lets the client's service account reset any user's password,
change their email and delete them. Treat the client secret like an admin
credential. Keep it in a file readable by the service user only
(`REVOKER_CLIENT_SECRET_FILE`, or systemd's `LoadCredential` as above), never
in the environment of other processes or in logs, and rotate it like other
admin credentials: regenerate it in Keycloak (the client's "Credentials" tab),
replace the file and restart the revoker.

## Tests

- `tests/`: unit tests, against a fake Keycloak and a fake Tokenserver database:
  `poetry run pytest tests`, from this directory
- `live/`: tests against a real Keycloak, Tokenserver and database, for each way
  of cutting a user off with an online and an offline session, including a
  password change by the user in Keycloak's own pages. Run by
  `keycloak/run-suite.sh`, which provides their settings
