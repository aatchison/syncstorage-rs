# Keycloak (OIDC) build: build, test and run

This branch adds a generic OpenID Connect back end to Tokenserver, tested
against Keycloak. It also adds `tools/keycloak_revoker`, which cuts off a
user's Sync access in the cases where Keycloak alone leaves it working:
password resets, password changes and deletions. This page covers building the
branch, running its test suite and running it locally. The token checks and
settings are in [docs/src/config.md](../docs/src/config.md) under "OIDC mode
(Keycloak)", and deploying the revoker is covered in
[tools/keycloak_revoker/README.md](../tools/keycloak_revoker/README.md).

| Path | What it is |
| --- | --- |
| `keycloak/start-services.sh` | Starts a fresh MySQL 8.0 and Keycloak 26.2.4 for the suite |
| `keycloak/run-suite.sh` | Builds, lints and runs every test for this build |
| `keycloak/realm-export.json` | The `sync` realm, for local development only |
| `config/local.keycloak.toml` | Config for `cargo run` against a local Keycloak |
| `Dockerfile.keycloak` | `./Dockerfile` without `py_verifier` |
| `docker/docker-compose.mysql.keycloak.yaml` | Overlay for a syncserver and Keycloak dev stack |
| `docker/docker-compose.e2e.mysql.keycloak.yaml` | Overlay that runs the integration tests in compose |

## Build

OIDC mode uses the native token verifier, so build without `py_verifier`. A
build with `py_verifier` refuses to start when
`SYNC_TOKENSERVER__OAUTH_PROVIDER=oidc`.

```shell
cargo build --no-default-features --features=syncstorage-db/mysql
make clippy_mysql_oidc     # clippy for this build, warnings as errors
```

The toolchain is Rust 1.98.1, the same as `Cargo.toml` and upstream CI. The
devcontainer in `.devcontainer/` has it, along with the MySQL client and the
other build packages.

To build a container image, use `Dockerfile.keycloak`. The simplest way is
`make docker_start_mysql_keycloak` (see [Run locally](#run-locally)).

## Test

You need rootless podman and the devcontainer CLI. `start-services.sh` runs on
the host, next to a running devcontainer for this checkout, and `run-suite.sh`
runs inside the devcontainer:

```shell
devcontainer up --workspace-folder .        # once
keycloak/start-services.sh                   # before every run
timeout 1800 devcontainer exec --workspace-folder . -- keycloak/run-suite.sh
```

The devcontainer has to run under podman, because `start-services.sh` finds it
with `podman ps`. If `docker` on your host isn't podman, add
`--docker-path podman` to the `devcontainer` commands. The `timeout` is
optional. It makes a hung run fail instead of waiting forever.
`make test_mysql_oidc_suite` runs the same `run-suite.sh`.

`start-services.sh` removes any earlier test containers and their volumes, then
starts MySQL and Keycloak in the devcontainer's network namespace. Inside the
devcontainer, MySQL is on `localhost:3306` and Keycloak on `localhost:7080`.
The script generates the MySQL root password, the Keycloak admin password and
the revoker's client secret into `/tmp/syncstorage-test-secrets`, on the host
and in the devcontainer. It never prints them, and `run-suite.sh` masks them in
its output.

`run-suite.sh` runs these steps in order and ends with a PASS/FAIL summary. It
exits non-zero if any step fails.

| Step | What | Expected at `8af24074` |
| --- | --- | --- |
| (a) | `cargo build` of the OIDC build | pass |
| (b) | `cargo fmt --check`, clippy for the OIDC build, `make clippy_mysql` | pass |
| (c) | `cargo test --workspace` for the OIDC build, against MySQL | 271 passed |
| (d) | `tools/integration_tests` against syncserver in OIDC mode | 102 passed, 1 skipped |
| (e) | `tools/tokenserver`, with `-o addopts=` so the `migration_records` tests run | 44 passed |
| (f) | `tools/keycloak_revoker/tests` (unit tests) | 177 passed |
| (g) | `tools/keycloak_revoker/live` (revocation against the real Keycloak) | 17 passed |

In step (d), upstream's two batch-id probes (`test_storage.py:2149` and `:2177`)
skip themselves when they can't trigger the case they test. 101 passed with 2
skipped is the same result. The suite leaves out
`test_payload_link_reconciliation.py`, which needs Spanner and GCS, and doesn't
build the Rust tests behind `#[cfg(feature = "spanner")]`.

A cold run takes about 7 minutes, mostly the first build and clippy. After
that a run takes about a minute. Logs go to `/tmp/syncstorage-suite` inside
the devcontainer. To run one step by hand, export the variables that `main()`
in `run-suite.sh` exports, then run that step's command.

The first run needs network access. The build fetches crates, and the
`utoipa-swagger-ui` build script downloads Swagger UI from github.com. The
Python steps install poetry 2.5.1 and their dependencies from PyPI.
`start-services.sh` pulls the MySQL and Keycloak images if they're missing.

### In a throwaway VM

The suite runs well in a disposable VM. That keeps the test containers, the
generated secrets and the build cache off your workstation. The VM needs
rootless podman, the devcontainer CLI and a checkout of the branch. It needs no
credentials. These sizes have been enough: 8 CPUs, 16 GiB of memory and 80 GiB
of disk. Everything else is the same as above, with the VM as the host:

```shell
cd syncstorage-rs
devcontainer up --workspace-folder .
keycloak/start-services.sh
timeout 1800 devcontainer exec --workspace-folder . -- keycloak/run-suite.sh
```

The devcontainer config includes docker-in-docker, kind and kubectl features.
The suite doesn't use any of them, because `start-services.sh` runs the
services with the host's podman. If one of them fails to install in your VM,
you can drop it from your local copy of `.devcontainer/devcontainer.json`.

To keep build output out of the work tree, set `CARGO_TARGET_DIR` inside the
devcontainer, for example with
`devcontainer exec --remote-env CARGO_TARGET_DIR=/tmp/cargo-target …`.
`run-suite.sh` uses it when it's set. If you snapshot the VM after a first run, later runs start with a
warm build cache and both images already pulled.

When you're done, delete the VM. Nothing in it needs to be kept.

## Run locally

### With cargo

You need Keycloak on `localhost:7080` with the `sync` realm, from
`start-services.sh` or the compose stack below, and MySQL on `localhost:3306`.

```shell
cp config/local.keycloak.toml /tmp/local.keycloak.toml
# in the copy, set master_secret, fxa_metrics_hash_secret and the two
# database_url values (the config's defaults are test:test@localhost:3306,
# databases syncstorage and tokenserver)
cargo run --no-default-features --features=syncstorage-db/mysql \
    -- --config /tmp/local.keycloak.toml
```

Syncserver then accepts access tokens from the realm's `public-client` that
carry the `https://identity.mozilla.com/apps/oldsync` scope. It's an optional
scope, so the client has to ask for it. Syncserver also creates the
`http://localhost:8000` node on startup.

### With docker compose

```shell
make docker_start_mysql_keycloak    # builds Dockerfile.keycloak, starts MySQL, Keycloak and syncserver
make docker_stop_mysql_keycloak
```

Keycloak is on `http://localhost:7080` and syncserver on `http://localhost:8000`.
The stack has no admin user. To create one, run
`docker compose -f docker/docker-compose.mysql.yaml -f docker/docker-compose.mysql.keycloak.yaml exec keycloak /opt/keycloak/bin/kc.sh bootstrap-admin user`.

This stack has a known issue that this branch doesn't fix. Syncserver expects
`iss` to be `http://keycloak:7080/realms/sync`, but a client on the host (curl,
Thunderbird) gets tokens whose `iss` is `http://localhost:7080/realms/sync`, so
Tokenserver rejects them with 401. The fix suggested in review has three parts:
set `KC_HOSTNAME: http://localhost:7080` on Keycloak, set the issuer to
`http://localhost:7080/realms/sync`, and let syncserver reach that address
(host networking or an `extra_hosts` entry). Until that's done, use the
`cargo run` route above, where both sides see `localhost:7080`.

Neither the compose stack nor the e2e overlay
(`make docker_run_mysql_keycloak_e2e_tests`) has been run end to end on this
branch. `run-suite.sh` is the tested path.

## The dev realm

`keycloak/realm-export.json` is for local development and tests only. It holds
no passwords or client secrets, and its `test@test.com` user has no
credential. `start-services.sh` sets the `keycloak-revoker` client's secret
after import, and the integration tests create their own users and a test
client through the admin API. The realm stores the events the revoker needs
(see "Revocation" in docs/src/config.md).
