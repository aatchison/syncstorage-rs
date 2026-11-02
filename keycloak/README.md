# Keycloak (OIDC) build: build, test and run

This branch adds a generic OpenID Connect back end to Tokenserver, tested
against Keycloak, and `tools/keycloak_revoker`, which ends a user's Sync
access when Keycloak alone would leave it alive (password resets and changes,
deletions). This page says how to build it, how to run its test suite, and how
to run it locally. What Tokenserver checks in a token, and the settings, are in
[docs/src/config.md](../docs/src/config.md) ("OIDC mode (Keycloak)"); how to
deploy the revoker is in
[tools/keycloak_revoker/README.md](../tools/keycloak_revoker/README.md).

Files:

| Path | What it is |
| --- | --- |
| `keycloak/start-services.sh` | Starts a fresh MySQL 8.0 and Keycloak 26.2.4 for the suite |
| `keycloak/run-suite.sh` | Builds, lints and runs every test for this build |
| `keycloak/realm-export.json` | The `sync` realm, for local development only |
| `config/local.keycloak.toml` | Config for `cargo run` against a local Keycloak |
| `Dockerfile.keycloak` | `./Dockerfile` without `py_verifier` |
| `docker/docker-compose.mysql.keycloak.yaml` | Overlay: syncserver + Keycloak dev stack |
| `docker/docker-compose.e2e.mysql.keycloak.yaml` | Overlay: the integration tests in compose |

## Build

The OIDC verifier is the native one, so build without `py_verifier`. With
`py_verifier`, syncserver refuses to start with
`SYNC_TOKENSERVER__OAUTH_PROVIDER=oidc`.

```shell
cargo build --no-default-features --features=syncstorage-db/mysql
make clippy_mysql_oidc     # clippy for this build, warnings as errors
```

The toolchain is Rust 1.98.1, as in `Cargo.toml` and upstream CI. The
devcontainer (`.devcontainer/`) has it, with the MySQL client and build
packages.

A container image: `Dockerfile.keycloak`, for example through
`make docker_start_mysql_keycloak` (see [Run locally](#run-locally)).

## Test

The whole suite is two commands. `start-services.sh` runs on the host that runs
the devcontainer (it needs rootless podman and a running devcontainer for this
checkout), and `run-suite.sh` runs inside the devcontainer:

```shell
devcontainer up --workspace-folder .        # once
keycloak/start-services.sh                   # before every run: fresh databases and Keycloak
devcontainer exec --workspace-folder . -- keycloak/run-suite.sh
```

`start-services.sh` starts MySQL and Keycloak in the devcontainer's network
namespace (MySQL on `localhost:3306`, Keycloak on `localhost:7080`), removes
any earlier containers and their volumes, and generates the MySQL root
password, the Keycloak admin password and the revoker's client secret into
`/tmp/syncstorage-test-secrets`, on the host and in the devcontainer. They are
never printed, and `run-suite.sh` masks them in its output.
`make test_mysql_oidc_suite` runs the same `run-suite.sh`.

`run-suite.sh` runs, in order, and prints a PASS/FAIL summary; it exits
non-zero if any step fails:

| Step | What | Expected at `8af24074` |
| --- | --- | --- |
| (a) | `cargo build` of the OIDC build | pass |
| (b) | `cargo fmt --check`, clippy for the OIDC build, `make clippy_mysql` | pass |
| (c) | `cargo test --workspace` for the OIDC build, against MySQL | 271 passed |
| (d) | `tools/integration_tests` against syncserver in OIDC mode | 102 passed, 1 skipped |
| (e) | `tools/tokenserver` (with `-o addopts=`, so `migration_records` runs) | 44 passed |
| (f) | `tools/keycloak_revoker/tests` (unit) | 177 passed |
| (g) | `tools/keycloak_revoker/live` (revocation against the real Keycloak) | 17 passed |

In (d), upstream's two batch-id probes (`test_storage.py:2149` and `:2177`)
skip themselves when they fail to trigger the case they look for, so 101
passed and 2 skipped is the same result. `test_payload_link_reconciliation.py`
is excluded (Spanner/GCS only), and the Rust tests behind
`#[cfg(feature = "spanner")]` aren't built.

A cold run takes about 7 minutes (most of it the first build and clippy);
later runs take about a minute. Logs are in `/tmp/syncstorage-suite` inside
the devcontainer. To run one part by hand, export the variables that
`run-suite.sh`'s `main()` exports and run that step's command.

Network: the first build fetches crates and, in `utoipa-swagger-ui`'s build
script, Swagger UI from github.com; the Python steps install poetry 2.5.1 and
the dependencies from PyPI; `start-services.sh` pulls the two images if they
are missing.

### On pine

On pine the suite runs in a disposable worker VM, through `~/bin/worker-run`
as `techne`: the worker-devc image has rootless podman and the devcontainer
CLI, the worktree is mounted at `/work` (`/workspaces/work` in the
devcontainer), egress goes through the allowlist proxy, and no credentials
enter the VM. This is how VERIFY-5 ran (3 runs out of 3 green at `8af24074`,
2026-10-23).

1. Make a worktree of the commit to test:

   ```shell
   cd ~/orca/projects/syncstorage-rs
   orca worktree create --repo path:$PWD --name kc-test --base-branch keycloak-rebase --setup skip
   ```

2. Start a worker on it. The devcontainer is built and started before the
   agent, with docker-in-docker, kind and kubectl left out (the suite uses the
   VM's podman, not Docker):

   ```shell
   WORKER_DEVCONTAINER=1 WORKER_DEVC_SKIP_FEATURES=docker-in-docker,kind,kubectl \
   WORKER_CPUS=8 WORKER_MEM=16GiB WORKER_DISK=80GiB \
   WORKER_DEVC_ENV="CARGO_TARGET_DIR=/tmp/cargo-target" \
   ~/bin/worker-run -m claude-sonnet-5-5 kc-test \
       ~/orca/workspaces/syncstorage-rs/kc-test claude \
       "Run keycloak/start-services.sh, then
        timeout 1800 devcontainer exec --workspace-folder /work -- keycloak/run-suite.sh,
        and report the summary. Don't change any file."
   ```

   `WORKER_IMAGE=syncstorage-kc-cache` starts from a snapshot with the
   devcontainer, a warm target dir and both service images already in it, so
   the first run is fast. It was taken at an earlier commit; cargo rebuilds
   what changed.

3. A worker can't push and holds no credentials. Close its Orca tab when it
   is done: that deletes the VM. Then remove the worktree with
   `orca worktree rm --worktree path:<dir>`.

To run the commands yourself instead of through an agent, open a shell in the
VM while it runs: `incus exec w-kc-test --user $(id -u) --cwd /work -- bash -l`,
and run the commands from [Test](#test) with `--workspace-folder /work`. (Not
exercised yet; the agent route is the one that has been run.)

## Run locally

### With cargo

Against the Keycloak from `start-services.sh` or the compose stack below
(Keycloak on `localhost:7080` with the `sync` realm) and a MySQL on
`localhost:3306`:

```shell
cp config/local.keycloak.toml /tmp/local.keycloak.toml
# in the copy, set master_secret, fxa_metrics_hash_secret and the two
# database_url values (the config's defaults are test:test@localhost:3306,
# databases syncstorage and tokenserver)
cargo run --no-default-features --features=syncstorage-db/mysql \
    -- --config /tmp/local.keycloak.toml
```

It accepts access tokens from the realm's `public-client` that carry the
`https://identity.mozilla.com/apps/oldsync` scope (an optional scope the client
must ask for), and creates the `http://localhost:8000` node on startup.

### With docker compose

```shell
make docker_start_mysql_keycloak    # builds Dockerfile.keycloak, starts MySQL, Keycloak, syncserver
make docker_stop_mysql_keycloak
```

Keycloak is on `http://localhost:7080`, syncserver on `http://localhost:8000`.
There is no admin user; create one with
`docker compose -f docker/docker-compose.mysql.yaml -f docker/docker-compose.mysql.keycloak.yaml exec keycloak /opt/keycloak/bin/kc.sh bootstrap-admin user`.

Known issue, not fixed on this branch: in this stack syncserver expects
`iss` = `http://keycloak:7080/realms/sync`, but a client on the host (curl,
Thunderbird) gets tokens with `iss` = `http://localhost:7080/realms/sync`, so
Tokenserver refuses them with 401. The fix suggested in review is
`KC_HOSTNAME: http://localhost:7080` on Keycloak, the issuer set to
`http://localhost:7080/realms/sync`, and a way for syncserver to reach that
address (host networking or an `extra_hosts` entry). Until then, use the
`cargo run` route above, where both sides see `localhost:7080`.

The compose route and the e2e overlay (`make docker_run_mysql_keycloak_e2e_tests`)
haven't been run end to end on this branch; `run-suite.sh` is the tested path.

## The dev realm

`keycloak/realm-export.json` is for local development and tests only. It has
no passwords or client secrets (its `test@test.com` user has no credential): `start-services.sh` sets the
`keycloak-revoker` client's secret after import, and the integration tests
create their own users and a test client through the admin API. It stores the
events the revoker needs (see docs/src/config.md, "Revocation").
