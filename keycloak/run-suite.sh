#!/usr/bin/env bash
# Build, lint and test this branch (MySQL storage, Keycloak/OIDC tokenserver).
#
# Usage, from the VM after keycloak/start-services.sh:
#
#     devcontainer exec --workspace-folder /work -- keycloak/run-suite.sh
#
# Runs, in order, on the fresh databases:
#   (a) cargo build of the OIDC build (MySQL, no py_verifier)
#   (b) cargo fmt --check; clippy of the OIDC build; make clippy_mysql (upstream CI)
#   (c) every Rust test in the workspace for the OIDC build, against MySQL
#   (d) tools/integration_tests (with tokenserver/) against syncserver in OIDC mode
# (c) runs before (d) because test_storage.py leaves collections behind that break
# syncstorage-mysql's static_collection_id test. Exits non-zero if any step fails.
# Secrets are read from the files start-services.sh wrote and masked in all output.
set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
SECRETS_DIR=/tmp/syncstorage-test-secrets
LOG_DIR=/tmp/syncstorage-suite
OIDC_FEATURES=(--no-default-features --features=syncstorage-db/mysql)
# Spanner/GCS only: needs the payload-link reconciliation stack (GCS, Pub/Sub)
PYTEST_EXCLUDE=(--ignore="$REPO/tools/integration_tests/test_payload_link_reconciliation.py")
POETRY_VERSION=2.5.1

mask() {
    python3 -I -u -c '
import sys
secrets = [open(p).read().strip() for p in sys.argv[1:]]
for line in sys.stdin:
    for s in secrets:
        line = line.replace(s, "********")
    sys.stdout.write(line)
' "$SECRETS_DIR/mysql-root-password" "$SECRETS_DIR/keycloak-admin-password"
}

summary=()
failed=0
step() {
    local name=$1 start=$SECONDS result
    shift
    echo "=== $name: $*"
    if "$@"; then result=PASS; else result=FAIL; failed=1; fi
    summary+=("$name: $result ($((SECONDS - start))s)")
    echo "=== $name: $result in $((SECONDS - start))s"
}

# Sums the "test result:" lines of cargo test
cargo_test() {
    cargo test --workspace "${OIDC_FEATURES[@]}" 2>&1 | tee "$LOG_DIR/cargo-test.log"
    local rc=${PIPESTATUS[0]}
    awk '/^test result:/ { p += $4; f += $6; i += $8; s++ }
        END { printf "cargo test totals: %d passed, %d failed, %d ignored, %d test binaries\n", p, f, i, s }' \
        "$LOG_DIR/cargo-test.log"
    return "$rc"
}

poetry_install() {
    if [ ! -x /tmp/poetry/bin/poetry ]; then
        python3 -m venv /tmp/poetry && /tmp/poetry/bin/pip install -q "poetry==$POETRY_VERSION" || return 1
    fi
    /tmp/poetry/bin/poetry -C tools/integration_tests install --no-interaction --no-root
}

integration_tests() {
    local pid rc=0
    "${CARGO_TARGET_DIR:-$REPO/target}/debug/syncserver" >"$LOG_DIR/syncserver.log" 2>&1 &
    pid=$!
    for _ in $(seq 120); do
        curl -fsS http://localhost:8000/__heartbeat__ >/dev/null 2>&1 && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if curl -fsS http://localhost:8000/__heartbeat__; then
        echo
        PYTHONPATH="$REPO/tools" /tmp/poetry/bin/poetry -C tools/integration_tests run \
            pytest "$REPO/tools/integration_tests" "${PYTEST_EXCLUDE[@]}" \
            -p no:cacheprovider -rs --durations=5 || rc=$?
    else
        echo "syncserver didn't become healthy"
        rc=1
    fi
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    if [ "$rc" -ne 0 ]; then
        echo "--- last lines of syncserver log:"
        tail -n 50 "$LOG_DIR/syncserver.log"
    fi
    return "$rc"
}

main() {
    cd "$REPO" || return 1
    echo "rustc: $(rustc --version)"
    echo "cargo: $(cargo --version)"
    echo "clippy: $(cargo clippy --version)"
    echo "rustfmt: $(cargo fmt --version)"
    echo "python: $(python3 --version)"

    local mysql_pw keycloak_pw db
    mysql_pw=$(cat "$SECRETS_DIR/mysql-root-password") || return 1
    keycloak_pw=$(cat "$SECRETS_DIR/keycloak-admin-password") || return 1
    db="mysql://root:$mysql_pw@127.0.0.1:3306"
    # Env shared by cargo test, syncserver and pytest (as in the Makefile and the
    # MySQL e2e compose files), plus the OIDC settings
    export SYNC_SYNCSTORAGE__DATABASE_URL="$db/syncstorage_rs"
    export SYNC_TOKENSERVER__DATABASE_URL="$db/tokenserver_rs"
    export RUST_TEST_THREADS=1
    export SYNC_HOST=127.0.0.1 SYNC_PORT=8000
    export SYNC_MASTER_SECRET=secret0
    export SYNC_TOKENSERVER__ENABLED=true
    export SYNC_TOKENSERVER__NODE_TYPE=mysql
    export SYNC_TOKENSERVER__RUN_MIGRATIONS=true
    export SYNC_TOKENSERVER__FXA_EMAIL_DOMAIN=api-accounts.stage.mozaws.net
    export SYNC_TOKENSERVER__FXA_METRICS_HASH_SECRET=secret0
    export SYNC_TOKENSERVER__OAUTH_PROVIDER=oidc
    export SYNC_TOKENSERVER__OIDC_ISSUER_URL=http://localhost:7080/realms/sync
    export SYNC_TOKENSERVER__OIDC_AUDIENCE=tokenserver
    # The client tools/integration_tests/tokenserver/helpers.py mints tokens through
    export SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS=tokenserver-tests
    export SYNC_SERVER_URL=http://localhost:8000
    export TOKENSERVER_HOST=http://localhost:8000
    export KEYCLOAK_ADMIN_USERNAME=admin
    export KEYCLOAK_ADMIN_PASSWORD="$keycloak_pw"
    export SQLALCHEMY_SILENCE_UBER_WARNING=1

    step "(a) build" cargo build "${OIDC_FEATURES[@]}"
    step "(b) fmt" cargo fmt -- --check
    step "(b) clippy OIDC" cargo clippy --workspace --all-targets "${OIDC_FEATURES[@]}" \
        -- -D clippy::dbg_macro -D warnings
    # PyO3 (py_verifier) needs a Python with a shared libpython, as on upstream CI's
    # runners; the devcontainer's default python3 is a static build
    step "(b) make clippy_mysql" env PYO3_PYTHON=/usr/bin/python3 make clippy_mysql
    step "(c) cargo test" cargo_test
    step "(d) poetry install" poetry_install
    step "(d) integration tests" integration_tests

    echo "=== summary"
    printf '%s\n' "${summary[@]}"
    return "$failed"
}

mkdir -p -m 700 "$LOG_DIR"
main 2>&1 | mask
exit "${PIPESTATUS[0]}"
