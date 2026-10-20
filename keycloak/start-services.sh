#!/usr/bin/env bash
# Start a fresh MySQL 8.0 and Keycloak 26.2.4 for keycloak/run-suite.sh.
#
# Usage, in the VM's own shell (not the devcontainer), with the devcontainer up:
#
#     keycloak/start-services.sh
#
# Both containers run under rootless podman in the devcontainer's network
# namespace, so inside the devcontainer MySQL is on localhost:3306 and Keycloak on
# localhost:7080. Any earlier containers of the same names are removed with their
# volumes, so the databases start empty. The MySQL root and Keycloak admin
# passwords and the client secret of the realm's keycloak-revoker client are
# generated into $SECRETS_DIR (mode 700, files mode 600) and copied to the same
# path inside the devcontainer. They are never printed.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
SECRETS_DIR=/tmp/syncstorage-test-secrets
MYSQL_IMAGE=docker.io/library/mysql:8.0
KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.2.4
MYSQL_CTR=syncstorage-test-mysql
KEYCLOAK_CTR=syncstorage-test-keycloak

devcontainer=$(podman ps -q --filter "label=devcontainer.local_folder=$REPO" | head -n1)
if [ -z "$devcontainer" ]; then
    echo "no running devcontainer for $REPO; start it first" >&2
    exit 1
fi

podman image exists "$MYSQL_IMAGE" || podman pull -q "$MYSQL_IMAGE" >/dev/null
podman image exists "$KEYCLOAK_IMAGE" || podman pull -q "$KEYCLOAK_IMAGE" >/dev/null
podman rm -f -v "$MYSQL_CTR" "$KEYCLOAK_CTR" >/dev/null 2>&1 || true

# Secrets: hex, so they can go in database URLs as they are
umask 077
rm -rf "$SECRETS_DIR"
mkdir -m 700 "$SECRETS_DIR"
openssl rand -hex 24 >"$SECRETS_DIR/mysql-root-password"
openssl rand -hex 24 >"$SECRETS_DIR/keycloak-admin-password"
openssl rand -hex 24 >"$SECRETS_DIR/keycloak-revoker-secret"
printf 'MYSQL_ROOT_PASSWORD=%s\n' "$(cat "$SECRETS_DIR/mysql-root-password")" >"$SECRETS_DIR/mysql.env"
printf 'KC_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$(cat "$SECRETS_DIR/keycloak-admin-password")" >"$SECRETS_DIR/keycloak.env"

podman run -d --name "$MYSQL_CTR" --network "container:$devcontainer" \
    --env-file "$SECRETS_DIR/mysql.env" \
    "$MYSQL_IMAGE" >/dev/null
podman run -d --name "$KEYCLOAK_CTR" --network "container:$devcontainer" \
    --env-file "$SECRETS_DIR/keycloak.env" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_HEALTH_ENABLED=true \
    -v "$REPO/keycloak/realm-export.json:/opt/keycloak/data/import/realm-export.json:ro" \
    "$KEYCLOAK_IMAGE" start-dev --http-port 7080 --import-realm >/dev/null

# Give the devcontainer's user (uid 1000) its own copy of the secrets, over stdin
podman exec -u 1000:1000 "$devcontainer" sh -c "rm -rf $SECRETS_DIR && mkdir -m 700 $SECRETS_DIR"
for f in mysql-root-password keycloak-admin-password keycloak-revoker-secret; do
    podman exec -i -u 1000:1000 "$devcontainer" sh -c "umask 077 && cat >$SECRETS_DIR/$f" <"$SECRETS_DIR/$f"
done

mysql_sql() {
    podman exec -i "$MYSQL_CTR" sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -h127.0.0.1 -uroot "$@"' mysql "$@"
}

# The entrypoint's first, temporary server doesn't listen on TCP, so this waits
# for the real one
echo "waiting for MySQL..."
for _ in $(seq 120); do
    if mysql_sql -e 'SELECT 1' >/dev/null 2>&1; then break; fi
    sleep 1
done
mysql_sql -e 'SELECT 1' >/dev/null
mysql_sql <<'SQL'
DROP DATABASE IF EXISTS syncstorage_rs;
DROP DATABASE IF EXISTS tokenserver_rs;
CREATE DATABASE syncstorage_rs;
CREATE DATABASE tokenserver_rs;
SQL

keycloak_ready() {
    podman exec "$KEYCLOAK_CTR" bash -c '
        exec 3<>/dev/tcp/localhost/9000 &&
        printf "GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&3 &&
        grep -q "200 OK" <&3 &&
        exec 4<>/dev/tcp/localhost/7080 &&
        printf "GET /realms/sync/.well-known/openid-configuration HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" >&4 &&
        grep -q "200 OK" <&4'
}
echo "waiting for Keycloak..."
for _ in $(seq 180); do
    if keycloak_ready >/dev/null 2>&1; then break; fi
    sleep 1
done
keycloak_ready

# The realm file has no secret for keycloak-revoker, so Keycloak generated one on
# import; replace it with ours, through the admin API from inside the devcontainer
# (where Keycloak is on localhost), reading both secrets from files there
echo "setting the keycloak-revoker client secret..."
podman exec -i -u 1000:1000 "$devcontainer" python3 -I - "$SECRETS_DIR" <<'PY'
import json
import sys
import urllib.parse
import urllib.request

secrets_dir = sys.argv[1]
base = "http://localhost:7080"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def read(name):
    with open(f"{secrets_dir}/{name}") as f:
        return f.read().strip()


def call(method, url, data=None, token=None, form=False):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if form:
        data = urllib.parse.urlencode(data).encode()
    elif data is not None:
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with opener.open(req, timeout=10) as res:
        body = res.read()
    return json.loads(body) if body else None


admin = call(
    "POST",
    f"{base}/realms/master/protocol/openid-connect/token",
    {
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": "admin",
        "password": read("keycloak-admin-password"),
    },
    form=True,
)["access_token"]
clients = f"{base}/admin/realms/sync/clients"
(client,) = call("GET", f"{clients}?clientId=keycloak-revoker", token=admin)
client["secret"] = read("keycloak-revoker-secret")
call("PUT", f"{clients}/{client['id']}", client, token=admin)
# Check that the service account can now get a token
call(
    "POST",
    f"{base}/realms/sync/protocol/openid-connect/token",
    {
        "grant_type": "client_credentials",
        "client_id": "keycloak-revoker",
        "client_secret": client["secret"],
    },
    form=True,
)
PY

for image in "$MYSQL_IMAGE" "$KEYCLOAK_IMAGE"; do
    echo "$image $(podman image inspect --format '{{.Digest}}' "$image")"
done
echo "MySQL (localhost:3306) and Keycloak (localhost:7080) are up in devcontainer $devcontainer."
echo "Next: devcontainer exec --workspace-folder $REPO -- keycloak/run-suite.sh"
