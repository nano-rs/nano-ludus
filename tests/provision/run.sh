#!/usr/bin/env bash
# Offline provisioning test for the aggregator's per-source ingest tokens
# (NAN-3841): runs tests/provision/provision.yml against mock_nano.py in
# several scenarios and checks what the role did. Needs ansible-core + python3.
#
#   bash tests/provision/run.sh
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROLE="$HERE/../../ansible/roles/nano_vector_aggregator"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/nano-ludus-provision.XXXXXX")
MOCK_PID=""
cleanup() { [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT
export ANSIBLE_FILTER_PLUGINS="$ROLE/filter_plugins"
export ANSIBLE_NOCOLOR=1 ANSIBLE_DEPRECATION_WARNINGS=0 ANSIBLE_LOCALHOST_WARNING=0 ANSIBLE_INVENTORY_UNPARSED_WARNING=0

fails=0
PORT=""
# Obviously fake, test-only: what nano_lean would have generated for the range.
( umask 077; printf 'test-password\n' > "$TMP/lab-admin-password" )
SOURCES='[{"source_id":"11111111-1111-4111-8111-111111111111","name":"Windows Event","source_type":"routed","route_key":"windows_event","enabled":true},
          {"source_id":"22222222-2222-4222-8222-222222222222","name":"Windows Sysmon","source_type":"routed","route_key":"windows_sysmon","enabled":true},
          {"source_id":"33333333-3333-4333-8333-333333333333","name":"Conduit","source_type":"splunk_hec","route_key":"conduit_proxy","enabled":true}]'

start_mock() { # <seed json>
    [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null; MOCK_PID=""
    printf '%s' "$1" > "$TMP/seed.json"; rm -f "$TMP/port"
    python3 -I "$HERE/mock_nano.py" "$TMP/seed.json" "$TMP/port" & MOCK_PID=$!
    for _ in $(seq 50); do [[ -s "$TMP/port" ]] && break; sleep 0.1; done
    PORT=$(cat "$TMP/port")
}

# play <case> <work dir> <expect: ok|fail> [grep for the failure] [extra vars json]
play() {
    local name=$1 dir=$2 expect=$3 want=${4:-} extra=${5:-'{}'}
    mkdir -p "$dir"
    python3 -I - "$TMP/vars.json" "$PORT" "$extra" "$TMP/lab-admin-password" <<'PY'
import json, sys
port = sys.argv[2]
v = {"nano_ingest_mode": "hec", "nano_api_url": f"http://127.0.0.1:{port}",
     "nano_ingest_url": f"http://127.0.0.1:{port}", "nano_api_password": "",
     # The range's generated lab admin password, as nano_lean leaves it on the controller.
     "nano_lab_admin_password_file": sys.argv[4],
     "nano_api_wait_retries": 1, "nano_api_wait_delay": 0, "inventory_hostname": "range-proxy"}
v.update(json.loads(sys.argv[3]))
json.dump(v, open(sys.argv[1], "w"))
PY
    local rc=0
    ansible-playbook -i "$HERE/../inventory.ini" "$HERE/provision.yml" -e "@$TMP/vars.json" \
        -e "work_dir=$dir" > "$TMP/$name.log" 2>&1 < /dev/null || rc=$?
    if [[ $expect == ok && $rc -ne 0 ]]; then
        echo "FAIL: $name: playbook failed"; grep -E 'FAILED|"msg"' "$TMP/$name.log" | head -5; fails=$((fails + 1)); return 1
    fi
    if [[ $expect == fail ]]; then
        if [[ $rc -eq 0 ]]; then echo "FAIL: $name: playbook passed, expected a failure"; fails=$((fails + 1)); return 1; fi
        if ! grep -q -- "$want" "$TMP/$name.log"; then
            echo "FAIL: $name: failure does not say \"$want\""; grep -E '"msg"' "$TMP/$name.log" | head -3; fails=$((fails + 1)); return 1
        fi
    fi
    # No token value may reach the log.
    if python3 -I - "$PORT" "$TMP/$name.log" "$TMP/vars.json" <<'PY'
import json, sys, urllib.request
state = json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/_state"))
log = open(sys.argv[2]).read()
given = json.load(open(sys.argv[3]))
values = [t["value"][12:] for t in state["tokens"]]
values += [v[12:] if v.startswith("nit_") else v for v in given.get("nano_ingest_source_tokens", {}).values()]
values += [given.get("nano_ingest_token", ""), given.get("nano_api_password", ""), given.get("nano_api_key", ""), "test-session", "test-password"]
leaked = [v for v in values if len(v) > 4 and v in log]
sys.exit(1 if leaked else 0)
PY
    then :; else echo "FAIL: $name: a token value is in the ansible output"; fails=$((fails + 1)); return 1; fi
    return 0
}

# check <case> <python asserting on S (mock state) and D (work dir)>
check() {
    local name=$1 code=$2
    if python3 -I - "$PORT" "$3" <<PY
import json, os, stat, sys, urllib.request
S = json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/_state"))
D = sys.argv[2]
def secret(st):
    p = os.path.join(D, "secrets", st)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600, f"{p} is not 0600"
    return open(p).read().strip()
def active(route):
    ids = {"windows_event": "11111111-1111-4111-8111-111111111111", "windows_sysmon": "22222222-2222-4222-8222-222222222222", "conduit_proxy": "33333333-3333-4333-8333-333333333333"}
    return [t for t in S["tokens"] if t.get("source_id") == ids[route] and not t.get("revoked")]
$code
PY
    then echo "ok   $name"; else echo "FAIL: $name: state check"; fails=$((fails + 1)); fi
}

W="$TMP/range"
# 1. Fresh range: one token issued per source, each bound to its own source.
start_mock "{\"model\":\"bound\",\"sources\":$SOURCES,\"tokens\":[]}"
play create "$W" ok && check create '
assert S["calls"].count("create") == 3, S["calls"]
for st in ("windows_event", "windows_sysmon", "conduit_proxy"):
    a = active(st); assert len(a) == 1, (st, a)
    assert secret(st) == a[0]["value"], st
state = json.load(open(os.path.join(D, "ingest-credentials.json")))
assert sorted(state) == ["conduit_proxy", "windows_event", "windows_sysmon"], state
assert all(not v.startswith("nit_") for v in state.values()), "state file holds a token value"
assert not os.path.exists(os.path.join(D, "secrets", "default"))
assert sorted(e["route"] for e in S["events"]) == ["conduit_proxy", "windows_event", "windows_sysmon"], S["events"]
' "$W"

# 2. Second run: the same tokens are reused, nothing issued or revoked.
play reuse "$W" ok && check reuse '
assert S["calls"].count("create") == 3 and "revoke" not in S["calls"], S["calls"]
' "$W"

# 3. A lost token file: a new token replaces it and the old one is revoked.
rm -f "$W/secrets/windows_sysmon"
play rotate "$W" ok && check rotate '
assert S["calls"].count("create") == 4 and S["calls"].count("revoke") == 1, S["calls"]
assert len(active("windows_sysmon")) == 1 and secret("windows_sysmon") == active("windows_sysmon")[0]["value"]
' "$W"

# 4. An operator-supplied unbound nit_ token is bound to its source (API key auth).
UNBOUND=nit_unbound1aaaaaaaaaaaaaaaaaaaaaaaa
start_mock "{\"model\":\"bound\",\"sources\":$SOURCES,\"tokens\":[{\"credential_id\":\"c-unbound\",\"name\":\"old fw\",\"value\":\"$UNBOUND\",\"source_id\":null}]}"
play bind "$TMP/bind" ok "" "{\"nano_api_key\":\"test-api-key\",\"nano_api_password\":\"\",\"nano_ingest_source_tokens\":{\"windows_event\":\"$UNBOUND\"}}" && check bind '
assert S["calls"].count("bind") == 1 and S["calls"].count("create") == 2, S["calls"]
assert [t["credential_id"] for t in active("windows_event")] == ["c-unbound"]
assert secret("windows_event").startswith("nit_unbound1")
' "$TMP/bind"

# 5. An operator token bound to a different source fails: bindings never change.
WRONG=nit_wrongsrcaaaaaaaaaaaaaaaaaaaaaaaa
start_mock "{\"model\":\"bound\",\"sources\":$SOURCES,\"tokens\":[{\"credential_id\":\"c-wrong\",\"name\":\"sysmon\",\"value\":\"$WRONG\",\"source_id\":\"22222222-2222-4222-8222-222222222222\"}]}"
play wrong-source "$TMP/wrong" fail "Bindings never change" "{\"nano_ingest_source_tokens\":{\"windows_event\":\"$WRONG\"}}" && check wrong-source '
assert "create" not in S["calls"] and "bind" not in S["calls"], S["calls"]
' "$TMP/wrong"

# 6. A forwarded source with no log source on nano fails clearly.
start_mock "{\"model\":\"bound\",\"sources\":$(python3 -I -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])[:2]))' "$SOURCES"),\"tokens\":[]}"
play missing-source "$TMP/missing" fail "no log source with route key 'conduit_proxy'" && check missing-source '
assert "create" not in S["calls"], S["calls"]
' "$TMP/missing"

# 7. A token nano refuses (not nano-issued, not bound) fails the post-start check with the bind hint.
start_mock "{\"model\":\"bound\",\"sources\":$SOURCES,\"tokens\":[]}"
play unbound-401 "$TMP/u401" fail "it is not bound to a log source" '{"nano_ingest_source_tokens":{"windows_event":"external-token-0123456789"}}'

# Old APIs must fail closed, even with a shared install token supplied.
start_mock "{\"model\":\"legacy\",\"sources\":[],\"tokens\":[]}"
play legacy "$TMP/legacy" fail "predates per-source ingest tokens"
start_mock "{\"model\":\"missing\",\"sources\":[],\"tokens\":[]}"
play pre-api "$TMP/preapi" fail "predates per-source ingest tokens"
play shared-token "$TMP/shared" fail "Every source requires its own bound token" '{"nano_ingest_token":"install-token-0123456789"}'

# 10. A wrong admin password fails with what to set.
start_mock "{\"model\":\"bound\",\"sources\":$SOURCES,\"tokens\":[]}"
play bad-login "$TMP/badlogin" fail "rejected the login" '{"nano_api_password":"nope"}' && echo "ok   bad-login"
# 11. No generated password on the controller (the SIEM role never ran) and no override: fail
#     and say where the password should be.
play no-lab-password "$TMP/nolabpw" fail "generated lab admin password is not at" "{\"nano_lab_admin_password_file\":\"$TMP/does-not-exist\"}" && echo "ok   no-lab-password"

# Current senders cannot bypass source authentication via native Vector or a reused credential.
play raw-vector "$TMP/raw" fail "requires authenticated HEC" '{"nano_ingest_mode":"vector"}'
play duplicated-token "$TMP/duplicate" fail "Each source must have a distinct token" \
    '{"nano_ingest_source_tokens":{"windows_event":"same-test-credential-0123456789","windows_sysmon":"same-test-credential-0123456789"}}'

for c in unbound-401 legacy pre-api shared-token raw-vector duplicated-token; do echo "ok   $c (failed as expected)"; done

echo
if (( fails > 0 )); then echo "provision: $fails failure(s)"; exit 1; fi
echo "provision: all passed"
