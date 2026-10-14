#!/usr/bin/env bash
# NAN-3397 role checks. Needs ansible-core + ansible-lint (with the
# ansible.windows / community.windows / community.general collections and the
# geerlingguy.docker role on their search paths) and docker.
#
#   bash tests/check.sh
#
# 1. ansible-lint over the roles and tests
# 2. ansible-playbook --syntax-check over every role
# 3. policy: the blueprint deploys no gen1 piece, no role mentions the retired
#    legacy (ClickHouse) or gen1 lake profiles, every Vector is the pinned 0.59
#    release, no token lands in a 0644 config, nothing routes on a declared
#    source type and the range shares no token across sources (NAN-3841)
# 4. render every scenario's Vector configs with the roles' own templates
# 5. `vector validate` each rendered config with the platform's Vector (0.59)
# 6. per-source token provisioning against a mock nano API (tests/provision)
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VECTOR_IMAGE=${VECTOR_IMAGE:-timberio/vector:0.59.0-alpine@sha256:0e36bc2a290039e9b6a5e92f04bd2f133223506f72d09682c1df16c015172b7a}
OUT=$(mktemp -d "${TMPDIR:-/tmp}/nano-ludus-check.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
export ANSIBLE_ROLES_PATH="$ROOT/ansible/roles${ANSIBLE_ROLES_PATH:+:$ANSIBLE_ROLES_PATH}"
export ANSIBLE_NOCOLOR=1 ANSIBLE_DEPRECATION_WARNINGS=0 ANSIBLE_LOCALHOST_WARNING=0 ANSIBLE_INVENTORY_UNPARSED_WARNING=0

fails=0
step() { printf '\n== %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; fails=$((fails + 1)); }

step "ansible-lint"
(cd "$ROOT" && ansible-lint --offline -q ansible/roles tests < /dev/null) || bad "ansible-lint"

step "syntax-check"
ansible-playbook -i "$ROOT/tests/inventory.ini" --syntax-check "$ROOT/tests/syntax.yml" < /dev/null || bad "syntax-check"

step "policy"
python3 - "$ROOT" <<'PY' || fails=$((fails + 1))
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
errs = []
roles_dir = root / "ansible/roles"
vendored = {p.name for p in roles_dir.iterdir() if p.is_dir()}
rc = (root / "blueprints/nanosiem/range-config.yml").read_text()
for ref in sorted(set(re.findall(r"^\s*-\s+(?:name:\s+)?(NanoSIEM\.[a-z_]+)\s*$", rc, re.M))):
    name = ref.split(".", 1)[1]
    if name not in vendored:
        errs.append(f"range-config uses {ref} but ansible/roles/{name} is not vendored")
for gone in ("nano_stack", "nano_lake"):
    if gone in vendored:
        errs.append(f"ansible/roles/{gone} (gen1) is still a deployable role")
    if re.search(rf"^\s*-\s+(?:name:\s+)?NanoSIEM\.{gone}\s*$", rc, re.M):
        errs.append(f"range-config still deploys the gen1 {gone}")
if not re.search(r"^\s*-\s+(?:name:\s+)?NanoSIEM\.nano_lean\s*$", rc, re.M):
    errs.append("range-config does not deploy the open-core lean install (NanoSIEM.nano_lean)")
# NAN-3841: nano binds each ingest token to one source (NAN-3806), so the
# blueprint must not hand the aggregator one shared token for every source.
if re.search(r"^\s+nano_ingest_token:", rc, re.M):
    errs.append("range-config gives the aggregator a shared nano_ingest_token; nano binds each token to one source")
# NAN-3841: this repo is public. No committed admin password, API key or
# ingest token may ship as a default: the lab admin password is generated per
# range on the controller.
secret_keys = r"(nano_lean_admin_password|nano_api_password|nano_api_key|nano_lean_ingest_token|nano_ingest_token)"
for p in [root / "blueprints/nanosiem/range-config.yml", *roles_dir.glob("*/defaults/main.yml")]:
    for m in re.finditer(rf"^\s*{secret_keys}:\s*(\S.*)$", p.read_text(), re.M):
        if m.group(2).strip() not in ('""', "''"):
            errs.append(f"{p.relative_to(root)}: {m.group(1)} has a committed value; secrets are generated or supplied, never defaults")
for p in [root / "README.md", root / "blueprints/nanosiem/range-config.yml", *roles_dir.rglob("*")]:
    if p.is_file() and re.search(r"change-?me", p.read_text(errors="ignore"), re.I):
        errs.append(f"{p.relative_to(root)}: a placeholder credential (change-me) is committed")
for p in roles_dir.rglob("*"):
    if not p.is_file() or p.suffix == ".pyc":
        continue
    t = p.read_text(errors="ignore")
    rel = p.relative_to(root)
    for m in re.finditer(r"timberio/vector:[^\s\"']+", t):
        if not re.fullmatch(r"timberio/vector:0\.59\.0-[a-z]+@sha256:[0-9a-f]{64}", m.group(0)):
            errs.append(f"{rel}: unpinned or non-0.59 Vector image {m.group(0)}")
    if re.search(r"vector/nightly|vector-nightly", t):
        errs.append(f"{rel}: installs a Vector nightly")
    # ClickHouse (legacy profile) and the gen1 lake profile are gone from the
    # product (NAN-3491); no role may configure or depend on them.
    if re.search(r"clickhouse|COMPOSE_PROFILES=(legacy|lake)\b|NANO_ENABLE_LAKE_CONTROL_PLANE", t, re.I):
        errs.append(f"{rel}: references ClickHouse or the gen1 lake profile")
    # The token decides the source; a source-type header routes nothing.
    if re.search(r"X-Source-Type", t, re.I):
        errs.append(f"{rel}: sends X-Source-Type; nano routes on the token alone (NAN-3806)")
for e in errs:
    print("FAIL:", e)
print("policy:", "ok" if not errs else f"{len(errs)} problem(s)")
sys.exit(1 if errs else 0)
PY

step "render + vector validate (${VECTOR_IMAGE%@*})"
for sc in "$ROOT"/tests/scenarios/*.yml; do
    name=$(basename "$sc" .yml)
    dir="$OUT/$name"
    if ! ansible-playbook -i "$ROOT/tests/inventory.ini" "$ROOT/tests/render.yml" \
            -e "@$sc" -e "out_dir=$dir" > "$OUT/$name.render.log" 2>&1 < /dev/null; then
        bad "$name: render failed"; grep -E 'FAILED|msg' "$OUT/$name.render.log" | head -5; continue
    fi
    # Vector >= 0.57 no longer interpolates ${VAR} in config files (it is
    # opt-in behind --dangerously-allow-env-var-interpolation), so a ${...}
    # left in a config is sent literally - e.g. as the HEC token.
    for f in "$dir"/*.toml; do
        if grep -n '\${' "$f"; then bad "$name: $(basename "$f") relies on \${VAR} interpolation (off by default since Vector 0.57)"; fi
        # A scheme-less `vector` sink address is deprecated in 0.59 and will
        # flip from http to https.
        if grep -n -E '^address = "[0-9{]' "$f" | grep -v -E '0\.0\.0\.0'; then
            if awk '/^\[sinks\./{s=1} /^\[sources\./{s=0} s && /^address = "[^h]/' "$f" | grep -q .; then
                bad "$name: $(basename "$f") has a scheme-less vector sink address"
            fi
        fi
    done
    # No scenario token may appear in a world-readable config.
    for f in "$dir"/*.toml "$dir"/*-compose.yml; do
        [[ -e "$f" ]] || continue
        if grep -q 'TESTTOKEN-' "$f"; then bad "$name: a token leaked into $(basename "$f")"; fi
    done
    for cfg in "$dir"/*.toml; do
        base=$(basename "$cfg")
        envargs=()
        if [[ "$base" == aggregator.toml ]]; then
            envargs=(-v "$dir/secrets:/etc/vector/secrets:ro")
        fi
        if [[ "$base" == agent.toml ]]; then
            # windows_event_log is compiled into the Windows build only; validate
            # the rest of the agent pipeline against a stdin stand-in on Linux.
            python3 - "$cfg" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s, n = re.subn(r'(\[sources\.windows_events\]\n)type = "windows_event_log"\n(?:[a-z_]+ = .*\n)*',
               r'\1type = "stdin"\n', s)
assert n == 1, "agent config: windows_events source block not found"
s = s.replace('data_dir = "C:/ProgramData/Vector/data"', 'data_dir = "/tmp"')
open(p, "w").write(s)
PY
        fi
        if docker run --rm "${envargs[@]}" -v "$dir:/cfg:ro" "$VECTOR_IMAGE" \
                validate --no-environment "/cfg/$base" > "$OUT/$name.$base.validate.log" 2>&1; then
            echo "ok   $name/$base"
        else
            bad "$name/$base: vector validate"; sed -n '1,25p' "$OUT/$name.$base.validate.log"
        fi
    done
done
step "token provisioning (mock nano API)"
bash "$ROOT/tests/provision/run.sh" < /dev/null || bad "token provisioning"

if [[ -n "${KEEP_RENDERED:-}" ]]; then rm -rf "$KEEP_RENDERED"; cp -r "$OUT" "$KEEP_RENDERED"; echo "rendered configs kept in $KEEP_RENDERED"; fi

echo
if (( fails > 0 )); then echo "check: $fails failure(s)"; exit 1; fi
echo "check: all passed"
