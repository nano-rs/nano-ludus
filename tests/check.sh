#!/usr/bin/env bash
# nano-ludus v2 policy, render, Vector and source-bound-token checks.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VECTOR_IMAGE=${VECTOR_IMAGE:-timberio/vector:0.61.0-alpine@sha256:3bb7ed5152910ed51729e256937b1d8a4bf67ff624e9d565e8e5877bffd015c7}
OUT=$(mktemp -d "${TMPDIR:-/tmp}/nano-ludus-check.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
export ANSIBLE_ROLES_PATH="$ROOT/ansible/roles${ANSIBLE_ROLES_PATH:+:$ANSIBLE_ROLES_PATH}"
export ANSIBLE_NOCOLOR=1 ANSIBLE_DEPRECATION_WARNINGS=0
export ANSIBLE_LOCALHOST_WARNING=0 ANSIBLE_INVENTORY_UNPARSED_WARNING=0
export VECTOR_IMAGE

fails=0
step() { printf '\n== %s\n' "$*"; }
bad()  { printf 'FAIL: %s\n' "$*"; fails=$((fails + 1)); }

step "ansible-lint"
(cd "$ROOT" && ansible-lint --offline -q ansible/roles tests < /dev/null) || bad "ansible-lint"

step "syntax-check"
ansible-playbook -i "$ROOT/tests/inventory.ini" --syntax-check "$ROOT/tests/syntax.yml" < /dev/null     || bad "syntax-check"

step "v2 policy"
python3 - "$ROOT" <<'PY' || fails=$((fails + 1))
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
roles_dir = root / "ansible/roles"
range_config = (root / "blueprints/nanosiem/range-config.yml").read_text()
errs = []
vendored = {p.name for p in roles_dir.iterdir() if p.is_dir()}

for ref in sorted(set(re.findall(r"^\s*-\s+(?:name:\s+)?(NanoSIEM\.[a-z_]+)\s*$", range_config, re.M))):
    name = ref.split(".", 1)[1]
    if name not in vendored:
        errs.append(f"range-config uses {ref} but ansible/roles/{name} is not vendored")

if "nano_stack" not in vendored:
    errs.append("ansible/roles/nano_stack is missing")
if not re.search(r"^\s*-\s+(?:name:\s+)?NanoSIEM\.nano_stack\s*$", range_config, re.M):
    errs.append("range-config does not deploy NanoSIEM.nano_stack")
for gone in ("nano_lean", "nano_lake"):
    if gone in vendored:
        errs.append(f"retired role ansible/roles/{gone} is still vendored")
    if re.search(rf"^\s*-\s+(?:name:\s+)?NanoSIEM\.{gone}\s*$", range_config, re.M):
        errs.append(f"range-config deploys retired role {gone}")

policy_files = [
    root / "README.md",
    root / "source.yml",
    *root.glob("blueprints/**/*.yml"),
    *roles_dir.rglob("*"),
]
for p in policy_files:
    if not p.is_file() or p.suffix == ".pyc":
        continue
    text = p.read_text(errors="ignore")
    rel = p.relative_to(root)
    for pattern, label in (
        (r"RustFS", "object-store component"),
        (r"nano-lake-cell", "retired cell service"),
        (r"COMPOSE_PROFILES\s*=\s*lean\b", "retired compose profile"),
        (r"NANO_ENABLE_LAKE_CONTROL_PLANE", "retired control-plane flag"),
    ):
        if re.search(pattern, text, re.I):
            errs.append(f"{rel}: references {label}")
    if re.search(r"X-Source-Type", text, re.I):
        errs.append(f"{rel}: sends X-Source-Type; v2 routes on the token")
    if re.search(r"change-?me", text, re.I):
        errs.append(f"{rel}: contains a placeholder credential")

stack_text = "\n".join(
    p.read_text(errors="ignore")
    for p in (roles_dir / "nano_stack").rglob("*")
    if p.is_file()
)
if "NANO_SCHEMA_PROFILE" not in stack_text or "ocsf" not in stack_text.lower():
    errs.append("nano_stack does not select the OCSF installer profile")
stack_defaults = (roles_dir / "nano_stack/defaults/main.yml").read_text()
if 'nanosiem_ref: "main"' not in stack_defaults or 'nanosiem_version: "2.0.0"' not in stack_defaults:
    errs.append("nano_stack does not use public main with the v2.0.0 release pin")
if "ClickHouse" not in stack_text:
    errs.append("nano_stack does not identify the v2 ClickHouse contract")
if "grep -qw avx2 /proc/cpuinfo" not in stack_text or "x86-64-v3" not in stack_text:
    errs.append("nano_stack does not preflight the ClickHouse AVX2 requirement")
if "lookup('ansible.builtin.env', 'HOME')" in stack_text or "delegate_to: localhost" in stack_text:
    errs.append("nano_stack writes secrets on the Ludus controller instead of the SIEM")
if "--non-interactive" in stack_text or "NANO_NONINTERACTIVE" in stack_text:
    errs.append("nano_stack uses an installer flag/env not present in the v2 contract")
if "/opt/nanosiem/docker-compose.yml" not in stack_text or "down --remove-orphans" not in stack_text:
    errs.append("nano_stack does not retire the exact pre-v2 Ludus compose stack")
if re.search(r"docker compose[^\n]*down[^\n]*(?:--volumes|(?:^|\s)-v(?:\s|$))", stack_text):
    errs.append("nano_stack deletes pre-v2 data volumes during migration")
for parser in ("windows_event", "windows_sysmon", "conduit_proxy"):
    if not re.search(rf"^\s*-\s+{parser}\s*$", (roles_dir / "nano_stack/defaults/main.yml").read_text(), re.M):
        errs.append(f"nano_stack does not deploy parser {parser}")

aggregator_text = "\n".join(
    p.read_text(errors="ignore")
    for p in (roles_dir / "nano_vector_aggregator").rglob("*")
    if p.is_file()
)
if "lookup('ansible.builtin.env', 'HOME')" in aggregator_text or "delegate_to: localhost" in aggregator_text:
    errs.append("nano_vector_aggregator reads secrets from the Ludus controller instead of the SIEM")
if "delegate_to: \"{{ nanosiem_siem_inventory_host }}\"" not in aggregator_text:
    errs.append("nano_vector_aggregator does not read the generated admin password from the SIEM host")

expected_image = (
    "timberio/vector:0.61.0-alpine@sha256:"
    "3bb7ed5152910ed51729e256937b1d8a4bf67ff624e9d565e8e5877bffd015c7"
)
for p in roles_dir.rglob("*"):
    if not p.is_file():
        continue
    text = p.read_text(errors="ignore")
    rel = p.relative_to(root)
    for match in re.finditer(r"(?:ghcr\.io/nano-rs/vector|timberio/vector):[^\s\"']+", text):
        if match.group(0) != expected_image:
            errs.append(f"{rel}: Vector edge image is not the pinned full 0.61.0 build: {match.group(0)}")
    if re.search(r"vector/nightly|vector-nightly|0\.59\.0", text):
        errs.append(f"{rel}: uses a pre-v2 Vector release")

agent_defaults = (roles_dir / "nano_vector_agent/defaults/main.yml").read_text()
if 'vector_version: "0.61.0"' not in agent_defaults:
    errs.append("Windows agent is not pinned to Vector 0.61.0")
if not re.search(r'vector_archive_sha256:\s*"[0-9a-f]{64}"', agent_defaults):
    errs.append("Windows agent archive has no sha256 pin")

if re.search(r"^\s+nano_ingest_token:\s*\S", range_config, re.M):
    errs.append("range-config commits a shared aggregator token")
secret_keys = r"(nanosiem_admin_password|nano_api_password|nano_api_key|nano_ingest_token)"
for p in [root / "blueprints/nanosiem/range-config.yml", *roles_dir.glob("*/defaults/main.yml")]:
    for m in re.finditer(rf"^\s*{secret_keys}:\s*(\S.*)$", p.read_text(), re.M):
        if m.group(2).strip() not in ('""', "''"):
            errs.append(f"{p.relative_to(root)}: {m.group(1)} has a committed value")

aggregator_template = (roles_dir / "nano_vector_aggregator/templates/vector-aggregator.toml.j2").read_text()
aggregator_compose = (roles_dir / "nano_vector_aggregator/templates/docker-compose.yml.j2").read_text()
if '[secret.nano_ingest]' not in aggregator_template or 'SECRET[nano_ingest.' not in aggregator_template:
    errs.append("aggregator does not use Vector's directory secret backend")
if './secrets:/etc/vector/secrets:ro' not in aggregator_compose:
    errs.append("aggregator secret directory is not mounted read-only")

conduit_compose = (roles_dir / "nano_conduit_proxy/templates/docker-compose.yml.j2").read_text()
if '"wget"' in conduit_compose or "/proc/net/tcp" not in conduit_compose:
    errs.append("Conduit healthchecks require a tool absent from the minimal images")
for listener_hex in ("2383", "20FB"):
    if f"*:{listener_hex})" not in conduit_compose:
        errs.append(f"Conduit healthcheck is missing listener 0x{listener_hex}")

for e in errs:
    print("FAIL:", e)
print("policy:", "ok" if not errs else f"{len(errs)} problem(s)")
sys.exit(1 if errs else 0)
PY

step "Vector edge image tools"
docker run --rm --entrypoint sh "$VECTOR_IMAGE" -ec \
    'command -v wget >/dev/null; command -v awk >/dev/null' \
    || bad "Vector edge image lacks healthcheck tools"

step "render + vector validate (${VECTOR_IMAGE%@*})"
for sc in "$ROOT"/tests/scenarios/*.yml; do
    name=$(basename "$sc" .yml)
    dir="$OUT/$name"
    if ! ansible-playbook -i "$ROOT/tests/inventory.ini" "$ROOT/tests/render.yml"             -e "@$sc" -e "out_dir=$dir" > "$OUT/$name.render.log" 2>&1 < /dev/null; then
        bad "$name: render failed"
        grep -E 'FAILED|msg' "$OUT/$name.render.log" | head -5 || true
        continue
    fi

    for f in "$dir"/*.toml; do
        if grep -n '\${' "$f"; then
            bad "$name: $(basename "$f") relies on disabled environment interpolation"
        fi
        if awk '/^\[sinks\./{s=1} /^\[sources\./{s=0} s && /^address = "[^h0]/' "$f" | grep -q .; then
            bad "$name: $(basename "$f") has a scheme-less Vector sink address"
        fi
    done

    for f in "$dir"/*.toml "$dir"/*-compose.yml; do
        [[ -e "$f" ]] || continue
        if grep -q 'TESTTOKEN-' "$f"; then
            bad "$name: a token leaked into $(basename "$f")"
        fi
    done

    for cfg in "$dir"/*.toml; do
        base=$(basename "$cfg")
        envargs=()
        if [[ "$base" == aggregator.toml ]]; then
            envargs=(-v "$dir/secrets:/etc/vector/secrets:ro")
        fi
        if [[ "$base" == agent.toml ]]; then
            python3 - "$cfg" <<'PY'
import re
import sys
p = sys.argv[1]
s = open(p).read()
s, n = re.subn(
    r'(\[sources\.windows_events\]\n)type = "windows_event_log"\n(?:[a-z_]+ = .*\n)*',
    r'\1type = "stdin"\n',
    s,
)
assert n == 1, "agent config: windows_events source block not found"
s = s.replace('data_dir = "C:/ProgramData/Vector/data"', 'data_dir = "/tmp"')
open(p, "w").write(s)
PY
        fi
        if docker run --rm "${envargs[@]}" -v "$dir:/cfg:ro" "$VECTOR_IMAGE"                 validate --no-environment "/cfg/$base" > "$OUT/$name.$base.validate.log" 2>&1; then
            echo "ok   $name/$base"
        else
            bad "$name/$base: vector validate"
            sed -n '1,25p' "$OUT/$name.$base.validate.log"
        fi
    done
done

step "HEC wire payloads and acknowledgements"
python3 "$ROOT/tests/hec_wire.py" || bad "HEC wire proof"

step "source-bound token provisioning"
bash "$ROOT/tests/provision/run.sh" < /dev/null || bad "token provisioning"

if [[ -n "${KEEP_RENDERED:-}" ]]; then
    rm -rf "$KEEP_RENDERED"
    cp -r "$OUT" "$KEEP_RENDERED"
    echo "rendered configs kept in $KEEP_RENDERED"
fi

echo
if (( fails > 0 )); then
    echo "check: $fails failure(s)"
    exit 1
fi
echo "check: all passed"
