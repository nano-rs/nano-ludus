# nano SIEM — Ludus Lab

A complete [nano](https://nano.rs) SIEM lab on [Ludus](https://ludus.cloud) in three commands:
an Active Directory domain, Windows endpoints shipping **Sysmon + Event Logs** through
**Vector 0.59** into an **open‑core nano lean install** (one trusted‑local lake cell, OCSF 1.9 on RustFS) on the range — or straight
into a **hosted lean tenant** (`<tenant>.ingest.nano.rs`) — with an optional **Conduit** MITM proxy.

```
┌──────────┐ ┌──────────┐ ┌──────────┐
│   DC01   │ │  SRV01   │ │   WS01   │     Windows: Sysmon + Event Logs
│ Win2022  │ │ Win2022  │ │  Win11   │     via the Vector 0.59 agent
└────┬─────┘ └────┬─────┘ └────┬─────┘
     │   Vector protocol :9000  │
     └────────────┬─────────────┘
                  ▼
          ┌────────────────┐
          │ PROXY / .10.11 │  Vector aggregator (the range's shipper) + Conduit
          └───────┬────────┘
                  │  HEC :8088, one sink and one bound token per source
                  ▼                         (or https://<tenant>.ingest.nano.rs)
          ┌───────────────────────────────┐
          │  SIEM / .10.10 (Debian 12)     │  open-core install.sh, lean profile:
          │  nginx :80 → web · API · search │  one lake cell, OCSF 1.9 on RustFS,
          │  ingest :8080 :8088 :4318 :6000 │  Vector 0.59, Postgres, Dragonfly
          └───────────────────────────────┘
```

> **NAN-3397 / NAN-3491 (Oct 2026):** the SIEM box used to run the retired gen1 stack
> (`nano_stack`, ClickHouse + UDM). It now runs the open‑core **lean** install (`nano_lean`,
> `install.sh --non-interactive`, compose profile `lean`); neither the retired `legacy`
> (ClickHouse) nor the gen1 `lake` profile is used. The aggregator ships over authenticated HEC
> instead of unauthenticated Vector‑native, and every Vector is pinned to 0.59. The old role is
> gone from this repo (see git history / `main` before this change).

## Quick start

You need a running **Ludus** server with the CLI connected (`ludus range list` works).
New to Ludus? Start with the [install guide](https://docs.ludus.cloud/docs/intro).

```bash
# 1. Build the templates this lab uses (skip any already BUILT; Windows ones take ~1–2 hr each)
ludus templates build -n debian-12-x64-server-template
ludus templates build -n win2022-server-x64-template
ludus templates build -n win11-22h2-x64-enterprise-template

# 2. Add this source, apply the blueprint, deploy
ludus source add https://github.com/nano-rs/nano-ludus
ludus blueprint apply nano-rs-nano-ludus/nanosiem
ludus range deploy
```

Then open **`http://10.<octet>.10.10`** over the Ludus WireGuard VPN (`<octet>` = your range's
second octet, from `ludus range list`) and log in as `admin@lab.local`. The password is random per
range (never committed): it is in `~/.nano-ludus/<range_id>/lab-admin-password` (0600) on the Ludus
controller and in `/root/.nano-lab-admin` (0600) on the SIEM VM.

> **Before you rely on step 2 — open-core availability.** `nano_lean` runs the product's own
> `install.sh` from `nano_lean_repo_url` at `nano_lean_ref` (defaults: the public mirror
> `nano-rs/nano`, `main`). The default needs nanosiem #5924 (lean installer + compose) and #5944
> (legacy profile removed) merged and synced to that mirror, and
> `ghcr.io/nano-rs/nano-lake-cell` published. As of 2026‑10‑10 the mirror is still pre‑lean
> (NAN‑3309). The role refuses a source without the lean profile rather than deploying a retired
> stack. Until then, point `nano_lean_repo_url` / `nano_lean_ref` at a source that carries #5924
> (e.g. `nano_lean_ref: feat/NAN-3492-open-lean-compose`), or skip the SIEM VM and ship the range
> to a hosted lean tenant (below).
>
> An existing pre‑lean SIEM VM (gen1 `nano_stack` or a gen1 lake install) is not cut over in
> place: `install.sh` refuses a pre‑lean `.env`. Rebuild the SIEM VM (or run `install.sh` by hand
> with `NANO_FRESH_LEAN_CUTOVER=1`, see the product's `docs/deployment/open-lean-install.md`).

> Ludus also builds a router from `debian-11-x64-server-template` on every deploy — a standard
> Ludus install already has it. If a deploy fails instantly saying that template doesn't exist,
> run `ludus templates build -n debian-11-x64-server-template` first.

## What you get

A 5‑VM range on VLAN 10 (`10.<octet>.10.0/24`), all joined to `lab.local`:
**SIEM** `.10` · **proxy/aggregator** `.11` · **DC01** `.20` · **SRV01** `.21` · **WS01** `.30`.
The whole nano app — web, API, search, `/ingest/` — is served through nginx on port 80.

**Log flow:** Sysmon + Windows Event Logs → Vector agent on each Windows box → aggregator (`.11`)
→ HEC → nano's Vector pipeline → OCSF parser → lake cell. The agent tags Sysmon events
`source_type=windows_sysmon` and everything else `source_type=windows_event`, and flattens each
event to JSON in `message`. The aggregator forwards each source on its own HEC sink, **with its
own ingest token**.

## Ingest tokens: one per source (NAN-3841)

nano binds every ingest token to exactly one log source, and the token alone decides where an
event lands (nano NAN-3806). A `sourcetype` / `X-Source-Type` no longer routes anything; nano
keeps a differing one only as `claimed_source_type`. An unbound token gets HTTP 401, and there is
no token that covers several log types. So the aggregator ships `windows_event`,
`windows_sysmon` and `conduit_proxy` with three tokens, each bound to its own source.

On the in‑range open‑core SIEM, the aggregator role issues them itself. It waits for the SIEM's
API and for each source's log source (the SIEM role deploys the parsers), logs in as the lab
admin with the range's generated password (the controller copy the SIEM role wrote; override with
`nano_api_password`, or give an admin API key in `nano_api_key`), and for each forwarded source:

- reuses the token it issued on an earlier deploy, while that token is still active and bound to
  the source (it keeps the credential ids in `/opt/vector-aggregator/ingest-credentials.json` and
  the values only in the 0600 files under `secrets/`);
- otherwise issues a new one, `POST /api/ingest-tokens {name, source_id}`, and revokes the token
  it replaces;
- uses a token you set in `nano_ingest_source_tokens` as given. If it is a nano‑issued `nit_`
  token that is still unbound, it binds it (`POST /api/ingest-tokens/{credential_id}/bind`). If
  it is bound to a different source, the deploy fails: bindings never change, so revoke it and
  issue a new one.

After the aggregator starts it posts one small marked event per source with that source's token
(`nano_ingest_verify_tokens`, on by default). A 401 fails the deploy with what to do: bind the
token in **Ingestion → Credentials → Bind**, or `POST /api/ingest-tokens/{credential_id}/bind`.

**A nano that predates per‑source tokens** (no binding API: `GET /api/ingest-tokens` has no
`sources`, or 404) still routes on the install token plus `sourcetype`. There the role falls back
to `nano_ingest_token` (the install's `VECTOR_AUTH_TOKEN`) as before, and says so; without one it
fails with "set nano_ingest_token … or upgrade nano".

> An existing range keeps its admin password: on the next deploy the SIEM role copies
> `/root/.nano-lab-admin` from the SIEM to the controller, so the aggregator logs in with it. To
> override, set `nano_lean_admin_password` and `nano_api_password` (from a vault, never a
> committed value), or give the aggregator an admin API key in `nano_api_key`.

**Parsers:** open‑core ships with only the OTLP parser live. `nano_lean` imports the OCSF parsers
named in `nano_lean_parsers` (default `windows_event`, `windows_sysmon`, `conduit_proxy`) from the
public [nano-rs/parsers](https://github.com/nano-rs/parsers) repository and deploys them, so range
events are searchable as OCSF (`class_uid`, `process.cmd_line`, `user.name`, …) from the first
event. Coverage today:

| Range source | source_type | OCSF parser | Coverage |
|---|---|---|---|
| Sysmon (Operational) | `windows_sysmon` | `windows_sysmon_ocsf` | EIDs 1, 3, 5, 7, 10, 11, 12, 13, 22, 23 |
| Security log | `windows_event` | `windows_event_ocsf` | EIDs 4624, 4625, 4634, 4672, 4688 |
| PowerShell, Defender, System, Application, DNS Server, Directory Service | `windows_event` | `windows_event_ocsf` | **not mapped**: they fall into the parser's Authentication branch (class 3002, activity Other) |
| Conduit proxy | `conduit_proxy` | `conduit_proxy_ocsf` | HTTP Activity 4002 |
| Linux auth / syslog | — | `syslog`, `linux_journald`, `linux_auditd` (on the `ocsf-1.9` parser branch) | **not shipped**: no range host runs a Linux shipper yet, so these lanes see nothing |

## Ship to a lean tenant

The aggregator's forward hop is just an endpoint plus token(s). The role issues no tokens on a
hosted tenant; set, on the proxy VM:

```yaml
role_vars:
  nano_ingest_mode: hec
  nano_ingest_url: "https://<tenant>.ingest.nano.rs"
  # One credential per source (a source credential is bound to one source_type):
  nano_ingest_source_tokens:
    windows_event: "<credential>"
    windows_sysmon: "<credential>"
    conduit_proxy: "<credential>"
  # Or a collector credential for the sources without their own:
  # nano_ingest_token: "<collector credential>"
```

Issue credentials in the tenant's **Settings → Add data** (protocol **HEC**). Each token is written
as a 0600 file under `/opt/vector-aggregator/secrets/` (one per source, plus `default` for a
shared fallback token). Vector reads them through its `directory` secret backend (`SECRET[nano_ingest.<key>]`).
Tokens never go into `vector.toml`, and never into `${VAR}` env interpolation, which Vector ≥ 0.57
no longer expands by default. HEC indexer acknowledgements are on automatically for `https://` URLs
(lean) and off for the in‑range `http://` open‑core HEC, which runs with acks disabled.
`nano_ingest_indexer_acknowledgements: true|false` overrides that. The SIEM VM can then be
dropped from the range config. `nano_ingest_mode: vector` (Vector‑native :6000) still exists for
an in‑range open‑core SIEM, but :6000 checks no token — lab networks only — and lean tenants have
no such port.

> Co‑locating the aggregator on the SIEM VM? RustFS holds 127.0.0.1:9000/9001 there, so set
> `aggregator_vector_port` (and the agents' `vector_aggregator_port`) to something else, e.g. 9100.

**Packaging:** this repo is a Ludus Source — the `nanosiem` blueprint lives in `blueprints/nanosiem/`,
the five `nano_*` roles are vendored under `ansible/roles/`, and `geerlingguy.docker` is declared
in `requirements.yml`.

Each role declares `author: NanoSIEM` in its `meta/main.yml`, so ansible‑galaxy installs it as
`NanoSIEM.<role>` — that is the name the range config must use. Referencing a role bare fails to
resolve at deploy time (NAN‑2358). Drop or change an `author` and you must update
`range-config.yml` to match.

| Role (as referenced in `range-config.yml`) | Purpose |
|---|---|
| `NanoSIEM.nano_lean` | Open‑core nano lean install on the SIEM box (`install.sh`, lean profile) + OCSF parser deploy |
| `NanoSIEM.nano_sysmon` | Sysmon (SwiftOnSecurity‑based config) on Windows |
| `NanoSIEM.nano_vector_aggregator` | Vector aggregator on the proxy box: agent intake → nano (HEC, per‑source tokens) |
| `NanoSIEM.nano_vector_agent` | Vector 0.59 agent on Windows (Event Log + Sysmon collection) |
| `NanoSIEM.nano_conduit_proxy` | Conduit MITM proxy + CA trust for HTTP(S) traffic capture |

**Checks:** `bash tests/check.sh` runs ansible‑lint, `ansible-playbook --syntax-check`, a policy
check (no gen1 role deployed, no ClickHouse / gen1 lake profile referenced, every Vector pinned to 0.59 by digest, no token in a world‑readable
config, no `X-Source-Type`, no shared aggregator token in the blueprint), and renders every scenario in `tests/scenarios/` with the roles' own templates and runs
`vector validate` (0.59) on the result. Then `tests/provision/run.sh` runs the aggregator's token
tasks against a mock of nano's ingest‑token API (issue, reuse, rotate, bind, wrong source, missing
source, 401, a pre‑NAN‑3806 nano, a rejected login) and checks no token value reaches the output.

<details>
<summary><b>Customize</b> — event channels, VM sizing, single‑box iteration</summary>

All edits go in `blueprints/nanosiem/range-config.yml`.

**Event‑log channels** — override `vector_eventlog_channels` per host:

```yaml
role_vars:
  vector_eventlog_channels:
    - "Application"
    - "System"
    - "Security"
    - "Microsoft-Windows-Sysmon/Operational"
    - "Microsoft-Windows-PowerShell/Operational"
    - "Microsoft-Windows-Windows Defender/Operational"
```

**Resource sizing** — adjust `ram_gb` / `cpus`. Minimums: SIEM 12 GiB visible to Docker / 4 CPU (16/8 recommended; `install.sh` refuses less than 12 GiB) ·
aggregator 2 GB / 2 CPU · DC 4 GB / 2 CPU · workstation 4 GB / 2 CPU.

**Buffering and backpressure** — every Vector hop (agent → aggregator → SIEM) writes to a disk
buffer, so a SIEM restart does not lose events. When a buffer *fills*, the default is to shed the
newest events rather than block:

| Variable | Default | Role |
| --- | --- | --- |
| `vector_buffer_max_bytes` / `vector_buffer_when_full` | 512 MB / `drop_newest` | agent |
| `aggregator_buffer_max_bytes` / `aggregator_buffer_when_full` | 1 GB / `drop_newest` | aggregator |
| `conduit_buffer_max_bytes` / `conduit_buffer_when_full` | 512 MB / `drop_newest` | conduit proxy |

Disk buffers have a hard floor of 256 MiB — `max_size` must be at least `268435488` bytes, and
Vector refuses to start below it, so a too-small override fails the deploy rather than the lab.

Setting any of these to `block` trades collection for durability, and the trade is worse than it
sounds: one hop that stops draining applies backpressure to every hop above it — including the
Windows Event Log readers — so the whole lab stops collecting at once. Restarting does not clear it,
because a restart preserves the backlog rather than draining it: collection stays frozen for as long
as the downstream hop cannot accept events. (The buffer is not permanently deadlocked — once
downstream recovers it drains normally, and you never need to delete a buffer directory.)

Prefer `drop_newest` and watch the aggregator's buffer instead:

```bash
# the aggregator's own sink buffer (metrics carry the nanosiem_aggregator_ namespace)
curl -s http://<proxy-ip>:9598/metrics | grep -E 'buffer_(byte_size|max_byte_size|discarded_events)'
docker inspect vector-aggregator --format '{{json .State.Health}}'   # red at >=90% full
```

That endpoint covers the **aggregator hop only**. The Windows agent sends its internal metrics to a
console sink (read them in the Vector service log on the endpoint), and the Conduit sidecar exposes
no metrics endpoint at all — so drops at those two hops are not visible from the proxy box.

**Iterate on one box** (after re‑syncing the source — see *Editing the lab* below):

```bash
ludus range deploy -t user-defined-roles --limit <RANGE>-nanosiem   # just the SIEM
ludus range deploy -t user-defined-roles --limit <RANGE>-dc01       # just DC01's roles
```
</details>

<details>
<summary><b>Editing the lab</b> — re‑sync the source after any change</summary>

`ludus range deploy` runs the copy of each role the **Ludus server** holds from the source
snapshot, *not* the files on your disk. After editing anything under `ansible/roles/` or the
range config you **must** re‑sync first, then re‑apply + deploy:

- **git source:** push your commit, then `ludus source sync nano-rs-nano-ludus`
- **local dev source:** `ludus source update nano-rs-nano-ludus -d .`

Then `ludus blueprint apply nano-rs-nano-ludus/nanosiem` + `ludus range deploy`. Forgetting the
re‑sync is the single most common "but I fixed that already" trap.

For local development you can add the source straight from a clone instead of GitHub:
`ludus source add -d . --id nano-rs-nano-ludus`.
</details>

<details>
<summary><b>Troubleshooting</b> — the real failure modes we hit building this lab</summary>

Most are handled automatically by the roles; this is what they are and what to do if one bites.
`<RANGE>` below = your range ID, the prefix on every VM name (`ludus range list`).

### Windows `TASK [Reboot]` → `winrm … the specified credentials were rejected`
A **Ludus base‑config** task (not a nano role) sometimes fails its WinRM auth on a freshly
provisioned Windows box — most often the **Win11 workstation** — while the Server‑2022 boxes
reboot fine. It's a Ludus platform reboot/credential race, one layer below this lab.

- **Retry it:** `ludus range deploy --limit <RANGE>-ws01` — a clean retry usually gets past the
  reboot and continues into the roles.
- The roles themselves are fine: `ludus range deploy -t user-defined-roles --limit <RANGE>-ws01`
  runs **only** the role stage (skipping the base reboot) and installs the agent cleanly.

### `Gathering Facts` fails with `Add-CSharpType … could not find file …\Temp\…dll`
Some stock Windows Server 2022 templates silently strip freshly‑compiled executables from the
per‑user temp, which breaks Ansible's C# module compilation. **The `nano_sysmon` role works
around this automatically** (it redirects `localuser`'s TEMP to `C:\Windows\Temp` via a `raw`
task before anything else). If a box still fails on its *very first* `Gathering Facts`, set it by
hand over RDP and re‑deploy:

```powershell
$sid = (New-Object System.Security.Principal.NTAccount("localuser")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$loaded = Test-Path "Registry::HKEY_USERS\$sid"
if (-not $loaded) { reg load "HKU\$sid" "C:\Users\localuser\NTUSER.DAT" | Out-Null }
New-ItemProperty "Registry::HKEY_USERS\$sid\Environment" -Name TEMP -Value "C:\Windows\Temp" -PropertyType ExpandString -Force
New-ItemProperty "Registry::HKEY_USERS\$sid\Environment" -Name TMP  -Value "C:\Windows\Temp" -PropertyType ExpandString -Force
if (-not $loaded) { [gc]::Collect(); reg unload "HKU\$sid" | Out-Null }
```

### `docker compose pull` times out resolving a registry
The Ludus lab DNS forwarder resolves fine at idle but can choke under a fully‑parallel image
pull. The `nano_lean` / aggregator / conduit roles already **serialize the pull**
(`COMPOSE_PARALLEL_LIMIT=1`) and **retry** it, so this is mostly handled — if it still fails after
the retries, just re‑run `ludus range deploy` (it resumes).

### Search throws `crypto.randomUUID is not a function` in the browser
`crypto.randomUUID` only exists in a **secure context**. Over plain `http://<ip>` it's undefined.
Fixed in recent `nano-web` images — make sure you're on `:latest`. For real use, front the SIEM
with **HTTPS** anyway (other browser security gates apply over plain HTTP).

### The deploy "keeps failing on the same box" after you fixed it
You almost certainly edited a role but didn't re‑sync the source (see *Editing the lab* above).
`ludus range deploy` uses the server‑cached role from the source snapshot — re‑sync, re‑apply,
then deploy.
</details>

## License

[Apache‑2.0](LICENSE).

> Internal Ansible variables keep a `nanosiem_*` prefix (they map to the `nanosiem` database/users
> the images expect) — that's intentional, not a typo.
