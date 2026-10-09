# nano SIEM — Ludus Lab

A complete [nano](https://nano.rs) SIEM lab on [Ludus](https://ludus.cloud) in three commands:
an Active Directory domain, Windows endpoints shipping **Sysmon + Event Logs** through
**Vector 0.59** into an **open‑core nano lake** (OCSF 1.9 on RustFS) on the range — or straight
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
                  │  Splunk HEC :8088, token-authenticated, one sink per source
                  ▼                         (or https://<tenant>.ingest.nano.rs)
          ┌───────────────────────────────┐
          │  SIEM / .10.10 (Debian 12)     │  open-core install.sh, lake profile:
          │  nginx :80 → web · API · search │  OCSF 1.9 object lake on RustFS,
          │  ingest :8080 :8088 :4318 :6000 │  Vector 0.59, Postgres
          └───────────────────────────────┘
```

> **NAN-3397 (Oct 2026):** the SIEM box used to run the retired gen1 stack (ClickHouse + UDM,
> `nano_stack`). It now runs the open‑core **lake** install (`nano_lake`), the aggregator ships
> over authenticated HEC instead of unauthenticated Vector‑native, and every Vector is pinned to
> 0.59. `nano_stack` is quarantined under `legacy/` and is no longer packaged.

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
second octet, from `ludus range list`) and log in as `admin@lab.local`; the generated password is
in `/root/.nano-lab-admin` on the SIEM VM.

> **Before you rely on step 2 — open-core availability.** `nano_lake` runs the product's own
> `install.sh` from `nano_lake_repo_url` (default: the public mirror `nano-rs/nano`). As of
> 2026‑10‑09 that mirror is still the legacy v0.1.703 ClickHouse snapshot (NAN‑3309) and the
> `nano-lake-*` images are not public (NAN‑3308). The role refuses a source without the lake
> profile rather than deploying gen1. Until both land, point `nano_lake_repo_url` at a
> lake‑capable source, or skip the SIEM VM and ship the range to a lean tenant (below).
>
> **Known blocker — open‑core + Windows data (NAN‑3401).** Every Windows/Sysmon event leaves
> dotted residual keys under `unmapped` (`event_data.subject_user_sid`, …). The open‑core lake's
> Iceberg bronze publisher cannot admit those columns ("Cannot add column with ambiguous name"),
> and it retries the batch forever. Range events parse into the right OCSF classes, but nothing
> after the first one becomes searchable until NAN‑3401 ships. Lean tenants are not affected
> (NAN‑2998).

> Ludus also builds a router from `debian-11-x64-server-template` on every deploy — a standard
> Ludus install already has it. If a deploy fails instantly saying that template doesn't exist,
> run `ludus templates build -n debian-11-x64-server-template` first.

## What you get

A 5‑VM range on VLAN 10 (`10.<octet>.10.0/24`), all joined to `lab.local`:
**SIEM** `.10` · **proxy/aggregator** `.11` · **DC01** `.20` · **SRV01** `.21` · **WS01** `.30`.
The whole nano app — web, API, search, `/ingest/` — is served through nginx on port 80.

**Log flow:** Sysmon + Windows Event Logs → Vector agent on each Windows box → aggregator (`.11`)
→ Splunk HEC → nano's Vector pipeline → OCSF parser → lake. The agent tags Sysmon events
`source_type=windows_sysmon` and everything else `source_type=windows_event`, and flattens each
event to JSON in `message`. The aggregator forwards each source on its own HEC sink with a literal
`sourcetype`, so a lean tenant's per‑source credentials work unchanged.

**Parsers:** open‑core ships with only the OTLP parser live. `nano_lake` imports the OCSF parsers
named in `nano_lake_parsers` (default `windows_event`, `windows_sysmon`, `conduit_proxy`) from the
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

The aggregator's forward hop is just an endpoint plus token(s). Set, on the proxy VM:

```yaml
role_vars:
  nano_ingest_mode: hec
  nano_ingest_url: "https://<tenant>.ingest.nano.rs"
  # A collector credential covers every source...
  nano_ingest_token: "<collector credential>"
  # ...or give each source its own (a source credential is bound to one source_type):
  nano_ingest_source_tokens:
    windows_event: "<credential>"
    windows_sysmon: "<credential>"
    conduit_proxy: "<credential>"
```

Issue credentials in the tenant's **Settings → Add data** (protocol **HEC**). Each token is written
as a 0600 file under `/opt/vector-aggregator/secrets/` (`default`, plus one per source with its own
credential). Vector reads them through its `directory` secret backend (`SECRET[nano_ingest.<key>]`).
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
| `NanoSIEM.nano_lake` | Open‑core nano lake on the SIEM box (`install.sh`, lake profile) + OCSF parser deploy |
| `NanoSIEM.nano_sysmon` | Sysmon (SwiftOnSecurity‑based config) on Windows |
| `NanoSIEM.nano_vector_aggregator` | Vector aggregator on the proxy box: agent intake → nano (HEC, per‑source tokens) |
| `NanoSIEM.nano_vector_agent` | Vector 0.59 agent on Windows (Event Log + Sysmon collection) |
| `NanoSIEM.nano_conduit_proxy` | Conduit MITM proxy + CA trust for HTTP(S) traffic capture |

**Checks:** `bash tests/check.sh` runs ansible‑lint, `ansible-playbook --syntax-check`, a policy
check (no gen1 role deployed, every Vector pinned to 0.59 by digest, no token in a world‑readable
config), and renders every scenario in `tests/scenarios/` with the roles' own templates and runs
`vector validate` (0.59) on the result.

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

**Resource sizing** — adjust `ram_gb` / `cpus`. Minimums: SIEM 12 GB / 4 CPU (16/8 recommended) ·
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
pull. The `nano_lake` / aggregator / conduit roles already **serialize the pull**
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
