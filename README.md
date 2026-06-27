# nano SIEM — Ludus Lab

A complete [nano](https://nano.rs) SIEM lab on [Ludus](https://ludus.cloud) in three commands:
an Active Directory domain, Windows endpoints shipping **Sysmon + Event Logs** through a
**Vector** pipeline into the full nano open‑core stack (ClickHouse · PostgreSQL · API/search/jobs/web),
with an optional **Conduit** MITM proxy. Runs entirely on public `ghcr.io/nano-rs` images —
no registry auth, no building from source.

```
┌──────────┐ ┌──────────┐ ┌──────────┐
│   DC01   │ │  SRV01   │ │   WS01   │     Windows: Sysmon + Event Logs
│ Win2022  │ │ Win2022  │ │  Win11   │     via the Vector agent
└────┬─────┘ └────┬─────┘ └────┬─────┘
     │   Vector protocol :9000  │
     └────────────┬─────────────┘
                  ▼
          ┌───────────────┐
          │ PROXY / .10.11 │  Vector aggregator + Conduit MITM proxy
          └───────┬────────┘
                  │  Vector protocol :6000
                  ▼
          ┌───────────────────────────┐
          │  SIEM / .10.10 (Debian 12) │  nginx :80 → web · API · search
          │  nano-* + ClickHouse + PG  │  jobs · Vector · Dragonfly
          └───────────────────────────┘
```

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
second octet, from `ludus range list`) and visit **`/setup`** to claim the admin account. Done.

> Ludus also builds a router from `debian-11-x64-server-template` on every deploy — a standard
> Ludus install already has it. If a deploy fails instantly saying that template doesn't exist,
> run `ludus templates build -n debian-11-x64-server-template` first.

## What you get

A 5‑VM range on VLAN 10 (`10.<octet>.10.0/24`), all joined to `lab.local`:
**SIEM** `.10` · **proxy/aggregator** `.11` · **DC01** `.20` · **SRV01** `.21` · **WS01** `.30`.
The whole nano app — web, API, search, `/ingest/` — is served through nginx on port 80.

**Log flow:** Sysmon + Windows Event Logs → Vector agent on each Windows box → aggregator (`.11`)
→ SIEM Vector pipeline → ClickHouse. Events are searchable immediately as raw `message` +
`source_type`; to extract structured fields, deploy the `windows_event` / `windows_sysmon`
parsers from the in‑app Parser Repository (open‑core ships none deployed).

**Packaging:** this repo is a Ludus Source — the `nanosiem` blueprint lives in `blueprints/nanosiem/`,
the five `nano_*` roles are vendored under `ansible/roles/`, and `geerlingguy.docker` is declared
in `requirements.yml`.

| Role | Purpose |
|---|---|
| `nano_stack` | Full nano SIEM stack on the SIEM box (Docker Compose, GHCR open‑core images) |
| `nano_sysmon` | Sysmon (SwiftOnSecurity config) on Windows + the temp‑redirect workaround |
| `nano_vector_aggregator` | Vector aggregator on the proxy box (agent intake → SIEM) |
| `nano_vector_agent` | Vector agent on Windows (Event Log + Sysmon collection) |
| `nano_conduit_proxy` | Conduit MITM proxy + CA trust for HTTP(S) traffic capture |

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
pull. The `nano_stack` / aggregator / conduit roles already **serialize the pull**
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
