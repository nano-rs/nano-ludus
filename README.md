# nano SIEM — Ludus Lab

Spin up a complete [nano](https://nano.rs) SIEM lab on [Ludus](https://ludus.cloud): an
Active Directory domain, Windows endpoints with **Sysmon + Event Log** collection, a
**Vector** aggregation pipeline, an optional **Conduit** MITM proxy, and the full nano
open‑core stack (ClickHouse + PostgreSQL + API/search/jobs + web), all wired end‑to‑end.

Everything runs from the **public open‑core images** on `ghcr.io/nano-rs` — no registry
auth, no building from source.

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

All VMs sit on VLAN 10: `10.<second-octet>.10.0/24`.

---

## 1. Get Ludus first

This lab is just Ansible roles + a Ludus blueprint — you need a running **Ludus** server
to deploy it. If you don't have one yet:

- **Ludus docs:** <https://docs.ludus.cloud>
- **Install guide:** <https://docs.ludus.cloud/docs/intro> → *Quick Start / Install*
- You'll need a Proxmox host (bare metal or nested) per Ludus's requirements, then the
  `ludus` CLI configured against your server (`ludus --help` should work).

Confirm your CLI is connected before continuing:

```bash
ludus range list      # shows your range + its range ID (the host-name prefix)
```

> **Your range ID is the prefix on every VM/host name.** In the examples below it's
> written as `<RANGE>` — substitute your own (e.g. if `ludus range list` shows
> `JS-nanosiem`, your `<RANGE>` is `JS`). Don't copy a literal prefix from these docs.

---

## 2. Build the templates

The blueprint uses three Ludus templates. Build them if `ludus templates list` shows
them as `NOT BUILT`:

```bash
ludus templates list
ludus templates build -n debian-12-x64-server-template
ludus templates build -n win2022-server-x64-template
ludus templates build -n win11-22h2-x64-enterprise-template
ludus templates status     # watch progress
```

> ⚠️ **Windows templates are the long pole** (~1–2 hr each) and occasionally fail on the
> Windows-update/sysprep step. If one errors, re‑run `ludus templates build -n <name>` —
> a manual retry almost always succeeds. Don't deploy until all three show **built**.

---

## 3. Add the roles

```bash
# Community role for Docker
ludus ansible role add geerlingguy.docker

# nano lab roles (clone this repo first)
git clone https://github.com/nano-rs/nano-ludus && cd nano-ludus
ludus ansible role add -d roles/nano_stack
ludus ansible role add -d roles/nano_sysmon
ludus ansible role add -d roles/nano_vector_aggregator
ludus ansible role add -d roles/nano_vector_agent
ludus ansible role add -d roles/nano_conduit_proxy

ludus ansible role list    # confirm all six are present
```

> 🔑 **The #1 gotcha:** `ludus range deploy` runs the copy of each role **cached on the
> Ludus server**, *not* the files on your disk. After editing any role you **must**
> re‑push it: `ludus ansible role add -d roles/<role> --force`. Forgetting this is the
> single most common "but I fixed that already" trap.

---

## 4. Deploy

```bash
ludus range config set -f blueprint.yml
ludus range deploy
ludus range logs -f
```

First boot is long — it provisions 5 VMs, stands up the `lab.local` AD domain, pulls
images, and runs first‑boot ClickHouse migrations. A clean run ends with every host at
`failed=0`.

---

## 5. Access (over the Ludus WireGuard VPN)

| Service | URL |
|---|---|
| **nano UI / API** | `http://10.<octet>.10.10` (nginx :80) |
| Grafana | `http://10.<octet>.10.10:3001` (`admin` / `nanosiem`) |
| Prometheus | `http://10.<octet>.10.10:9090` |
| Vector API | `http://10.<octet>.10.10:8686` |

The whole app (web, API, search, `/ingest/`) is served through nginx on **port 80** — no
service-specific ports. On first visit you're redirected to **`/setup`** to create the
admin account (it's open until claimed — do it promptly).

`<octet>` is your range's second octet (`ludus range list`).

---

## Log flow

1. **Sysmon** (installed by `nano_sysmon`) and the classic **Windows Event Logs** are read
   by the **Vector agent** on each Windows box via the native `windows_event_log` source.
2. The agent tags Sysmon as `source_type=windows_sysmon` and everything else as
   `windows_event`, and ships over the Vector protocol to the **aggregator** (`.10.11:9000`).
3. The **aggregator** buffers to disk and forwards to the **SIEM** (`.10.10:6000`).
4. The SIEM's **Vector** runs the nano pipeline (auth → parse → route → ClickHouse).

Events are searchable immediately as raw `message` + `source_type`. To extract structured
fields (`process_name`, `src_host`, …), **deploy the `windows_event` / `windows_sysmon`
parsers** from the in‑app Parser Repository — open‑core ships with none deployed.

---

## Customization

**Event-log channels** — override `vector_eventlog_channels` per host in `blueprint.yml`:

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

**Resource sizing** — adjust `ram_gb` / `cpus` in `blueprint.yml`. Minimums:
SIEM 12 GB / 4 CPU (16/8 recommended) · aggregator 2 GB / 2 CPU · DC 4 GB / 2 CPU ·
workstation 4 GB / 2 CPU.

**Iterate on a single box** (after `--force` re‑adding the role):

```bash
ludus range deploy -t user-defined-roles --limit <RANGE>-nanosiem   # just the SIEM
ludus range deploy -t user-defined-roles --limit <RANGE>-dc01       # just DC01's roles
```

---

## Troubleshooting

These are the real failure modes we hit building this lab. Most are handled automatically
by the roles; this is what they are and what to do if one bites.

### Windows `TASK [Reboot]` → `winrm … the specified credentials were rejected`
A **Ludus base‑config** task (not a nano role) sometimes fails its WinRM auth on a freshly
provisioned Windows box — most often the **Win11 workstation** — while the Server‑2022
boxes reboot fine. It's a Ludus platform reboot/credential race, one layer below this lab.

- **Retry it:** `ludus range deploy --limit <RANGE>-ws01` — a clean retry usually gets past
  the reboot and continues into the roles.
- The roles themselves are fine: `ludus range deploy -t user-defined-roles --limit <RANGE>-ws01`
  runs **only** the role stage (skipping the base reboot) and installs the agent cleanly.

### `Gathering Facts` fails with `Add-CSharpType … could not find file …\Temp\…dll`
Some stock Windows Server 2022 templates silently strip freshly‑compiled executables from
the per‑user temp, which breaks Ansible's C# module compilation. **The `nano_sysmon` role
works around this automatically** (it redirects `localuser`'s TEMP to `C:\Windows\Temp`
via a `raw` task before anything else). If a box still fails on its *very first*
`Gathering Facts`, set it by hand over RDP and re‑deploy:

```powershell
$sid = (New-Object System.Security.Principal.NTAccount("localuser")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$loaded = Test-Path "Registry::HKEY_USERS\$sid"
if (-not $loaded) { reg load "HKU\$sid" "C:\Users\localuser\NTUSER.DAT" | Out-Null }
New-ItemProperty "Registry::HKEY_USERS\$sid\Environment" -Name TEMP -Value "C:\Windows\Temp" -PropertyType ExpandString -Force
New-ItemProperty "Registry::HKEY_USERS\$sid\Environment" -Name TMP  -Value "C:\Windows\Temp" -PropertyType ExpandString -Force
if (-not $loaded) { [gc]::Collect(); reg unload "HKU\$sid" | Out-Null }
```

### `docker compose pull` times out resolving a registry
The Ludus lab DNS forwarder resolves fine at idle but can choke under a fully‑parallel
image pull. The `nano_stack` / aggregator / conduit roles already **serialize the pull**
(`COMPOSE_PARALLEL_LIMIT=1`) and **retry** it, so this is mostly handled — if it still
fails after the retries, just re‑run `ludus range deploy` (it resumes).

### Search throws `crypto.randomUUID is not a function` in the browser
`crypto.randomUUID` only exists in a **secure context**. Over plain `http://<ip>` it's
undefined. Fixed in recent `nano-web` images — make sure you're on `:latest`. For real use,
front the SIEM with **HTTPS** anyway (other browser security gates apply over plain HTTP).

### The deploy "keeps failing on the same box" after you fixed it
You almost certainly edited a role but didn't re‑push it. `ludus range deploy` uses the
**server‑cached** role. Run `ludus ansible role add -d roles/<role> --force`, then deploy.

---

## What's in here

| Role | Purpose |
|---|---|
| `nano_stack` | Full nano SIEM stack on the SIEM box (Docker Compose, GHCR open‑core images) |
| `nano_sysmon` | Install Sysmon (SwiftOnSecurity config) on Windows + the temp‑redirect workaround |
| `nano_vector_aggregator` | Vector aggregator on the proxy box (agent intake → SIEM) |
| `nano_vector_agent` | Vector agent on Windows (Event Log + Sysmon collection) |
| `nano_conduit_proxy` | Conduit MITM proxy + CA trust for HTTP(S) traffic capture |

---

## License

[Apache-2.0](LICENSE).

> Internal Ansible variables keep a `nanosiem_*` prefix (they map to the `nanosiem`
> database/users the images expect) — that's intentional and not a typo.
