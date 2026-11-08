# nano v2 — Ludus Lab

A complete [nano](https://nano.rs) v2 SIEM lab on [Ludus](https://ludus.cloud):
an Active Directory domain, three Windows endpoints, Sysmon and Windows Event
Logs, a Vector aggregator, OCSF parsers, and the nano open-core stack backed by
ClickHouse. An optional Conduit proxy adds HTTP activity telemetry.

```text
DC01 ─┐
SRV01 ├─ Vector 0.61 :9000 ─► proxy / aggregator ─ HEC :8088 ─► nano v2
WS01 ─┘                         + Conduit                         OCSF / ClickHouse
```

The aggregator uses one source-bound ingest token for each route:
`windows_event`, `windows_sysmon`, and `conduit_proxy`. The token determines
the nano log source; the sender's `sourcetype` is informational.

## Quick start

You need a running Ludus server with the CLI connected
(`ludus range list` works).

```bash
# Build the templates if the server does not already have them.
ludus templates build -n debian-11-x64-server-template
ludus templates build -n debian-12-x64-server-template
ludus templates build -n win2022-server-x64-template
ludus templates build -n win11-22h2-x64-enterprise-template

# Add every source artifact, apply the blueprint, and deploy.
ludus source add https://github.com/nano-rs/nano-ludus --all
ludus blueprint apply nano-rs-nano-ludus/nanosiem
ludus range deploy
```

The Debian 11 template is required by the Ludus router even though the blueprint
does not name it.

The SIEM VM must expose AVX2 for ClickHouse 26.6+. The role checks this before
installing anything and reports the Proxmox CPU-model remediation (`host` or
`x86-64-v3`) if the feature is hidden.

Open `http://10.<range-octet>.10.10` over the Ludus WireGuard connection and
log in as `admin@lab.local`. The password is generated once per range and is
never committed. It is stored only on the SIEM VM, mode 0600, in
`/root/.nano-lab-admin-password`; `/root/.nano-lab-admin` records the login URL
and email for operator recovery. The aggregator reads the password through an
Ansible delegated task. Nothing writes beneath the Ludus controller's
read-only home.

## v2 installer contract

`NanoSIEM.nano_stack` checks out the public
[`nano-rs/nano`](https://github.com/nano-rs/nano) source and runs its
`install.sh` with the documented environment:

- `NANO_ADMIN_EMAIL`, `NANO_ADMIN_NAME`, and `NANO_ADMIN_PASSWORD`
- `NANO_BASE_URL`
- `NANO_REPO_URL`, `NANO_BRANCH`, and `NANO_INSTALL_DIR`
- `NANO_SCHEMA_PROFILE=ocsf`

There is no private installer flag, pseudo-TTY, or role-side stack patch. The
installer owns `.env`, image digest verification, resource sizing, database
migration, first-admin creation, and stack startup.

The public mirror intentionally publishes no git tags. The role checks out
`main`, whose `images.lock` records the released product, and pins the image
release separately:

```yaml
nanosiem_ref: "main"
nanosiem_version: "2.0.0"
```

The role refuses a source whose installer does not identify the v2 product line
and OCSF/ClickHouse profile contract. It imports and deploys these OCSF parsers
from `nano-rs/parsers` after the API becomes healthy:

| Range lane | Route key | Parser |
| --- | --- | --- |
| Windows Event Log | `windows_event` | `parsers-ocsf/windows_event/parser.yaml` |
| Sysmon | `windows_sysmon` | `parsers-ocsf/windows_sysmon/parser.yaml` |
| Conduit proxy | `conduit_proxy` | `parsers-ocsf/conduit_proxy/parser.yaml` |

## Source-bound ingest tokens

nano v2 binds each ingest token to exactly one log source. The aggregator role:

1. waits for nano and the three deployed parser routes;
2. logs in with the per-range admin password, or an operator-provided admin API
   key;
3. issues `POST /api/ingest-tokens {"name": ..., "source_id": ...}` once per
   source;
4. stores only credential IDs in
   `/opt/vector-aggregator/ingest-credentials.json`;
5. stores token values in separate mode-0600 files under
   `/opt/vector-aggregator/secrets/`;
6. reads those files through Vector's directory secret backend; and
7. sends one marked HEC event per source to prove each credential is accepted.

A valid token from an earlier deploy is reused. If its local secret file is
lost, the role creates a replacement before revoking the old credential. A
token bound to another source is rejected because bindings never change.

Vector config files never contain token values and do not rely on environment
interpolation. The latter is disabled by default in modern Vector releases.

To supply credentials yourself:

```yaml
nano_ingest_source_tokens:
  windows_event: "<token bound to windows_event>"
  windows_sysmon: "<token bound to windows_sysmon>"
  conduit_proxy: "<token bound to conduit_proxy>"
```

A single shared token is intentionally unsupported.

## Vector versions

The v2 server compose uses nano's feature-minimized Vector fork. That server
image omits the Vector and HEC sinks required by the Ludus edge hops, so the
aggregator and Conduit sidecar use the full upstream Alpine build at the same
0.61 base version, pinned to its multi-architecture digest. Alpine also
provides the small wget/awk tools used by the aggregator healthcheck:

```text
timberio/vector:0.61.0-alpine
sha256:3bb7ed5152910ed51729e256937b1d8a4bf67ff624e9d565e8e5877bffd015c7
```

The Windows collector uses the checksum-pinned official Vector 0.61.0 archive.
It needs only the stable `windows_event_log` source and Vector sink; nano's
server-specific changes remain in the Linux image.

## Topology and roles

The range is five VMs on VLAN 10:

| Address suffix | VM | Purpose |
| --- | --- | --- |
| `.10` | SIEM | nano v2 open core, OCSF, ClickHouse, Postgres, Vector, nginx |
| `.11` | proxy | Vector aggregator plus Conduit |
| `.20` | DC01 | Windows Server domain controller, Sysmon and Event Logs |
| `.21` | SRV01 | Windows member server, Sysmon and Event Logs |
| `.30` | WS01 | Windows 11 workstation, Sysmon and Event Logs |

The vendored roles are:

| Role | Purpose |
| --- | --- |
| `NanoSIEM.nano_stack` | Run the v2 open-core installer and deploy the OCSF parsers |
| `NanoSIEM.nano_sysmon` | Install the observation-only Sysmon configuration |
| `NanoSIEM.nano_vector_agent` | Collect Windows Event Logs and Sysmon with Vector 0.61 |
| `NanoSIEM.nano_vector_aggregator` | Receive Vector events and forward source-bound HEC |
| `NanoSIEM.nano_conduit_proxy` | Capture proxy activity and send it to the aggregator |

## Local checks

```bash
bash tests/check.sh
```

The gate:

- runs `ansible-lint` and an Ansible syntax check over every role;
- enforces the v2/OCSF/ClickHouse policy and exact Vector pins;
- forbids the retired role/profile artifacts and shared aggregator tokens;
- renders every Vector scenario from the actual role templates;
- validates the rendered configs with the v2 Vector image;
- exercises the source-bound token lifecycle against a loopback mock API; and
- sends real rendered HEC payloads to a loopback receiver, checking distinct
  credentials, raw parser payloads, compression, and HEC acknowledgements.

## Customization

Edit `blueprints/nanosiem/range-config.yml`.

Event channels are controlled per Windows host:

```yaml
vector_eventlog_channels:
  - Application
  - System
  - Security
  - Microsoft-Windows-Sysmon/Operational
  - Microsoft-Windows-PowerShell/Operational
  - Microsoft-Windows-Windows Defender/Operational
```

Each Vector hop has a disk buffer. The default `when_full = "drop_newest"`
keeps endpoint collection moving when downstream is unavailable. Setting
`block` propagates backpressure to the Windows Event Log readers.

| Variables | Default | Role |
| --- | --- | --- |
| `vector_buffer_max_bytes` / `vector_buffer_when_full` | 512 MiB / `drop_newest` | Windows agent |
| `aggregator_buffer_max_bytes` / `aggregator_buffer_when_full` | 1 GiB per source / `drop_newest` | aggregator |
| `conduit_buffer_max_bytes` / `conduit_buffer_when_full` | 512 MiB / `drop_newest` | Conduit sidecar |

The aggregator exposes its internal metrics on `:9598`; its container health
check becomes unhealthy when the fullest sink buffer reaches the configured
threshold.

## Editing the source

Ludus deploys the server's cached source snapshot, not files from a local clone.
After changes, resync and reapply:

```bash
# Published git source
ludus source sync nano-rs-nano-ludus
ludus source add nano-rs-nano-ludus --all --force

# Or a local checkout
ludus source update nano-rs-nano-ludus -d .

ludus blueprint apply nano-rs-nano-ludus/nanosiem
ludus range deploy
```

## Troubleshooting

- A first-deploy WinRM error immediately after a Windows rename is a known
  Ludus 2.2.1 race. Re-run the range deploy; completed hosts are skipped.
- If a role change appears to have no effect, resync the Ludus source before
  redeploying.
- Pulls are serialized with `COMPOSE_PARALLEL_LIMIT=1` because the range DNS
  forwarder can time out under many simultaneous registry lookups.
- The SIEM installer's complete output is kept mode 0600 at
  `/root/nano-v2-install.log`; Ansible does not echo it because it may contain
  sensitive setup context.

## License

[Apache-2.0](LICENSE)
