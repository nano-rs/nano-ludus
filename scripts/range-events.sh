#!/usr/bin/env bash
# Show what the range's SIEM has stored in OCSF: event counts by source and
# class, and by host when the table has a host column.
#
#   scripts/range-events.sh [siem-ip] [hours]     (defaults: 10.1.10.10, 6)
#
# Runs over SSH as the template's debian user and uses sudo for Docker, so it
# asks for those passwords itself. The query runs inside the nano-clickhouse
# container with the credentials that container already holds; no password is
# passed on a command line or printed.
set -euo pipefail

host=${1:-10.1.10.10}
hours=${2:-6}
[[ "$hours" =~ ^[1-9][0-9]*$ ]] || { echo "hours must be a positive integer" >&2; exit 2; }

# Runs as root on the SIEM box. $1 is the hour window.
remote=$(cat <<'REMOTE'
set -euo pipefail
docker exec -i -e HOURS="$1" nano-clickhouse sh -s <<'CONTAINER'
set -eu
export CLICKHOUSE_USER=nanosiem CLICKHOUSE_PASSWORD="$CLICKHOUSE_NANOSIEM_PASSWORD"
q() { clickhouse-client --format PrettyCompactMonoBlock -q "$1"; }

echo "== nanosiem.ocsf_logs, last $HOURS h, by source and class"
q "SELECT source_type, class_name, count() AS events, max(timestamp) AS latest
   FROM nanosiem.ocsf_logs
   WHERE timestamp > now() - INTERVAL $HOURS HOUR
   GROUP BY source_type, class_name
   ORDER BY events DESC
   LIMIT 30"

col=$(clickhouse-client -q "SELECT name FROM system.columns
   WHERE database = 'nanosiem' AND table = 'ocsf_logs'
     AND name IN ('device_hostname', 'src_endpoint_hostname', 'hostname', 'device_name')
   ORDER BY indexOf(['device_hostname', 'src_endpoint_hostname', 'hostname', 'device_name'], name)
   LIMIT 1")
if [ -n "$col" ]; then
    echo "== by host ($col)"
    q "SELECT $col AS host, source_type, count() AS events, max(timestamp) AS latest
       FROM nanosiem.ocsf_logs
       WHERE timestamp > now() - INTERVAL $HOURS HOUR
       GROUP BY host, source_type
       ORDER BY host, events DESC"
else
    echo "== no host column found; host-like columns in ocsf_logs:"
    clickhouse-client -q "SELECT name FROM system.columns
       WHERE database = 'nanosiem' AND table = 'ocsf_logs' AND name ILIKE '%host%'
       FORMAT TSV"
fi
CONTAINER
REMOTE
)

ssh -t "debian@$host" "sudo bash -c $(printf '%q' "$remote") range-events $(printf '%q' "$hours")"
