# Quarantined: gen1 roles (NAN-3397)

`nano_stack/` deployed the legacy ("gen1") nano stack: ClickHouse + PostgreSQL
+ the UDM pipeline, fetched from the public `nano-rs/nano` mirror's
`docker-compose.opensource.yml`. That stack is no longer the product. The range
SIEM is now an open-core **lake** install (`ansible/roles/nano_lake`), and a
range can also ship straight to a hosted lean tenant
(`nano_vector_aggregator` with `nano_ingest_url` / `nano_ingest_token`).

The role is kept here, outside `ansible/roles/`, only for reference: Ludus
packages `ansible/roles/` alone, so nothing in this directory can be deployed
from the `nanosiem` blueprint. `tests/check.sh` fails if it moves back.
