# Decide, per forwarded source_type, how the aggregator gets an ingest token
# bound to that source on an open-core nano (NAN-3841, NAN-3806 model).
#
# nano (nanosiem #6582) binds every ingest token to exactly one log source and
# routes every event sent with it there, whatever `sourcetype` it declares.
# This filter only plans; ingest_tokens.yml performs the API calls.
#
# It never returns a token value. Operator-supplied tokens are reduced to their
# display prefix (`nit_` + 8 characters), which is what the API lists.

from __future__ import annotations

TOKEN_MARKER = "nit_"
PREFIX_LEN = len(TOKEN_MARKER) + 8


def _token_prefix(value):
    if isinstance(value, str) and value.startswith(TOKEN_MARKER) and len(value) >= PREFIX_LEN:
        return value[:PREFIX_LEN]
    return None


def nano_ingest_token_plan(wanted, listing, operator_tokens=None, state=None, secret_names=None):
    """Plan one entry per wanted source_type.

    wanted          source_types the aggregator forwards
    listing         GET /api/ingest-tokens body: {tokens: [...], sources: [...]}
    operator_tokens nano_ingest_source_tokens (st -> token value)
    state           ingest-credentials.json (st -> credential_id) from a previous run
    secret_names    names of the token files already in the secrets dir

    Each entry: {source_type, action, source_id, credential_id, revoke, error}
      action: operator  - the operator's token is used as given (already bound
                          to this source, or not a nano-issued token we can check)
              bind      - the operator's token is unbound: bind credential_id
              reuse     - keep the token this role issued earlier (credential_id)
              create    - issue a new token bound to source_id; revoke the
                          stale credential `revoke` afterwards, if any
              error     - `error` says why; the play fails
    """
    operator_tokens = operator_tokens or {}
    state = state or {}
    secret_names = set(secret_names or [])
    tokens = listing.get("tokens") or []
    sources = listing.get("sources") or []

    by_route = {}
    for source in sources:
        route = source.get("route_key")
        if not route:
            continue
        # Prefer an enabled source when two share a route key.
        if route not in by_route or (source.get("enabled") and not by_route[route].get("enabled")):
            by_route[route] = source
    by_id = {t.get("credential_id"): t for t in tokens}
    by_prefix = {}
    for t in tokens:
        if t.get("state") != "revoked" and t.get("token_prefix"):
            by_prefix.setdefault(t["token_prefix"], []).append(t)

    plan = []
    for st in wanted:
        entry = {
            "source_type": st,
            "action": "error",
            "source_id": None,
            "credential_id": None,
            "revoke": None,
            "error": None,
        }
        plan.append(entry)
        source = by_route.get(st)
        if source is None:
            entry["error"] = (
                f"nano has no log source with route key {st!r}, so no token can be bound to it. "
                f"Deploy its parser (nano_lean_parsers on the SIEM, or Settings > Parser Repository) "
                f"or drop {st!r} from nano_ingest_sources."
            )
            continue
        entry["source_id"] = source.get("source_id")

        supplied = operator_tokens.get(st)
        if supplied:
            prefix = _token_prefix(supplied)
            matches = by_prefix.get(prefix, []) if prefix else []
            if len(matches) != 1:
                # Not a nano-issued token (or not uniquely listed): use it as
                # given. The post-start check reports a 401.
                entry["action"] = "operator"
                continue
            cred = matches[0]
            entry["credential_id"] = cred.get("credential_id")
            if cred.get("state") == "unbound":
                entry["action"] = "bind"
            elif cred.get("route_key") == st:
                entry["action"] = "operator"
            else:
                entry["error"] = (
                    f"The token given for {st!r} in nano_ingest_source_tokens ({prefix}) is bound to "
                    f"{cred.get('route_key') or cred.get('source_name') or 'another source'!r}. "
                    f"Bindings never change: revoke it and issue a token bound to {st!r}."
                )
            continue

        previous = state.get(st)
        cred = by_id.get(previous) if previous else None
        if cred and cred.get("state") == "active" and cred.get("route_key") == st and st in secret_names:
            entry["action"] = "reuse"
            entry["credential_id"] = previous
            continue
        entry["action"] = "create"
        if cred and cred.get("state") != "revoked":
            entry["revoke"] = previous
    return plan


class FilterModule:
    def filters(self):
        return {"nano_ingest_token_plan": nano_ingest_token_plan}
