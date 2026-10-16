"""Offline stand-in for the nano ingest-token API (nanosiem #6582) and HEC.

    python3 -I tests/provision/mock_nano.py <seed.json> <port-file>

Serves, on 127.0.0.1 (random port, written to <port-file>):
  POST /api/auth/login
  GET  /api/ingest-tokens                       (seed "model": bound | legacy | missing)
  POST /api/ingest-tokens                       {name, source_id} -> 201
  POST /api/ingest-tokens/{id}/bind             {source_id}
  POST /api/ingest-tokens/{id}/revoke
  POST /services/collector/event                401 unless the token is active and bound
  GET  /_state                                  test inspection (tokens incl. values, calls)
Test data only; no real secrets.
"""
import json
import secrets
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

seed = json.load(open(sys.argv[1]))
MODEL = seed.get("model", "bound")
SOURCES = seed.get("sources", [])
TOKENS = seed.get("tokens", [])  # each: credential_id, name, value, source_id|None, revoked
CALLS = []
EVENTS = []


def route_of(source_id):
    for s in SOURCES:
        if s["source_id"] == source_id:
            return s
    return None


def view(t):
    src = route_of(t.get("source_id")) if t.get("source_id") else None
    state = "revoked" if t.get("revoked") else ("active" if src else "unbound")
    return {
        "credential_id": t["credential_id"],
        "name": t["name"],
        "token_prefix": t["value"][:12],
        "state": state,
        "source_id": t.get("source_id"),
        "source_name": src["name"] if src else None,
        "route_key": src["route_key"] if src else None,
        "request_count": t.get("request_count", 0),
        "revocable": not t.get("revoked"),
    }


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body=None):
        data = json.dumps(body if body is not None else {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def authed(self):
        return self.headers.get("X-API-Key") == "test-api-key" or self.headers.get("Authorization") == "Bearer test-session"

    def do_GET(self):
        if self.path == "/_state":
            return self.send(200, {"tokens": TOKENS, "calls": CALLS, "events": EVENTS})
        if self.path == "/api/ingest-tokens":
            CALLS.append("list")
            if MODEL == "missing":
                return self.send(404, {"error": "not found"})
            if not self.authed():
                return self.send(401)
            body = {"tokens": [view(t) for t in TOKENS], "install_token": {"name": "Install token (legacy)"}}
            if MODEL == "bound":
                body["sources"] = SOURCES
            return self.send(200, body)
        return self.send(404)

    def do_POST(self):
        p = self.path
        if p == "/api/auth/login":
            b = self.body()
            if b.get("password") == "test-password":
                return self.send(200, {"tokens": {"access_token": "test-session"}})
            return self.send(401, {"error": "invalid credentials"})
        if p == "/services/collector/event":
            auth = self.headers.get("Authorization", "")
            value = auth[len("Splunk "):] if auth.startswith("Splunk ") else None
            tok = next((t for t in TOKENS if t["value"] == value), None)
            if MODEL != "bound":
                ok = value == seed.get("install_token")
                EVENTS.append({"route": "legacy", "body": self.body()})
                return self.send(200 if ok else 401, {"text": "Success" if ok else "Invalid token", "code": 0 if ok else 4})
            if not tok or tok.get("revoked") or not route_of(tok.get("source_id")):
                return self.send(401, {"text": "Invalid token", "code": 4})
            EVENTS.append({"route": route_of(tok["source_id"])["route_key"], "body": self.body()})
            return self.send(200, {"text": "Success", "code": 0})
        if not p.startswith("/api/ingest-tokens"):
            return self.send(404)
        if not self.authed():
            return self.send(401)
        if p == "/api/ingest-tokens":
            b = self.body()
            CALLS.append("create")
            if set(b) != {"name", "source_id"}:
                return self.send(422, {"error": "name + source_id only"})
            if not route_of(b["source_id"]):
                return self.send(400, {"error": "source"})
            if any(t["name"] == b["name"] and not t.get("revoked") for t in TOKENS):
                return self.send(409, {"error": "duplicate name"})
            t = {"credential_id": str(uuid.uuid4()), "name": b["name"], "value": "nit_" + secrets.token_hex(16),
                 "source_id": b["source_id"], "revoked": False}
            TOKENS.append(t)
            return self.send(201, {"credential": view(t), "token": t["value"]})
        parts = p.strip("/").split("/")
        if len(parts) == 4:
            t = next((t for t in TOKENS if t["credential_id"] == parts[2]), None)
            if not t:
                return self.send(404)
            if parts[3] == "bind":
                CALLS.append("bind")
                b = self.body()
                if t.get("revoked") or t.get("source_id"):
                    return self.send(409, {"error": "already bound"})
                if not route_of(b.get("source_id")):
                    return self.send(400)
                t["source_id"] = b["source_id"]
                return self.send(200, view(t))
            if parts[3] == "revoke":
                CALLS.append("revoke")
                if t.get("revoked"):
                    return self.send(409)
                t["revoked"] = True
                return self.send(200, view(t))
        return self.send(404)


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
open(sys.argv[2], "w").write(str(srv.server_address[1]))
srv.serve_forever()
