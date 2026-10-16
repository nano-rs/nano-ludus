"""Offline wire proof: rendered Vector sinks -> loopback HEC mock, no VM setup.

Uses only fake test credentials. Replaces agent intake with stdin; routing,
encoding, compression, per-source secrets and HEC acknowledgements stay rendered.
"""
import gzip
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("VECTOR_IMAGE", "timberio/vector:0.59.0-alpine@sha256:0e36bc2a290039e9b6a5e92f04bd2f133223506f72d09682c1df16c015172b7a")
SAMPLES = {
    "windows_event": {"event_id": 4624, "event_data": {"TargetUserName": "lab-user"}},
    "windows_sysmon": {"event_id": 1, "event_data": {"Image": "C:\\Windows\\System32\\cmd.exe"}},
    "conduit_proxy": {"method": "GET", "url": "https://example.test/", "status": 200},
}
TOKENS = {st: f"TESTTOKEN-{st}-wire-0123456789abcdef" for st in SAMPLES}
EVENTS = []
ACKS = []
ERRORS = []
DELIVERED = threading.Event()


class HEC(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.send({"text": "HEC is healthy", "code": 17})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
        if self.path == "/services/collector/ack":
            ids = json.loads(raw)["acks"]
            ACKS.extend(ids)
            if set(EVENTS) == set(SAMPLES):
                DELIVERED.set()
            return self.send({"acks": {str(i): True for i in ids}})
        try:
            assert self.path == "/services/collector/event"
            auth = self.headers.get("Authorization", "")
            route = next(st for st, value in TOKENS.items() if auth == "Splunk " + value)
            # HEC batches are consecutive JSON objects, with optional newlines.
            decoder = json.JSONDecoder()
            data = raw.decode().strip()
            while data:
                event, end = decoder.raw_decode(data)
                assert event["sourcetype"] == route
                assert isinstance(event["event"], str), "HEC payload must be the original message"
                assert json.loads(event["event"]) == SAMPLES[route], "parser input was nested or changed"
                EVENTS.append(route)
                data = data[end:].lstrip()
            self.send({"text": "Success", "code": 0, "ackId": len(EVENTS)})
        except Exception as exc:
            # Never dump requests or headers, even though these tokens are fake.
            ERRORS.append(type(exc).__name__)
            self.send({"text": "Invalid payload", "code": 6})


with ThreadingHTTPServer(("127.0.0.1", 0), HEC) as server, tempfile.TemporaryDirectory(prefix="ludus-wire-") as temp:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    out = Path(temp)
    variables = {
        "render_parts": ["aggregator"], "out_dir": temp,
        "nano_ingest_url": f"http://127.0.0.1:{server.server_port}",
        "nano_ingest_source_tokens": TOKENS,
    }
    vars_file = out / "vars.json"
    vars_file.write_text(json.dumps(variables))
    rendered = subprocess.run([
        "ansible-playbook", "-i", str(ROOT / "tests/inventory.ini"),
        str(ROOT / "tests/render.yml"), "-e", "@" + str(vars_file),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
    assert rendered.returncode == 0, "wire scenario rendering failed (output withheld)"
    config = (out / "aggregator.toml").read_text()
    assert 'acknowledgements.indexer_acknowledgements_enabled = true' in config
    config = re.sub(r'\[sources.agents\]\n.*?(?=\n\[|\n#)',
                    '[sources.agents]\ntype = "stdin"\ndecoding.codec = "json"\n', config, flags=re.S)
    config = config.replace('data_dir = "/var/lib/vector"', 'data_dir = "/tmp/vector-wire"')
    # Test-only shortening; preserve the ACK-enabled production sink behavior.
    config = config.replace('type = "disk"\nmax_size = 1073741824', 'type = "memory"\nmax_events = 100')
    config = config.replace('compression = "gzip"', 'compression = "gzip"\nbatch.timeout_secs = 0.1\nacknowledgements.query_interval = 1')
    (out / "wire.toml").write_text(config)
    payload = "".join(json.dumps({"source_type": st, "message": json.dumps(sample)}) + "\n" for st, sample in SAMPLES.items())
    name = out.name
    run = subprocess.Popen([
        "docker", "run", "--rm", "-i", "--name", name, "--network", "host",
        "-v", f"{temp}:/cfg:ro", "-v", f"{temp}/secrets:/etc/vector/secrets:ro",
        IMAGE, "--config", "/cfg/wire.toml", "--require-healthy", "true",
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        run.stdin.write(payload.encode())
        run.stdin.close()
        run.stdin = None
        delivered = DELIVERED.wait(20)
    finally:
        subprocess.run(["docker", "stop", "--timeout", "2", name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10)
        output, _ = run.communicate(timeout=10)
    assert delivered, "Vector did not deliver all source messages and poll receipts (output withheld)"
    assert not ERRORS, "HEC rejected rendered sender payload"
    assert sorted(set(EVENTS)) == sorted(SAMPLES), "not every source reached HEC with its own token"
    assert ACKS, "rendered sender did not poll HEC receipts"
    server.shutdown()
print("wire: all three source payloads, distinct credentials, gzip and HEC ACK polling passed")
