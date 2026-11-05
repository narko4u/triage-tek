#!/usr/bin/env python3
"""TriageTek - demo server.

Standard library only. No accounts, no external services, no network calls.
Run: python3 server.py [--port 8791]
"""
import argparse
import csv
import io
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sel.engine import Engine          # noqa: E402
from sel import tamper as tamper_mod   # noqa: E402
from sel.ledger import Ledger          # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
DATA = os.environ.get("SEL_DATA") or os.path.join(HERE, "data")
SIGNER = None
if os.environ.get("SEL_HYBRID") == "1":
    from sel import pqc
    SIGNER = pqc.Signer(os.path.join(DATA, "keys"))
ENGINE = Engine(DATA, signer=SIGNER)


class Handler(BaseHTTPRequestHandler):
    server_version = "SEL/0.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ---- helpers -------------------------------------------------------
    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, (bytes, bytearray)):
            body = (json.dumps(body, indent=1) if ctype == "application/json" else str(body)).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        return json.loads(self.rfile.read(n).decode("utf-8"))

    # ---- routing -------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path

        if path in ("/", "/index.html"):
            return self._static("index.html", "text/html; charset=utf-8")
        if path.startswith("/static/"):
            name = path[len("/static/"):]
            return self._static(name, "text/css" if name.endswith(".css") else "application/javascript")

        if path == "/api/summary":
            return self._send(200, ENGINE.summary())
        if path == "/api/queue":
            return self._send(200, {"queue": ENGINE.queue(int(q.get("limit", ["150"])[0]))})
        if path == "/api/equity":
            return self._send(200, ENGINE.equity())
        if path == "/api/verify":
            ok, bad, detail = ENGINE.ledger.verify()
            payload = {"ok": ok, "records": len(ENGINE.ledger),
                       "head": ENGINE.ledger.head, "first_bad_seq": bad, "detail": detail}
            if any(r.get("kind") == "KEY" for r in ENGINE.ledger.all()):
                payload["signatures"] = ENGINE.ledger.verify_signatures()
            return self._send(200, payload)
        if path.startswith("/api/person/"):
            pid = path[len("/api/person/"):]
            try:
                return self._send(200, ENGINE.person_view(pid))
            except KeyError:
                return self._send(404, {"error": "no such person"})
        if path == "/api/export/cohort":
            return self._export_cohort()
        if path == "/api/export":
            pid = q.get("person_id", [None])[0]
            if not pid:
                return self._send(400, {"error": "person_id required"})
            try:
                return self._export_person(pid)
            except KeyError:
                return self._send(404, {"error": "no such person"})

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        try:
            body = self._json_body()
        except Exception:
            return self._send(400, {"error": "invalid json"})

        if u.path == "/api/approve":
            try:
                rec = ENGINE.approve(body["person_id"], body.get("approver_id", "clinician"),
                                     body.get("role", "clinician"), body.get("note", ""))
            except (KeyError, ValueError) as exc:
                return self._send(409, {"error": str(exc)})
            return self._send(200, {"sealed": rec})
        if u.path == "/api/release":
            try:
                rec = ENGINE.release(body["person_id"], body.get("released_by", "clinician"))
            except (KeyError, ValueError) as exc:
                return self._send(409, {"error": str(exc)})
            return self._send(200, {"sealed": rec})
        if u.path == "/api/outcome":
            try:
                rec = ENGINE.record_outcome(body["person_id"], body["outcome"])
            except (KeyError, ValueError) as exc:
                return self._send(409, {"error": str(exc)})
            return self._send(200, {"sealed": rec})
        if u.path == "/api/tamper":
            return self._tamper(body.get("seq"))
        if u.path == "/api/reset":
            return self._send(403, {"error": "reset disabled: the record is append-only by design"})

        return self._send(404, {"error": "not found"})

    # ---- payloads ------------------------------------------------------
    def _static(self, name, ctype):
        root = os.path.realpath(WEB)
        path = os.path.realpath(os.path.join(root, name))
        if path != root and not path.startswith(root + os.sep):
            return self._send(404, {"error": "not found"})
        if not os.path.isfile(path):
            return self._send(404, {"error": "not found"})
        with open(path, "rb") as fh:
            return self._send(200, fh.read(), ctype)

    def _tamper(self, seq):
        src = os.path.join(DATA, "ledger.jsonl")
        dst = os.path.join(DATA, "tampered.jsonl")
        if seq is None:
            seq = 0
            for i, rec in enumerate(ENGINE.ledger.all()):
                if rec.get("tier") == "HIGH":
                    seq = i
                    break
        info = tamper_mod.tamper(src, dst, seq, "tier", "LOW")
        ok, bad, detail = Ledger(dst).verify()
        live_ok, _, live_detail = ENGINE.ledger.verify()
        return self._send(200, {"tampered": info, "tampered_verify": {"ok": ok, "first_bad_seq": bad, "detail": detail},
                                "live_verify": {"ok": live_ok, "detail": live_detail}})

    def _export_person(self, pid):
        view = ENGINE.person_view(pid)
        pack = {
            "generated_at": ENGINE.summary()["sealed_at"],
            "person_id": pid,
            "pseudonym": view["pseudonym"],
            "assessment": view["assessment"],
            "status": view["status"],
            "records": view["chain"],
            "verification": dict(zip(("ok", "first_bad_seq", "detail"), ENGINE.ledger.verify())),
        }
        body = json.dumps(pack, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", 'attachment; filename="sel-audit-%s.json"' % pid)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _export_cohort(self):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["person_id", "pseudonym", "age", "sex", "tier", "score", "consent_secondary_use",
                    "consent_outreach", "status", "chain_records"])
        for person in ENGINE.cohort:
            v = ENGINE.person_view(person["person_id"])
            w.writerow([person["person_id"], v["pseudonym"], person["age"], person["sex"],
                        v["assessment"]["tier"], v["assessment"]["score"],
                        person["consent_secondary_use"], person["consent_outreach"],
                        v["status"], len(v["chain"])])
        body = buf.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", 'attachment; filename="sel-cohort-audit.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    if not ENGINE.ledger.all():
        result = ENGINE.run_cycle()
        print("cycle:", json.dumps(result))

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("TriageTek on http://%s:%d" % (args.host, args.port))
    print("ledger records:", len(ENGINE.ledger))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
