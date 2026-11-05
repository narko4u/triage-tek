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
import shutil
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sel.engine import Engine, LedgerIntegrityError, UnknownPerson   # noqa: E402
from sel import tamper as tamper_mod   # noqa: E402
from sel.ledger import Ledger          # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
DATA = os.environ.get("SEL_DATA") or os.path.join(HERE, "data")
SIGNER = None
if os.environ.get("SEL_HYBRID") == "1":
    from sel import pqc
    SIGNER = pqc.Signer(os.path.join(DATA, "keys"))
try:
    ENGINE = Engine(DATA, signer=SIGNER)
except LedgerIntegrityError as exc:
    raise SystemExit(str(exc))


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
        self.send_header("X-Robots-Tag", "noindex, nofollow")
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
            try:
                limit = int(q.get("limit", ["150"])[0])
                offset = int(q.get("offset", ["0"])[0])
            except (TypeError, ValueError):
                return self._send(400, {"error": "limit and offset must be integers"})
            if not 1 <= limit <= 500:
                return self._send(400, {"error": "limit must be between 1 and 500"})
            if offset < 0:
                return self._send(400, {"error": "offset must not be negative"})
            rows = ENGINE.queue(limit, offset)
            total = len(ENGINE.queue(len(ENGINE.cohort)))
            return self._send(200, {"queue": rows, "total": total,
                                    "limit": limit, "offset": offset})
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
            pid = unquote(path[len("/api/person/"):])
            try:
                return self._send(200, ENGINE.person_view(pid))
            except UnknownPerson:
                return self._send(404, {"error": "no such person"})
            except KeyError:
                return self._send(500, {"error": "person record is incomplete"})
        if path == "/api/export/cohort":
            return self._export_cohort()
        if path == "/api/export":
            pid = q.get("person_id", [None])[0]
            if not pid:
                return self._send(400, {"error": "missing required field"})
            try:
                return self._export_person(pid)
            except UnknownPerson:
                return self._send(404, {"error": "no such person"})
            except KeyError:
                return self._send(500, {"error": "person record is incomplete"})

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        try:
            body = self._json_body()
        except Exception:
            return self._send(400, {"error": "invalid json"})

        if not isinstance(body, dict):
            return self._send(400, {"error": "body must be a JSON object"})

        person_id = body.get("person_id")
        if person_id is not None and not isinstance(person_id, str):
            return self._send(400, {"error": "person_id must be a string"})

        if u.path == "/api/approve":
            if not person_id:
                return self._send(400, {"error": "person_id required"})
            try:
                rec = ENGINE.approve(person_id, body.get("approver_id", "clinician"),
                                     body.get("role", "clinician"), body.get("note", ""))
            except UnknownPerson:
                return self._send(404, {"error": "no such person"})
            except ValueError as exc:
                return self._send(409, {"error": str(exc)})
            return self._send(200, {"sealed": rec})
        if u.path == "/api/release":
            if not person_id:
                return self._send(400, {"error": "person_id required"})
            try:
                rec = ENGINE.release(person_id, body.get("released_by", "clinician"))
            except UnknownPerson:
                return self._send(404, {"error": "no such person"})
            except ValueError as exc:
                return self._send(409, {"error": str(exc)})
            return self._send(200, {"sealed": rec})
        if u.path == "/api/outcome":
            if not person_id or not body.get("outcome"):
                return self._send(400, {"error": "person_id and outcome required"})
            try:
                rec = ENGINE.record_outcome(person_id, body["outcome"])
            except UnknownPerson:
                return self._send(404, {"error": "no such person"})
            except ValueError as exc:
                return self._send(409, {"error": str(exc)})
            return self._send(200, {"sealed": rec})
        if u.path == "/api/tamper":
            seq = body.get("seq")
            if seq is not None and (not isinstance(seq, int) or isinstance(seq, bool) or seq < 0):
                return self._send(400, {"error": "seq must be a non-negative integer"})
            if seq is not None and seq >= len(ENGINE.ledger):
                return self._send(400, {"error": "seq out of range"})
            target = seq if seq is not None else self._first_tier_seq()
            if target is not None and "tier" not in ENGINE.ledger.all()[target]:
                return self._send(400, {"error": "chosen record has no tier field to tamper"})
            return self._tamper(seq)
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

    def _first_tier_seq(self):
        for i, rec in enumerate(ENGINE.ledger.all()):
            if "tier" in rec:
                return i
        return None

    def _tamper(self, seq):
        src = os.path.join(ENGINE.data_dir, "ledger.jsonl")
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


def _rebuild_engine():
    """Seal a fresh cycle beside the live one, then swap it in."""
    global ENGINE, DATA
    staging = DATA.rstrip("/") + ".next"
    shutil.rmtree(staging, ignore_errors=True)
    fresh = Engine(staging)
    fresh.run_cycle()
    previous = DATA
    ENGINE, DATA = fresh, staging
    shutil.rmtree(previous, ignore_errors=True)
    print("demo reset: %d records, head %s" % (len(ENGINE.ledger), ENGINE.ledger.head[:12]))


def _reset_loop(interval):
    while True:
        time.sleep(interval)
        try:
            _rebuild_engine()
        except Exception as exc:  # a failed reset must never kill the server
            print("demo reset failed: %s" % exc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8791)))
    ap.add_argument("--host", default=os.environ.get("SEL_HOST", "127.0.0.1"))
    args = ap.parse_args()

    if not any(r.get("decision") for r in ENGINE.ledger.all()):
        result = ENGINE.run_cycle()
        print("cycle:", json.dumps(result))
        if SIGNER is not None:
            ENGINE.ledger.seal_checkpoint()

    interval = int(os.environ.get("SEL_DEMO_RESET_SECONDS", "0"))
    if interval > 0:
        threading.Thread(target=_reset_loop, args=(interval,), daemon=True).start()
        print("demo reset every %d seconds" % interval)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("TriageTek on http://%s:%d" % (args.host, args.port))
    print("ledger records:", len(ENGINE.ledger))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
