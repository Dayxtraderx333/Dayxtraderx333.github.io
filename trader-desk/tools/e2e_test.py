#!/usr/bin/env python3
"""End-to-end test for Trader Desk protocol v2 (and v1 compatibility) via ppng.io.

Run as rabbitagent with the bridge venv:
  sudo -u rabbitagent ~/.traderdesk/venv/bin/python e2e_test.py \
      [--key ~/.traderdesk/device.key] [--log ~/.traderdesk/bridge.log] [--no-v1] [--flood]
Never prints the key.
"""
import argparse, base64, hashlib, hmac, json, os, re, sys, time, threading, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RELAY = "https://ppng.io"
RES_BUCKETS = (1024, 2048, 4096, 8192)
KEY_FILE = "/home/rabbitagent/.traderdesk/device.key"   # kept for importers (health ping)
LOG = "/home/rabbitagent/.traderdesk/bridge.log"


class Client:
    def __init__(self, k):
        self.k = k
        self.aes = AESGCM(hmac.new(k, b"aes-v1", hashlib.sha256).digest())
        self.req = "td-" + hmac.new(k, b"req-v1", hashlib.sha256).hexdigest()[:32]

    def res(self, rid):
        return "td-" + hmac.new(self.k, b"res-v1" + rid.encode(), hashlib.sha256).hexdigest()[:32]

    def build(self, cmd, arg="", ts=None, rid=None, v=2, pad=64):
        rid = rid or os.urandom(16).hex()
        ts = int(time.time()) if ts is None else ts
        iv = os.urandom(12)
        pt = json.dumps({"cmd": cmd, "arg": arg}).encode()
        if v == 2:
            pt = pt + b" " * max(0, pad - len(pt))
            ct = self.aes.encrypt(iv, pt, f"req|2|{rid}|{ts}".encode())
            env = {"v": 2, "id": rid, "ts": ts}
        else:
            ct = self.aes.encrypt(iv, pt, f"req|1|{rid}|{ts}|{cmd}".encode())
            env = {"v": 1, "id": rid, "ts": ts, "cmd": cmd}
        env.update(iv=base64.b64encode(iv).decode(), ct=base64.b64encode(ct).decode())
        return rid, env

    def open(self, rid, cmd, txt, v=2):
        env = json.loads(txt)
        assert env["id"] == rid and env["v"] == v
        raw_ct = base64.b64decode(env["ct"])
        aad = f"res|2|{rid}|{env['ts']}" if v == 2 else f"res|1|{rid}|{env['ts']}|{cmd}"
        pt = self.aes.decrypt(base64.b64decode(env["iv"]), raw_ct, aad.encode())
        res = json.loads(pt)
        assert res["id"] == rid and res["cmd"] == cmd, "reply not bound to request"
        res["_ptlen"] = len(pt)
        return res


def get(url, timeout):
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=timeout) as r:
            return r.read().decode()
    except Exception:
        return None


def post(url, body, timeout=30):
    try:
        req = urllib.request.Request(url, data=body.encode(), method="POST")
        req.add_header("Content-Type", "text/plain")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
        return True
    except Exception:
        return False


def roundtrip(client, rid, cmd, body, reply_client=None, wait=40, req_channel=None, v=2):
    out = {}
    rc = reply_client or client
    t = threading.Thread(target=lambda: out.setdefault("txt", get(f"{RELAY}/{rc.res(rid)}", wait)))
    t.start()
    time.sleep(0.4)
    payload = json.dumps(body) if isinstance(body, dict) else body
    for _ in range(4):   # like the page: retry if the relay drops the hand-over
        if post(f"{RELAY}/{req_channel or client.req}", payload, timeout=min(wait, 30)):
            break
        time.sleep(0.6)
    t.join(wait + 5)
    txt = out.get("txt")
    if not txt:
        return None
    return rc.open(rid, cmd, txt, v)


results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default=KEY_FILE)
    ap.add_argument("--log", default=LOG)
    ap.add_argument("--no-v1", action="store_true")
    ap.add_argument("--flood", action="store_true")
    args = ap.parse_args()
    log_path = args.log

    def lines():
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            return fh.readlines()

    def count(pattern, since):
        return sum(1 for l in lines()[since:] if pattern in l)

    with open(args.key) as fh:
        c = Client(bytes.fromhex(fh.read().strip()))
    start = len(lines())
    boot = None
    for l in reversed(lines()):
        m = re.search(r"boot=(\d+)", l)
        if m:
            boot = int(m.group(1)); break

    # ---- ts before bridge start (only testable within 60 s of start)
    if boot and time.time() - boot < 50:
        rid, body = c.build("pulse", ts=boot - 3)
        res = roundtrip(c, rid, "pulse", body, wait=8)
        check("ts earlier than bridge start rejected", res is None and count("predates bridge start", start) >= 1)
    else:
        print("SKIP  ts-before-start test (bridge started >50 s ago)")

    # ---- positives: all 7 commands, v2
    last_body = None
    for cmd, arg in [("brief", ""), ("pulse", ""), ("spy", ""), ("options", ""),
                     ("quote", "NVDA"), ("scorecard", ""), ("botstatus", "")]:
        t0 = time.time()
        rid, body = c.build(cmd, arg)
        res = roundtrip(c, rid, cmd, body)
        ok = bool(res and res.get("ok") and len(res.get("text", "")) > 40)
        check(f"v2 {cmd} {arg}".strip(), ok and res["_ptlen"] in RES_BUCKETS and "cmd" not in body,
              f"{len(res['text']) if res else 0} chars, padded to {res['_ptlen'] if res else '-'}, {time.time()-t0:.1f}s")
        if ok:
            last_body = (rid, cmd, body)

    # ---- v1 compatibility during cutover
    if not args.no_v1:
        rid, body = c.build("pulse", v=1)
        res = roundtrip(c, rid, "pulse", body, v=1)
        check("v1 request still answered (in v1)", bool(res and res["ok"]))
    else:
        rid, body = c.build("pulse", v=1)
        res = roundtrip(c, rid, "pulse", body, wait=8, v=1)
        check("v1 request refused", res is None)

    # ---- unknown cmd and ticker injection
    rid, body = c.build("ops")
    res = roundtrip(c, rid, "ops", body)
    check("unknown cmd 'ops' refused", bool(res and not res["ok"] and "Unknown" in res["text"]))
    rid, body = c.build("quote", "NVDA; rm -rf /")
    res = roundtrip(c, rid, "quote", body)
    check("ticker injection refused", bool(res and not res["ok"] and "ticker" in res["text"]))

    # ---- replay, stale, unpadded, tamper
    rid, cmd, body = last_body
    check("replayed id gets no answer", roundtrip(c, rid, cmd, body, wait=8) is None)
    rid, body = c.build("pulse", ts=int(time.time()) - 120)
    check("stale ts (-120 s) gets no answer", roundtrip(c, rid, "pulse", body, wait=8) is None)
    rid, body = c.build("pulse", pad=0)
    check("v2 unpadded plaintext refused", roundtrip(c, rid, "pulse", body, wait=8) is None)
    rid, body = c.build("pulse")
    ct = bytearray(base64.b64decode(body["ct"])); ct[0] ^= 1
    body["ct"] = base64.b64encode(bytes(ct)).decode()
    check("tampered ciphertext gets no answer", roundtrip(c, rid, "pulse", body, wait=8) is None)
    rid, body = c.build("pulse"); body["ts"] += 1
    check("tampered AAD (ts) gets no answer", roundtrip(c, rid, "pulse", body, wait=8) is None)
    bad = Client(os.urandom(32))
    rid, body = bad.build("pulse")
    check("wrong key on real channel gets no answer",
          roundtrip(bad, rid, "pulse", body, wait=8, req_channel=c.req) is None)
    rid, body = bad.build("pulse")
    check("wrong key's own channel is unanswered", roundtrip(bad, rid, "pulse", body, wait=6) is None)

    # ---- rate limit (10 accepted / minute)
    limited = False
    for i in range(12):
        rid, body = c.build("nope")
        res = roundtrip(c, rid, "nope", body, wait=20)
        if res and "Too many requests" in res["text"]:
            limited = True
            break
    check("rate limit triggers within 12 rapid requests", limited, f"after {i+1}")

    # ---- garbage flood must not block a valid request (no lockout any more)
    if args.flood:
        print("flood: 25 unauthenticated bodies, then a valid request", flush=True)
        for _ in range(25):
            rid, body = c.build("pulse")
            body["ct"] = base64.b64encode(os.urandom(48)).decode()
            post(f"{RELAY}/{c.req}", json.dumps(body), timeout=10)
        print("waiting 62 s so the valid-request rate limit is clear", flush=True)
        time.sleep(62)
        rid, body = c.build("pulse")
        res = roundtrip(c, rid, "pulse", body)
        check("valid request answered right after a garbage flood", bool(res and res["ok"]))
        check("unauth cap engaged (excess dropped silently)", count("unauth cap reached", start) >= 1)
        check("no lockout exists", count("LOCKOUT", start) == 0)

    time.sleep(1.5)
    check("log: auth rejected / replay / stale lines",
          count("auth rejected", start) >= 2 and count("replay", start) >= 1 and count("stale request", start) >= 1)
    new = "".join(lines()[start:])
    check("log has no payloads/args/keys", "NVDA" not in new and "rm -rf" not in new
          and c.req not in new and '"ct"' not in new)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
