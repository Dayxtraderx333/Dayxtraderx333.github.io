#!/usr/bin/env python3
"""End-to-end test for Trader Desk protocol v1 through ppng.io.

Run as rabbitagent with the bridge venv:
  sudo -u rabbitagent ~/.traderdesk/venv/bin/python e2e_test.py [--lockout]
Reads the device key from ~/.traderdesk/device.key; never prints it.
"""
import base64, hashlib, hmac, json, os, sys, time, threading, urllib.request
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RELAY = "https://ppng.io"
KEY_FILE = "/home/rabbitagent/.traderdesk/device.key"
LOG = "/home/rabbitagent/.traderdesk/bridge.log"


class Client:
    def __init__(self, k):
        self.k = k
        self.aes = AESGCM(hmac.new(k, b"aes-v1", hashlib.sha256).digest())
        self.req = "td-" + hmac.new(k, b"req-v1", hashlib.sha256).hexdigest()[:32]

    def res(self, rid):
        return "td-" + hmac.new(self.k, b"res-v1" + rid.encode(), hashlib.sha256).hexdigest()[:32]

    def build(self, cmd, arg="", ts=None, rid=None):
        rid = rid or os.urandom(16).hex()
        ts = int(time.time()) if ts is None else ts
        iv = os.urandom(12)
        ct = self.aes.encrypt(iv, json.dumps({"cmd": cmd, "arg": arg}).encode(),
                              f"req|1|{rid}|{ts}|{cmd}".encode())
        return rid, {"v": 1, "id": rid, "ts": ts, "cmd": cmd,
                     "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()}

    def open(self, rid, cmd, txt):
        env = json.loads(txt)
        assert env["id"] == rid and env["v"] == 1
        pt = self.aes.decrypt(base64.b64decode(env["iv"]), base64.b64decode(env["ct"]),
                              f"res|1|{rid}|{env['ts']}|{cmd}".encode())
        res = json.loads(pt)
        assert res["id"] == rid and res["cmd"] == cmd, "reply not bound to request"
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


def roundtrip(client, rid, cmd, body, reply_client=None, wait=40, req_channel=None):
    out = {}
    rc = reply_client or client
    t = threading.Thread(target=lambda: out.setdefault("txt", get(f"{RELAY}/{rc.res(rid)}", wait)))
    t.start()
    time.sleep(0.4)
    post(f"{RELAY}/{req_channel or client.req}", json.dumps(body) if isinstance(body, dict) else body,
         timeout=min(wait, 30))
    t.join(wait + 5)
    txt = out.get("txt")
    if not txt:
        return None
    return rc.open(rid, cmd, txt)


results = []
def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}", flush=True)


def log_count(pattern, since):
    n = 0
    with open(LOG, encoding="utf-8", errors="replace") as fh:
        for line in fh.readlines()[since:]:
            if pattern in line:
                n += 1
    return n


def log_len():
    with open(LOG, encoding="utf-8", errors="replace") as fh:
        return len(fh.readlines())


def main():
    with open(KEY_FILE) as fh:
        c = Client(bytes.fromhex(fh.read().strip()))
    start = log_len()

    # ---- positives: all 7 commands
    last_body = None
    for cmd, arg in [("brief", ""), ("pulse", ""), ("spy", ""), ("options", ""),
                     ("quote", "NVDA"), ("scorecard", ""), ("botstatus", "")]:
        t0 = time.time()
        rid, body = c.build(cmd, arg)
        res = roundtrip(c, rid, cmd, body)
        ok = bool(res and res.get("ok") and len(res.get("text", "")) > 40)
        check(f"{cmd} {arg}".strip(), ok,
              f"{len(res['text']) if res else 0} chars, {time.time()-t0:.1f}s")
        last_body = (rid, cmd, body)

    # ---- unknown cmd (ops is no longer remote) and ticker injection
    rid, body = c.build("ops")
    res = roundtrip(c, rid, "ops", body)
    check("unknown cmd 'ops' refused", bool(res and not res["ok"] and "Unknown" in res["text"]))
    rid, body = c.build("quote", "NVDA; rm -rf /")
    res = roundtrip(c, rid, "quote", body)
    check("ticker injection refused", bool(res and not res["ok"] and "ticker" in res["text"]))
    rid, body = c.build("quote", "$(id)")
    res = roundtrip(c, rid, "quote", body)
    check("ticker $(id) refused", bool(res and not res["ok"] and "ticker" in res["text"]))

    # ---- replayed id (exact same authentic body again)
    rid, cmd, body = last_body
    res = roundtrip(c, rid, cmd, body, wait=8)
    check("replayed id gets no answer", res is None)

    # ---- stale ts
    rid, body = c.build("pulse", ts=int(time.time()) - 120)
    res = roundtrip(c, rid, "pulse", body, wait=8)
    check("stale ts (-120 s) gets no answer", res is None)

    # ---- tampered ciphertext
    rid, body = c.build("pulse")
    ct = bytearray(base64.b64decode(body["ct"])); ct[0] ^= 1
    body["ct"] = base64.b64encode(bytes(ct)).decode()
    res = roundtrip(c, rid, "pulse", body, wait=8)
    check("tampered ciphertext gets no answer", res is None)

    # ---- tampered AAD (cmd swapped in clear header)
    rid, body = c.build("pulse"); body["cmd"] = "brief"
    res = roundtrip(c, rid, "brief", body, wait=8)
    check("tampered header cmd gets no answer", res is None)

    # ---- wrong key, sent to the REAL channel (attacker who learned the channel)
    bad = Client(os.urandom(32))
    rid, body = bad.build("pulse")
    res = roundtrip(bad, rid, "pulse", body, reply_client=bad, wait=8, req_channel=c.req)
    res2 = get(f"{RELAY}/{c.res(rid)}", 3)
    check("wrong key on real channel gets no answer", res is None and not res2)

    # ---- wrong key on its own derived channel: bridge is not even listening there
    rid, body = bad.build("pulse")
    res = roundtrip(bad, rid, "pulse", body, wait=6)
    check("wrong key's channel is unanswered", res is None)

    # ---- rate limit (10 accepted / minute)
    limited = False
    for i in range(12):
        rid, body = c.build("nope")
        res = roundtrip(c, rid, "nope", body, wait=20)
        if res and "Too many requests" in res["text"]:
            limited = True
            break
    check("rate limit triggers within 12 rapid requests", limited, f"after {i+1}")

    time.sleep(1.5)
    check("log: 'auth rejected' lines written", log_count("auth rejected", start) >= 3,
          f"{log_count('auth rejected', start)} lines")
    check("log: replay + stale rejected", log_count("replay", start) >= 1 and log_count("stale request", start) >= 1)
    # metadata-only logging: no ticker args or payload text in the new log lines
    with open(LOG, encoding="utf-8", errors="replace") as fh:
        new = "".join(fh.readlines()[start:])
    check("log has no payloads/args/keys", "NVDA" not in new and "rm -rf" not in new
          and c.req not in new and '"ct"' not in new)

    if "--lockout" in sys.argv:
        for _ in range(5):
            rid, body = c.build("pulse")
            body["ct"] = base64.b64encode(os.urandom(40)).decode()
            roundtrip(c, rid, "pulse", body, wait=4)
        time.sleep(1)
        check("lockout logged after 5 auth failures", log_count("LOCKOUT", start) >= 1)
        print("waiting 65 s for the rate-limit window, then testing a valid request during lockout", flush=True)
        time.sleep(65)
        rid, body = c.build("pulse")
        res = roundtrip(c, rid, "pulse", body, wait=8)
        check("valid request ignored during lockout", res is None)
        print("waiting for lockout to expire (~4 min)", flush=True)
        time.sleep(250)
        rid, body = c.build("pulse")
        res = roundtrip(c, rid, "pulse", body, wait=40)
        check("valid request works after lockout expires", bool(res and res["ok"]))

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
