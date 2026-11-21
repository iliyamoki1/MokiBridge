#!/usr/bin/env python3
"""Moki Bridge — in-Iran poster (emergency relay).

WHY: the main bridge lives in Germany. During a national-internet cut,
Iran severs international transit, so the Germany server cannot reach
Bale's API (tapi.bale.ai) at all — while Bale itself keeps working
INSIDE Iran. This tiny poster runs on any host INSIDE Iran's national
network, holds a synced stockpile of already-tested configs, and keeps
dripping them into the channel for the whole outage.

Zero dependencies (Python 3 stdlib only) so it runs anywhere: an
Iranian VPS/PaaS, a home PC, a Raspberry Pi.

SETUP
  BALE_TOKEN=...  BALE_CHAT_ID=...  python3 poster.py
  Optional: PACE=300 (seconds between posts during drip mode),
            DRY_RUN=1 (print instead of posting).

FILES (same directory)
  stockpile.jsonl   — synced from the main bridge (one JSON per line:
                      {"type":"text","text":...,"entities":[...],"h":..}
                      or {"type":"file","file":"name","caption":...})
  stockpile_files/  — the files referenced by file entries
  posted.txt        — hashes already posted (dedup, survives restarts)

Sync stockpile.jsonl + stockpile_files/ from the main server whenever
the international link is up (rsync/scp); the poster does the rest.
"""
import hashlib
import json
import os
import time
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = os.environ["BALE_TOKEN"]
CHAT = os.environ["BALE_CHAT_ID"]
PACE = int(os.environ.get("PACE", "300"))
DRY = os.environ.get("DRY_RUN") == "1"
API = f"https://tapi.bale.ai/bot{TOKEN}"
STOCK = os.path.join(HERE, "stockpile.jsonl")
POSTED = os.path.join(HERE, "posted.txt")


def posted_set():
    try:
        return set(open(POSTED).read().split())
    except Exception:
        return set()


def mark_posted(h):
    with open(POSTED, "a") as f:
        f.write(h + "\n")


def api_json(method, payload):
    req = urllib.request.Request(
        f"{API}/{method}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def api_document(path, caption):
    boundary = "----mokiposter" + uuid.uuid4().hex
    body = b""
    for name, val in (("chat_id", str(CHAT)), ("caption", caption)):
        body += (f"--{boundary}\r\nContent-Disposition: form-data; "
                 f"name=\"{name}\"\r\n\r\n{val}\r\n").encode()
    fname = os.path.basename(path)
    body += (f"--{boundary}\r\nContent-Disposition: form-data; "
             f"name=\"document\"; filename=\"{fname}\"\r\n"
             "Content-Type: application/octet-stream\r\n\r\n").encode()
    body += open(path, "rb").read() + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        f"{API}/sendDocument", data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read())


def entry_hash(e):
    if e.get("h"):
        return e["h"]
    key = e.get("text") or e.get("caption") or e.get("file", "")
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def main():
    print(f"[poster] up — chat {CHAT}, pace {PACE}s, dry={DRY}", flush=True)
    backoff = 30
    while True:
        try:
            done = posted_set()
            entries = []
            if os.path.exists(STOCK):
                for line in open(STOCK):
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            pass
            fresh = [e for e in entries if entry_hash(e) not in done]
            if not fresh:
                time.sleep(60)
                continue
            e = fresh[0]
            h = entry_hash(e)
            if DRY:
                print(f"[poster] DRY would post {e.get('type')} {h}: "
                      f"{(e.get('text') or e.get('caption') or '')[:60]}",
                      flush=True)
                mark_posted(h)
                continue
            if e.get("type") == "file":
                path = os.path.join(HERE, "stockpile_files", e["file"])
                if not os.path.exists(path):
                    mark_posted(h)  # file missing — skip, never crash
                    continue
                d = api_document(path, e.get("caption", ""))
            else:
                payload = {"chat_id": CHAT, "text": e.get("text", "")}
                if e.get("entities"):
                    payload["entities"] = e["entities"]
                d = api_json("sendMessage", payload)
            if d.get("ok"):
                mark_posted(h)
                backoff = 30
                print(f"[poster] posted {h}", flush=True)
                time.sleep(PACE)
            else:
                ra = ((d.get("parameters") or {}).get("retry_after")
                      if d.get("error_code") == 429 else None)
                print(f"[poster] api: {str(d)[:120]}", flush=True)
                time.sleep(ra + 1 if ra else backoff)
                backoff = min(600, backoff * 2)
        except Exception as ex:
            print(f"[poster] error: {ex} — retry in {backoff}s", flush=True)
            time.sleep(backoff)
            backoff = min(600, backoff * 2)


if __name__ == "__main__":
    main()
