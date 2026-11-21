#!/usr/bin/env python3
"""Telegram -> Bale config bridge (v3) — «Moki Bridge».

A userbot (Telethon, Scrapmoki-style StringSession login) watches EVERY
channel/group the account is a member of, detects VPN configs (links in
text incl. base64-wrapped ones, config files, QR photos), TESTS each one
(tester.py: Xray / sing-box tunnel tests, NPV + OpenVPN file tests, Iran
DNS poison check) and forwards it to a Bale channel via the Bale bot API.

Posting format: PLAIN text + Bot API ENTITIES (code + spoiler over the
config link) — Bale clients render entities; markup (HTML/Markdown) is
shown raw by Bale and is therefore never used.

Store-and-forward: items land in a SQLite outbox first; the sender loop
tests + delivers with retry/backoff (Bale retry_after honored), so
nothing is lost if the Bale API is briefly unreachable. Dedup by content
hash (7 days). Shared settings live in state.json and are controlled
from BOTH the Telegram bot and the Bale bot: pause, send mode
(all / passed-only), time window, files on/off, probe URL. Every
notable event goes to the events table (owner-visible logs).
"""
import asyncio
import hashlib
import io
import json
import os
import random
import re
import sqlite3
import sys
import time
import zipfile

import httpx

BASE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(BASE, "config.json")))
BALE_TOKEN = os.environ["BALE_TOKEN"]
BALE_API = f"https://tapi.bale.ai/bot{BALE_TOKEN}"
DB_PATH = os.path.join(BASE, "bridge.db")
STATE_PATH = os.path.join(BASE, "state.json")
SESSION_TXT = os.path.join(BASE, "session.txt")
BEST_PATH = os.path.join(BASE, "best_channels.json")
BACKFILL_MSGS = int(CFG.get("backfill_msgs", 200))
SEND_PACE = 2.0

LINK_RE = re.compile(
    r"(?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic|wireguard|snell)"
    r"://[^\s<>'\"\)\]]+",
    re.IGNORECASE,
)
FILE_EXTS = {".npv", ".npvt", ".npvs", ".hc", ".zip", ".ovpn", ".conf",
             ".json", ".txt", ".rar", ".7z", ".yaml", ".yml", ".gz"}
TEXT_FILE_EXTS = {".txt", ".json", ".conf"}
TESTABLE_EXTS = {".npv", ".npvt", ".npvs", ".ovpn"}
WINDOW_SECONDS = {"now": 600, "1h": 3600, "24h": 86400, "all": None}

db = sqlite3.connect(DB_PATH)
db.executescript("""
CREATE TABLE IF NOT EXISTS seen (
    hash TEXT PRIMARY KEY, ts INTEGER);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT, text TEXT, file_path TEXT, file_name TEXT,
    caption TEXT, ts INTEGER, sent INTEGER DEFAULT 0, tries INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT, detail TEXT);
""")
db.commit()

import tester  # noqa: E402


# ---------------- shared settings / events ----------------

def read_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def write_state(**kw):
    st = read_state()
    st.update(kw)
    with open(STATE_PATH, "w") as f:
        json.dump(st, f)


def setting(key, default):
    return read_state().get(key, default)


def log_event(kind, detail=""):
    try:
        db.execute("INSERT INTO events (ts,kind,detail) VALUES (?,?,?)",
                   (int(time.time()), kind, str(detail)[:300]))
        db.execute("DELETE FROM events WHERE id NOT IN "
                   "(SELECT id FROM events ORDER BY id DESC LIMIT 500)")
        db.commit()
    except Exception:
        pass


def content_hash(s: str) -> str:
    return hashlib.sha256(s.strip().encode()).hexdigest()


def already_seen(h: str) -> bool:
    row = db.execute("SELECT ts FROM seen WHERE hash=?", (h,)).fetchone()
    if row and time.time() - row[0] < 7 * 86400:
        return True
    db.execute("INSERT OR REPLACE INTO seen VALUES (?,?)", (h, int(time.time())))
    db.commit()
    return False


def enqueue(kind, text=None, file_path=None, file_name=None, caption=None):
    db.execute(
        "INSERT INTO outbox (kind,text,file_path,file_name,caption,ts) VALUES (?,?,?,?,?,?)",
        (kind, text, file_path, file_name, caption, int(time.time())))
    db.commit()


def meta_get(key, default=None):
    row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(key, value):
    db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))
    db.commit()


# ---------------- detection ----------------

B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/=]{24,}")


def extract_links(text: str):
    if not text:
        return []
    out = []
    for m in LINK_RE.findall(text):
        link = m.rstrip(".,;")
        low = link.lower()
        if low.startswith("hy2://"):
            link = "hysteria2://" + link[6:]
        out.append(link)
    if not out:
        import base64
        for blob in B64_BLOB_RE.findall(text):
            try:
                dec = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode(
                    "utf-8", "ignore")
            except Exception:
                continue
            out += extract_links(dec)
    return out


def within_window(msg_ts: float) -> bool:
    w = WINDOW_SECONDS.get(setting("time_window", "now"))
    if w is None:
        return True
    return (time.time() - msg_ts) <= w


# ---------------- Bale posting (entities, never markup) ----------------

def _u16len(s: str) -> int:
    return len(s.encode("utf-16-le")) // 2


def build_post(link: str, title: str, stamp: str, result_text: str):
    head = f"📡 {title} · {stamp}\n\n"
    text = head + link + "\n\n" + result_text
    off = _u16len(head)
    ln = _u16len(link)
    entities = [{"type": "code", "offset": off, "length": ln},
                {"type": "spoiler", "offset": off, "length": ln}]
    return text, entities


async def bale_post(client: httpx.AsyncClient, text: str, entities=None):
    payload = {"chat_id": CFG["bale_chat_id"], "text": text}
    if entities:
        payload["entities"] = entities
    r = await client.post(f"{BALE_API}/sendMessage", json=payload)
    data = r.json()
    if data.get("ok"):
        return True
    if entities:  # degrade to clean plain text, never raw markup
        r = await client.post(f"{BALE_API}/sendMessage", json={
            "chat_id": CFG["bale_chat_id"], "text": text})
        data = r.json()
        if data.get("ok"):
            return True
    if data.get("error_code") == 429:
        ra = (data.get("parameters") or {}).get("retry_after", 5)
        raise _RetryAfter(ra, str(data)[:160])
    raise RuntimeError(str(data)[:200])


class _RetryAfter(Exception):
    def __init__(self, seconds, msg):
        super().__init__(msg)
        self.seconds = seconds


_test_sem = asyncio.Semaphore(3)


async def process_link_item(client: httpx.AsyncClient, payload_json: str):
    d = json.loads(payload_json)
    link, title, stamp = d["link"], d["title"], d["stamp"]
    probe = setting("probe_url", tester.DEFAULT_PROBE)
    async with _test_sem:
        try:
            res = await tester.test_link(link, probe_url=probe)
        except Exception as e:
            res = {"ok": False, "error": f"tester_crash: {e}"[:60]}
    if setting("send_mode", "all") == "passed_only" and not res.get("ok"):
        log_event("skip_failed", link[:80])
        return
    text, entities = build_post(link, title, stamp, tester.format_result(res))
    await bale_post(client, text, entities)
    log_event("post_ok" if res.get("ok") else "post_fail",
              f"{title}: {link[:60]}")


async def process_file_item(client: httpx.AsyncClient, fpath, fname, caption):
    ext = os.path.splitext(fname or "")[1].lower()
    result_text = ""
    res = None
    if ext in TESTABLE_EXTS or ext == ".zip":
        try:
            with open(fpath, "rb") as fh:
                data = fh.read()
            probe = setting("probe_url", tester.DEFAULT_PROBE)
            if ext == ".zip":
                res = await _test_zip(data, probe)
            else:
                async with _test_sem:
                    res = await tester.test_file(data, fname, probe_url=probe)
        except Exception as e:
            res = {"ok": False, "error": f"tester_crash: {e}"[:60]}
    if res is not None:
        if res.get("error") == "ovpn_no_tun":
            result_text = "\n\n📁 فایل کانفیگ (بدون تست — محدودیت سرور تست)"
        else:
            result_text = "\n\n" + tester.format_result(res)
        if setting("send_mode", "all") == "passed_only" and not res.get("ok"):
            log_event("skip_failed_file", fname)
            return
    with open(fpath, "rb") as fh:
        r = await client.post(f"{BALE_API}/sendDocument", data={
            "chat_id": str(CFG["bale_chat_id"]),
            "caption": (caption or "") + result_text},
            files={"document": (fname, fh)})
    data = r.json()
    if not data.get("ok"):
        if data.get("error_code") == 429:
            ra = (data.get("parameters") or {}).get("retry_after", 5)
            raise _RetryAfter(ra, str(data)[:160])
        raise RuntimeError(str(data)[:200])
    log_event("post_file", fname)


async def _test_zip(data: bytes, probe):
    """If a zip carries an npv/ovpn inside, test that; else untestable."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        for name in zf.namelist():
            ext = os.path.splitext(name)[1].lower()
            if ext in TESTABLE_EXTS:
                inner = zf.read(name)
                async with _test_sem:
                    return await tester.test_file(inner, name, probe_url=probe)
    except Exception:
        pass
    return {"ok": False, "error": "npv_parse", "note": "zip_without_testable"}


async def bale_send_loop():
    async with httpx.AsyncClient(timeout=90) as client:
        while True:
            if setting("paused", False):
                await asyncio.sleep(3)
                continue
            row = db.execute(
                "SELECT id,kind,text,file_path,file_name,caption,tries FROM outbox "
                "WHERE sent=0 ORDER BY id LIMIT 1").fetchone()
            if not row:
                await asyncio.sleep(2)
                continue
            oid, kind, text, fpath, fname, caption, tries = row
            try:
                if kind == "link":
                    await process_link_item(client, text)
                elif kind == "file":
                    await process_file_item(client, fpath, fname, caption)
                else:
                    await bale_post(client, text)
                db.execute("UPDATE outbox SET sent=1 WHERE id=?", (oid,))
                db.commit()
                if fpath:
                    try:
                        os.remove(fpath)
                    except OSError:
                        pass
                await asyncio.sleep(SEND_PACE)
            except _RetryAfter as e:
                print(f"[bale] 429 — wait {e.seconds}s", flush=True)
                await asyncio.sleep(e.seconds + 1)
            except Exception as e:
                db.execute("UPDATE outbox SET tries=tries+1 WHERE id=?", (oid,))
                db.commit()
                wait = min(300, 5 * (2 ** min(tries, 6)))
                print(f"[bale] send failed ({e}); retry in {wait}s", flush=True)
                log_event("send_error", str(e)[:120])
                await asyncio.sleep(wait)


# ---------------- Telegram side ----------------

async def qr_links_from_photo(message):
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as qr_decode
    except Exception:
        return []
    try:
        path = await message.download_media(file=os.path.join(BASE, "tmp_qr"))
        found = []
        for sym in qr_decode(Image.open(path)):
            found += extract_links(sym.data.decode("utf-8", "ignore"))
        os.remove(path)
        return found
    except Exception:
        return []


async def handle_message(msg, chat):
    if not within_window(msg.date.timestamp()):
        return
    title = getattr(chat, "title", "?") or "?"
    stamp = msg.date.strftime("%H:%M")
    links = extract_links(msg.message or "")
    if msg.photo:
        links += await qr_links_from_photo(msg)
    for link in links:
        if already_seen(content_hash(link)):
            continue
        enqueue("link", text=json.dumps(
            {"link": link, "title": title, "stamp": stamp}, ensure_ascii=False))
    if msg.document and setting("files_enabled", True):
        name = None
        for a in msg.document.attributes:
            name = getattr(a, "file_name", None) or name
        ext = os.path.splitext(name or "")[1].lower()
        mime = msg.document.mime_type or ""
        if ext in FILE_EXTS or "zip" in mime:
            if msg.document.size and msg.document.size > 25 * 1024 * 1024:
                return
            path = await msg.download_media(file=os.path.join(BASE, "files"))
            with open(path, "rb") as fh:
                raw = fh.read()
            if already_seen(content_hash(raw.hex())):
                os.remove(path)
                return
            if ext in TEXT_FILE_EXTS and len(raw) < 512 * 1024:
                for link in extract_links(raw.decode("utf-8", "ignore")):
                    if already_seen(content_hash(link)):
                        continue
                    enqueue("link", text=json.dumps(
                        {"link": link, "title": title, "stamp": stamp},
                        ensure_ascii=False))
            enqueue("file", file_path=path, file_name=name or f"file{ext or '.bin'}",
                    caption=f"📁 فایل کانفیگ\n📡 {title} · {stamp}")


def make_client():
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    session = ""
    if os.path.exists(SESSION_TXT):
        session = open(SESSION_TXT).read().strip()
    if session:
        return TelegramClient(StringSession(session), CFG["tg_api_id"],
                              CFG["tg_api_hash"], device_model="Desktop",
                              connection_retries=5, timeout=20)
    return TelegramClient(os.path.join(BASE, "tg_session"),
                          CFG["tg_api_id"], CFG["tg_api_hash"],
                          device_model="Desktop", connection_retries=5, timeout=20)


async def backfill(client):
    dialogs = await client.get_dialogs()
    for d in dialogs:
        chat = d.entity
        if not (getattr(chat, "broadcast", False) or getattr(chat, "megagroup", False)):
            continue
        key = f"backfill:{chat.id}"
        if meta_get(key):
            continue
        try:
            async for msg in client.iter_messages(chat, limit=BACKFILL_MSGS):
                try:
                    await handle_message(msg, chat)
                except Exception as e:
                    print(f"[bf] msg error in {getattr(chat, 'title', '?')}: {e}",
                          flush=True)
            meta_set(key, int(time.time()))
            print(f"[bf] done: {getattr(chat, 'title', '?')}", flush=True)
        except Exception as e:
            print(f"[bf] channel error {getattr(chat, 'title', '?')}: {e}", flush=True)
        await asyncio.sleep(3)


async def do_join_best(client):
    from telethon.tl.functions.channels import JoinChannelRequest
    from telethon.errors import FloodWaitError
    if not os.path.exists(BEST_PATH):
        log_event("join_error", "best_channels.json missing")
        return
    best = json.load(open(BEST_PATH))
    have = set()
    async for d in client.iter_dialogs():
        un = getattr(d.entity, "username", None)
        if un:
            have.add(un.lower())
    joined = already = failed = 0
    for item in best:
        uname = item.lstrip("@").lower()
        if uname in have:
            already += 1
            continue
        try:
            await client(JoinChannelRequest(uname))
            joined += 1
            log_event("joined", uname)
        except FloodWaitError as e:
            log_event("join_floodwait", f"{e.seconds}s")
            break
        except Exception as e:
            failed += 1
            log_event("join_failed", f"{uname}: {str(e)[:60]}")
        await asyncio.sleep(random.uniform(20, 40))
    log_event("join_summary", f"joined={joined} already={already} failed={failed}")
    write_state(want_backfill=True)


async def flags_task(client):
    """Poll state.json for work requested from the bots: backfill, join."""
    while True:
        try:
            st = read_state()
            if st.get("want_join"):
                write_state(want_join=False)
                await do_join_best(client)
            if st.get("want_backfill"):
                write_state(want_backfill=False)
                db.execute("DELETE FROM meta WHERE key LIKE 'backfill:%'")
                db.commit()
                await backfill(client)
        except Exception as e:
            print(f"[flags] error: {e}", flush=True)
        await asyncio.sleep(15)


async def watcher_once():
    from telethon import events
    client = make_client()
    await client.connect()
    if not await client.is_user_authorized():
        print("[tg] NOT authorized — waiting for login via control bot", flush=True)
        await asyncio.sleep(30)
        await client.disconnect()
        return
    me = await client.get_me()
    print(f"[tg] logged in as {me.id} (@{me.username})", flush=True)
    log_event("tg_login", f"{me.id}")

    if not meta_get("backfill:initial"):
        write_state(want_backfill=True)
    asyncio.create_task(flags_task(client))

    @client.on(events.NewMessage())
    async def handler(event):
        try:
            if setting("paused", False):
                return
            chat = await event.get_chat()
            if not (getattr(chat, "broadcast", False) or getattr(chat, "megagroup", False)):
                return
            await handle_message(event.message, chat)
        except Exception as e:
            print(f"[tg] handler error: {e}", flush=True)

    print("[tg] watcher running (all memberships)", flush=True)
    await client.run_until_disconnected()
    print("[tg] disconnected", flush=True)


async def watcher_supervisor():
    backoff = 5
    while True:
        try:
            await watcher_once()
            backoff = 5
        except Exception as e:
            print(f"[tg] watcher crashed: {e}; reconnect in {backoff}s", flush=True)
            log_event("watcher_crash", str(e)[:120])
            await asyncio.sleep(backoff)
            backoff = min(120, backoff * 2)


async def main():
    os.makedirs(os.path.join(BASE, "files"), exist_ok=True)
    log_event("bridge_start", "")
    await asyncio.gather(bale_send_loop(), watcher_supervisor())


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        samples = [
            "کانفیگ جدید vless://abc@1.2.3.4:443?security=reality#x بگیرید",
            "سلام به همه",
            "trojan://pass@host:443#t و vmess://eyJ2IjoiMiJ9",
            "hy2://p@h:443 و یه فایل npv ضمیمه شد",
        ]
        for s in samples:
            print(extract_links(s))
        sys.exit(0)
    asyncio.run(main())
