#!/usr/bin/env python3
"""Bale control bot for Moki Bridge — the owner runs the WHOLE bridge
from Bale: status, pause/resume, send-mode (all / passed-only), time
window, files on/off, test probe domain, channel list, join-best,
backfill, and full logs. Owner-only (Iliya's Bale id); everyone else
gets silence. Shares state.json + bridge.db with the bridge and the
Telegram bot, so a setting changed here applies everywhere at once.
"""
import asyncio
import json
import os
import sqlite3
import time

import httpx

BASE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(BASE, "config.json")))
TOKEN = os.environ["BALE_TOKEN"]
API = f"https://tapi.bale.ai/bot{TOKEN}"
OWNER_ID = int(os.environ.get("OWNER_BALE_ID", "0"))  # the owner's Bale user id
STATE_PATH = os.path.join(BASE, "state.json")
DB_PATH = os.path.join(BASE, "bridge.db")
SESSION_TXT = os.path.join(BASE, "session.txt")
OFFSET_PATH = os.path.join(BASE, "bale_offset.txt")
REPO_URL = "https://github.com/iliyamoki1/MokiBridge"
SUPPORT = "@illiioiilli"

PROBES = {
    "probe:cloudflare": "http://cp.cloudflare.com/generate_204",
    "probe:google": "http://www.google.com/generate_204",
    "probe:connectivity": "http://connectivitycheck.gstatic.com/generate_204",
}
WINDOWS = {"win:now": ("از الان", "now"), "win:1h": ("۱ ساعت اخیر", "1h"),
           "win:24h": ("۲۴ ساعت اخیر", "24h"), "win:all": ("همه", "all")}

HEADER = "🌉 Moki Bridge | پل موکی\n━━━━━━━━━━━━━━━\n"


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


def dbq(sql, args=()):
    db = sqlite3.connect(DB_PATH)
    try:
        return db.execute(sql, args).fetchall()
    finally:
        db.close()


def panel_kb():
    st = read_state()
    mode = "فقط تست‌شده‌ها ✅️" if st.get("send_mode") == "passed_only" else "همه 📤"
    win = {"now": "از الان", "1h": "۱ ساعت اخیر", "24h": "۲۴ ساعت اخیر",
           "all": "همه"}.get(st.get("time_window", "now"), "از الان")
    files = "روشن ✅️" if st.get("files_enabled", True) else "خاموش ❌️"
    rows = [
        [{"text": "📊 وضعیت", "callback_data": "status"},
         {"text": "📜 لاگ‌ها", "callback_data": "logs"}],
        [{"text": "▶️ ادامه" if st.get("paused") else "⏸ توقف موقت",
          "callback_data": "resume" if st.get("paused") else "pause"}],
        [{"text": f"🎯 حالت ارسال: {mode}", "callback_data": "mode"}],
        [{"text": f"🕐 بازه زمانی: {win}", "callback_data": "winmenu"}],
        [{"text": f"📁 فایل‌ها: {files}", "callback_data": "files"}],
        [{"text": "🧪 دامنه تست اتصال", "callback_data": "probemenu"}],
        [{"text": "⭐️ عضویت در بهترین کانال‌ها", "callback_data": "join"},
         {"text": "🔎 اسکن سابقه", "callback_data": "backfill"}],
        [{"text": "ℹ️ درباره", "callback_data": "about"}],
    ]
    return {"inline_keyboard": rows}


def status_text():
    pending = dbq("SELECT COUNT(*) FROM outbox WHERE sent=0")[0][0]
    sent = dbq("SELECT COUNT(*) FROM outbox WHERE sent=1")[0][0]
    seen = dbq("SELECT COUNT(*) FROM seen")[0][0]
    st = read_state()
    return (HEADER + "وضعیت پل\n"
            f"👤 اکانت تلگرام: {'وصل ✅️' if os.path.exists(SESSION_TXT) else 'وصل نیست ❌️'}\n"
            f"⏸ توقف: {'بله' if st.get('paused') else 'نه'}\n"
            f"🎯 حالت ارسال: {'فقط تست‌شده‌ها' if st.get('send_mode') == 'passed_only' else 'همه'}\n"
            f"📥 در صف: {pending} · 📤 ارسال‌شده: {sent} · 🔁 دیده‌شده: {seen}\n"
            f"🧪 دامنه تست: {st.get('probe_url', 'http://cp.cloudflare.com/generate_204')}")


def logs_text():
    rows = dbq("SELECT ts,kind,detail FROM events ORDER BY id DESC LIMIT 12")
    if not rows:
        return HEADER + "📜 لاگی نیست"
    lines = []
    for ts, kind, detail in rows:
        t = time.strftime("%H:%M", time.localtime(ts))
        lines.append(f"• {t} — {kind} {detail}")
    return HEADER + "لاگ‌های اخیر\n" + "\n".join(lines)


ABOUT = (HEADER + "درباره\n"
         "پل موکی کانفیگ‌های کانال‌های تلگرام رو با تست واقعی اتصال، خودکار می‌فرسته تو بله — برای روزهای قطعی و نت ملی.\n\n"
         f"👨‍💻 سازنده: Moki\n🆘 پشتیبانی: {SUPPORT}\n💻 سورس پروژه: {REPO_URL}")


async def api(client, method, **kw):
    r = await client.post(f"{API}/{method}", json=kw)
    return r.json()


async def send_panel(client, chat_id, text=None, kb=True):
    return await api(client, "sendMessage", chat_id=chat_id,
                     text=text or (HEADER + "پنل کنترل پل — همه‌چیز از همینجا:"),
                                          reply_markup=panel_kb() if kb else None)


async def edit_panel(client, chat_id, msg_id, text):
    return await api(client, "editMessageText", chat_id=chat_id,
                     message_id=msg_id, text=text,                      reply_markup=panel_kb())


_custom_probe_wait = set()


async def handle_message(client, msg):
    frm = (msg.get("from") or {}).get("id")
    if frm != OWNER_ID:
        return
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()
    if chat_id in _custom_probe_wait and text.startswith("http"):
        _custom_probe_wait.discard(chat_id)
        write_state(probe_url=text)
        await api(client, "sendMessage", chat_id=chat_id,
                  text=f"🧪 دامنه تست عوض شد:\n{text}",
                  )
        await send_panel(client, chat_id)
        return
    if text in ("/start", "/panel", "پنل"):
        await send_panel(client, chat_id)


async def handle_callback(client, cb):
    frm = (cb.get("from") or {}).get("id")
    if frm != OWNER_ID:
        return
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    msg_id = msg.get("message_id")
    await api(client, "answerCallbackQuery", callback_query_id=cb["id"])
    st = read_state()
    if data == "status":
        await edit_panel(client, chat_id, msg_id, status_text())
    elif data == "logs":
        await edit_panel(client, chat_id, msg_id, logs_text())
    elif data == "about":
        await edit_panel(client, chat_id, msg_id, ABOUT)
    elif data == "pause":
        write_state(paused=True)
        await edit_panel(client, chat_id, msg_id, HEADER + "⏸ پل متوقف شد")
    elif data == "resume":
        write_state(paused=False)
        await edit_panel(client, chat_id, msg_id, HEADER + "▶️ پل ادامه می‌ده")
    elif data == "mode":
        new = "all" if st.get("send_mode") == "passed_only" else "passed_only"
        write_state(send_mode=new)
        label = "فقط کانفیگ‌های تست‌شده ✅️" if new == "passed_only" else "همه کانفیگ‌ها 📤"
        await edit_panel(client, chat_id, msg_id, HEADER + f"🎯 حالت ارسال: {label}")
    elif data == "files":
        write_state(files_enabled=not st.get("files_enabled", True))
        await edit_panel(client, chat_id, msg_id, status_text())
    elif data == "winmenu":
        kb = {"inline_keyboard": [[{"text": label, "callback_data": key}]
                                   for key, (label, _v) in WINDOWS.items()] +
              [[{"text": "🔙 برگشت", "callback_data": "home"}]]}
        await api(client, "editMessageText", chat_id=chat_id, message_id=msg_id,
                  text=HEADER + "🕐 پیام‌های کدوم بازه فرستاده بشن؟",
                  reply_markup=kb)
    elif data in WINDOWS:
        label, val = WINDOWS[data]
        write_state(time_window=val)
        await edit_panel(client, chat_id, msg_id, HEADER + f"🕐 بازه زمانی: {label}")
    elif data == "probemenu":
        kb = {"inline_keyboard": [
            [{"text": "Cloudflare", "callback_data": "probe:cloudflare"}],
            [{"text": "Google", "callback_data": "probe:google"}],
            [{"text": "Google Connectivity", "callback_data": "probe:connectivity"}],
            [{"text": "✏️ دامنه دلخواه", "callback_data": "probe:custom"}],
            [{"text": "🔙 برگشت", "callback_data": "home"}]]}
        await api(client, "editMessageText", chat_id=chat_id, message_id=msg_id,
                  text=HEADER + "🧪 تست اتصال با کدوم دامنه انجام بشه؟",
                  reply_markup=kb)
    elif data in PROBES:
        write_state(probe_url=PROBES[data])
        await edit_panel(client, chat_id, msg_id,
                         HEADER + f"🧪 دامنه تست:\n{PROBES[data]}")
    elif data == "probe:custom":
        _custom_probe_wait.add(chat_id)
        await api(client, "sendMessage", chat_id=chat_id,
                  text="✏️ آدرس کامل دامنه تست رو بفرست (با http:// یا https://):")
    elif data == "join":
        write_state(want_join=True)
        await api(client, "sendMessage", chat_id=chat_id,
                  text="⭐️ عضویت در بهترین کانال‌ها شروع شد — گزارشش تو لاگ‌ها میاد")
    elif data == "backfill":
        write_state(want_backfill=True)
        await api(client, "sendMessage", chat_id=chat_id,
                  text="🔎 اسکن سابقه کانال‌ها تو صف انجام قرار گرفت")
    elif data == "home":
        await edit_panel(client, chat_id, msg_id,
                         HEADER + "پنل کنترل پل — همه‌چیز از همینجا:")


async def main():
    offset = 0
    if os.path.exists(OFFSET_PATH):
        try:
            offset = int(open(OFFSET_PATH).read().strip() or 0)
        except Exception:
            offset = 0
    async with httpx.AsyncClient(timeout=60) as client:
        print("[bale-bot] polling started", flush=True)
        while True:
            try:
                r = await client.post(f"{API}/getUpdates", json={
                    "offset": offset, "timeout": 30})
                data = r.json()
                for upd in data.get("result", []):
                    offset = upd["update_id"] + 1
                    with open(OFFSET_PATH, "w") as f:
                        f.write(str(offset))
                    try:
                        if "message" in upd:
                            await handle_message(client, upd["message"])
                        elif "callback_query" in upd:
                            await handle_callback(client, upd["callback_query"])
                    except Exception as e:
                        print(f"[bale-bot] handler error: {e}", flush=True)
            except Exception as e:
                print(f"[bale-bot] poll error: {e}", flush=True)
                await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
