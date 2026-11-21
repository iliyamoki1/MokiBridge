#!/usr/bin/env python3
"""Telegram control bot for the Telegram -> Bale config bridge.

Admin-only (Iliya). Mirrors Scrapmoki's account-login method exactly:
Telethon client over an empty StringSession with a Desktop device
profile; phone -> code -> optional 2FA password. The login only ADDS a
new session to the account — it never reads, terminates or resets any
existing session/authorization, and never logs anything out. On success
the StringSession is stored server-side only (session.txt, chmod 600)
and the bridge picks it up automatically.
"""
import asyncio
import json
import os
import random
import sqlite3

from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (CallbackQuery, InlineKeyboardButton,
                           InlineKeyboardMarkup, Message)
from telethon import TelegramClient
from telethon.errors import (FloodWaitError, PasswordHashInvalidError,
                             PhoneCodeExpiredError, PhoneCodeInvalidError,
                             PhoneNumberInvalidError, SessionPasswordNeededError)
from telethon.sessions import StringSession

BASE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(BASE, "config.json")))
BOT_TOKEN = os.environ["TG_BOT_TOKEN"]
ADMIN_ID = int(os.environ.get("OWNER_TG_ID", "0"))
STATE_PATH = os.path.join(BASE, "state.json")
SESSION_TXT = os.path.join(BASE, "session.txt")
BEST_PATH = os.path.join(BASE, "best_channels.json")
DB_PATH = os.path.join(BASE, "bridge.db")

router = Router()
_pending = {}  # uid -> {client, phone, hash}


class St(StatesGroup):
    phone = State()
    code = State()
    password = State()


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


def is_admin(uid: int) -> bool:
    return uid == ADMIN_ID


REPO_URL = "https://github.com/iliyamoki1/MokiBridge"
HEADER = "🌉 <b>Moki Bridge | پل موکی</b>\n━━━━━━━━━━━━━━━\n"
PROBES = {"cloudflare": "http://cp.cloudflare.com/generate_204",
          "google": "http://www.google.com/generate_204",
          "connectivity": "http://connectivitycheck.gstatic.com/generate_204"}
WINDOWS = {"now": "از الان", "1h": "۱ ساعت اخیر", "24h": "۲۴ ساعت اخیر",
           "all": "همه"}
ABOUT = (HEADER + "<b>درباره</b>\n"
         "پل موکی کانفیگ‌های کانال‌های تلگرام رو با تست واقعی اتصال، خودکار می‌فرسته تو بله — برای روزهای قطعی و نت ملی.\n\n"
         "👨‍💻 سازنده: Moki\n🆘 پشتیبانی: @illiioiilli\n"
         f"💻 سورس پروژه: {REPO_URL}")


def main_kb():
    st = read_state()
    mode = "فقط تست‌شده‌ها ✅️" if st.get("send_mode") == "passed_only" else "همه 📤"
    win = WINDOWS.get(st.get("time_window", "now"), "از الان")
    files = "روشن ✅️" if st.get("files_enabled", True) else "خاموش ❌️"
    rows = [
        [InlineKeyboardButton(text="📲 ورود به اکانت تلگرام", callback_data="login")],
        [InlineKeyboardButton(text="📊 وضعیت پل", callback_data="status"),
         InlineKeyboardButton(text="📋 کانال‌های عضو", callback_data="channels")],
        [InlineKeyboardButton(text="⭐️ عضویت در بهترین کانال‌ها", callback_data="joinbest"),
         InlineKeyboardButton(text="🔎 اسکن سابقه کانال‌ها", callback_data="backfill")],
        [InlineKeyboardButton(text=f"🎯 حالت ارسال: {mode}", callback_data="mode")],
        [InlineKeyboardButton(text=f"🕐 بازه زمانی: {win}", callback_data="winmenu"),
         InlineKeyboardButton(text=f"📁 فایل‌ها: {files}", callback_data="files")],
        [InlineKeyboardButton(text="🧪 دامنه تست اتصال", callback_data="probemenu"),
         InlineKeyboardButton(text="📜 لاگ‌ها", callback_data="logs")],
        [InlineKeyboardButton(
            text="▶️ ادامه" if st.get("paused") else "⏸ توقف موقت",
            callback_data="resume" if st.get("paused") else "pause"),
         InlineKeyboardButton(text="ℹ️ درباره", callback_data="about")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def make_login_client() -> TelegramClient:
    """Scrapmoki's make_tg_client with an empty session: same API creds,
    same Desktop device profile. No proxy (server egress is clean)."""
    return TelegramClient(StringSession(""), CFG["tg_api_id"], CFG["tg_api_hash"],
                          device_model="Desktop", connection_retries=2, timeout=15)


def bridge_client() -> TelegramClient:
    session = ""
    if os.path.exists(SESSION_TXT):
        session = open(SESSION_TXT).read().strip()
    return TelegramClient(StringSession(session), CFG["tg_api_id"],
                          CFG["tg_api_hash"], device_model="Desktop",
                          connection_retries=2, timeout=15)


@router.message(CommandStart())
async def cmd_start(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return
    await state.clear()
    await m.answer(HEADER + "کانفیگ‌های همه کانال‌های عضوشده، با تست واقعی، می‌رن تو کانال بله.",
                   reply_markup=main_kb())


@router.callback_query(F.data == "home")
async def cb_home(c: CallbackQuery, state: FSMContext):
    if not is_admin(c.from_user.id):
        return await c.answer()
    await state.clear()
    await c.message.edit_text(HEADER + "پنل کنترل پل", reply_markup=main_kb())
    await c.answer()


# ---------------- login (Scrapmoki method) ----------------

@router.callback_query(F.data == "login")
async def cb_login(c: CallbackQuery, state: FSMContext):
    if not is_admin(c.from_user.id):
        return await c.answer()
    await state.set_state(St.phone)
    await c.message.edit_text(
        "📲 <b>ورود به اکانت</b>\n\nشماره رو با کد کشور بفرست:\n<code>+98...</code>\n\n"
        "این ورود فقط یه سشن جدید اضافه می‌کنه؛ به هیچ دیوایس یا سشن دیگه‌ای دست نمی‌زنه و چیزی رو لاگ‌اوت نمی‌کنه.")
    await c.answer()


@router.message(St.phone)
async def got_phone(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return
    phone = (m.text or "").strip().replace(" ", "")
    if phone.startswith("09"):
        phone = "+98" + phone[1:]
    wait = await m.answer("⏳ دارم کد ورود رو می‌فرستم...")
    cl = make_login_client()
    try:
        await cl.connect()
        sent = await cl.send_code_request(phone)
    except PhoneNumberInvalidError:
        await cl.disconnect()
        return await wait.edit_text("❌️ شماره اشتباهه. دوباره با «ورود به اکانت» شروع کن.")
    except FloodWaitError as e:
        await cl.disconnect()
        await state.clear()
        return await wait.edit_text(f"⏳ تلگرام گفته {e.seconds} ثانیه صبر کن، بعد دوباره تلاش کن.")
    except Exception as e:
        await cl.disconnect()
        await state.clear()
        return await wait.edit_text(f"❌️ خطا: <code>{str(e)[:120]}</code>")
    _pending[m.from_user.id] = {"client": cl, "phone": phone,
                                "hash": sent.phone_code_hash}
    await state.set_state(St.code)
    await wait.edit_text("🔐 کد ورود رو بفرست (کدی که تو تلگرام اومد):")


@router.message(St.code)
async def got_code(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return
    p = _pending.get(m.from_user.id)
    code = (m.text or "").strip().replace(" ", "")
    try:
        await m.delete()
    except Exception:
        pass
    if not p:
        await state.clear()
        return await m.answer("سشن ورود تموم شده. دوباره شروع کن.", reply_markup=main_kb())
    try:
        await p["client"].sign_in(phone=p["phone"], code=code,
                                  phone_code_hash=p["hash"])
    except SessionPasswordNeededError:
        await state.set_state(St.password)
        return await m.answer("🔑 رمز دومرحله‌ای رو بفرست:")
    except (PhoneCodeInvalidError, PhoneCodeExpiredError):
        return await m.answer("❌️ کد اشتباه یا منقضیه. کد درست رو بفرست:")
    except Exception as e:
        await state.clear()
        return await m.answer(f"❌️ خطا: <code>{str(e)[:120]}</code>", reply_markup=main_kb())
    await state.clear()
    await complete_login(m)


@router.message(St.password)
async def got_password(m: Message, state: FSMContext):
    if not is_admin(m.from_user.id):
        return
    p = _pending.get(m.from_user.id)
    pw = m.text or ""
    try:
        await m.delete()
    except Exception:
        pass
    if not p:
        await state.clear()
        return await m.answer("سشن ورود تموم شده. دوباره شروع کن.", reply_markup=main_kb())
    try:
        await p["client"].sign_in(password=pw)
    except PasswordHashInvalidError:
        return await m.answer("❌️ رمز اشتباهه. دوباره بفرست:")
    except Exception as e:
        await state.clear()
        return await m.answer(f"❌️ خطا: <code>{str(e)[:120]}</code>", reply_markup=main_kb())
    await state.clear()
    await complete_login(m)


async def complete_login(m: Message):
    p = _pending.pop(m.from_user.id, None)
    cl: TelegramClient = p["client"]
    me = await cl.get_me()
    session_str = cl.session.save()
    with open(SESSION_TXT, "w") as f:
        f.write(session_str)
    os.chmod(SESSION_TXT, 0o600)
    await cl.disconnect()
    write_state(want_backfill=True)
    await m.answer(
        f"✅️ <b>اکانت وصل شد</b>\n👤 {me.first_name or ''} (@{me.username or '—'}) · <code>{me.id}</code>\n\n"
        "پل خودکار روشن می‌شه: همه کانال‌های عضوشده رصد می‌شن و سابقه‌شون هم اسکن می‌شه.",
        reply_markup=main_kb())


# ---------------- panel actions ----------------

@router.callback_query(F.data == "status")
async def cb_status(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    db = sqlite3.connect(DB_PATH)
    pending = db.execute("SELECT COUNT(*) FROM outbox WHERE sent=0").fetchone()[0]
    sent = db.execute("SELECT COUNT(*) FROM outbox WHERE sent=1").fetchone()[0]
    seen = db.execute("SELECT COUNT(*) FROM seen").fetchone()[0]
    db.close()
    connected = os.path.exists(SESSION_TXT)
    st = read_state()
    txt = ("📊 <b>وضعیت پل</b>\n"
           f"👤 اکانت: {'وصل ✅️' if connected else 'وصل نیست ❌️'}\n"
           f"⏸ توقف: {'بله' if st.get('paused') else 'نه'}\n"
           f"📥 در صف ارسال: {pending}\n"
           f"📤 ارسال‌شده: {sent}\n"
           f"🔁 کانفیگ‌های دیده‌شده (ضدتکرار): {seen}")
    await c.message.edit_text(txt, reply_markup=main_kb())
    await c.answer()


@router.callback_query(F.data == "mode")
async def cb_mode(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    st = read_state()
    new = "all" if st.get("send_mode") == "passed_only" else "passed_only"
    write_state(send_mode=new)
    await c.message.edit_reply_markup(reply_markup=main_kb())
    await c.answer("🎯 حالت ارسال عوض شد")


@router.callback_query(F.data == "files")
async def cb_files(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    st = read_state()
    write_state(files_enabled=not st.get("files_enabled", True))
    await c.message.edit_reply_markup(reply_markup=main_kb())
    await c.answer("📁 وضعیت فایل‌ها عوض شد")


@router.callback_query(F.data == "winmenu")
async def cb_winmenu(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    rows = [[InlineKeyboardButton(text=label, callback_data=f"win:{key}")]
            for key, label in WINDOWS.items()]
    rows.append([InlineKeyboardButton(text="🔙 برگشت", callback_data="home")])
    await c.message.edit_text(HEADER + "🕐 پیام‌های کدوم بازه فرستاده بشن؟",
                              reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))
    await c.answer()


@router.callback_query(F.data.startswith("win:"))
async def cb_win(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    write_state(time_window=c.data[4:])
    await c.message.edit_text(HEADER + "پنل کنترل پل", reply_markup=main_kb())
    await c.answer("🕐 بازه زمانی ثبت شد")


@router.callback_query(F.data == "probemenu")
async def cb_probemenu(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    rows = [[InlineKeyboardButton(text=name.capitalize(), callback_data=f"probe:{name}")]
            for name in PROBES]
    rows.append([InlineKeyboardButton(text="🔙 برگشت", callback_data="home")])
    await c.message.edit_text(HEADER + "🧪 تست اتصال با کدوم دامنه انجام بشه؟",
                              reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))
    await c.answer()


@router.callback_query(F.data.startswith("probe:"))
async def cb_probe(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    write_state(probe_url=PROBES[c.data[6:]])
    await c.message.edit_text(HEADER + "پنل کنترل پل", reply_markup=main_kb())
    await c.answer("🧪 دامنه تست ثبت شد")


@router.callback_query(F.data == "logs")
async def cb_logs(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    import time as _t
    db = sqlite3.connect(DB_PATH)
    rows = db.execute("SELECT ts,kind,detail FROM events ORDER BY id DESC LIMIT 12").fetchall()
    db.close()
    lines = [f"• {_t.strftime('%H:%M', _t.localtime(ts))} — {k} {d}" for ts, k, d in rows]
    body = "\n".join(lines) or "لاگی نیست"
    await c.message.edit_text(HEADER + f"<b>لاگ‌های اخیر</b>\n{body}", reply_markup=main_kb())
    await c.answer()


@router.callback_query(F.data == "about")
async def cb_about(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    await c.message.edit_text(ABOUT, reply_markup=main_kb())
    await c.answer()


@router.callback_query(F.data == "channels")
async def cb_channels(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    if not os.path.exists(SESSION_TXT):
        await c.answer("اول اکانت رو وصل کن", show_alert=True)
        return
    await c.answer("⏳ دارم لیست می‌کنم...")
    cl = bridge_client()
    lines = []
    try:
        await cl.connect()
        async for d in cl.iter_dialogs():
            e = d.entity
            if getattr(e, "broadcast", False) or getattr(e, "megagroup", False):
                un = f"@{e.username}" if getattr(e, "username", None) else "—"
                lines.append(f"• {d.name} <code>{un}</code>")
    except Exception as e:
        lines = [f"❌️ خطا: <code>{str(e)[:120]}</code>"]
    finally:
        await cl.disconnect()
    body = "\n".join(lines[:60]) or "کانالی پیدا نشد"
    await c.message.edit_text(f"📋 <b>کانال‌ها و گروه‌های عضو ({len(lines)})</b>\n\n{body}",
                              reply_markup=main_kb())


@router.callback_query(F.data == "backfill")
async def cb_backfill(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    write_state(want_backfill=True)
    await c.answer("🔎 اسکن سابقه تو صف انجام قرار گرفت", show_alert=True)


@router.callback_query(F.data == "pause")
async def cb_pause(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    write_state(paused=True)
    await c.message.edit_reply_markup(reply_markup=main_kb())
    await c.answer("⏸ پل متوقف شد")


@router.callback_query(F.data == "resume")
async def cb_resume(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    write_state(paused=False)
    await c.message.edit_reply_markup(reply_markup=main_kb())
    await c.answer("▶️ پل ادامه می‌ده")


@router.callback_query(F.data == "joinbest")
async def cb_joinbest(c: CallbackQuery):
    if not is_admin(c.from_user.id):
        return await c.answer()
    if not os.path.exists(SESSION_TXT):
        await c.answer("اول اکانت رو وصل کن", show_alert=True)
        return
    if not os.path.exists(BEST_PATH):
        await c.answer("لیست بهترین‌ها هنوز آماده نیست", show_alert=True)
        return
    write_state(want_join=True)
    await c.answer("⭐️ عضویت شروع شد — گزارشش تو لاگ‌ها میاد", show_alert=True)


async def main():
    from aiogram.client.default import DefaultBotProperties
    bot = Bot(BOT_TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
