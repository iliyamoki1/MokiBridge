#!/usr/bin/env python3
"""Rubika destination setup helper: verifies the bot token (getMe) and
lists recent updates so the channel's chat_id can be found after the
bot is added as a channel admin. Reads RUBIKA_TOKEN from rubika.env;
when a channel chat_id is discovered it is printed (and with --save,
written back into rubika.env as RUBIKA_CHAT_ID)."""
import asyncio
import json
import os
import sys

import httpx

BASE = os.path.dirname(os.path.abspath(__file__))
env = {}
for line in open(os.path.join(BASE, "rubika.env")):
    line = line.strip()
    if "=" in line and not line.startswith("#"):
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
API = f"https://botapi.rubika.ir/v3/{env['RUBIKA_TOKEN']}"


async def main():
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{API}/getMe", json={})
        print("getMe:", r.status_code, r.text[:300])
        r = await c.post(f"{API}/getUpdates", json={})
        d = r.json()
        print("getUpdates status:", d.get("status"))
        chats = {}
        for upd in d.get("data", {}).get("updates", []) or []:
            for key in ("updated_message", "new_message", "removed_message"):
                msg = upd.get(key) or {}
                cid = msg.get("chat_id")
                if cid:
                    chats[cid] = msg.get("chat_type") or upd.get("type", "?")
        for cid, ctype in chats.items():
            print("CHAT:", cid, ctype)
        if "--save" in sys.argv and len(chats) == 1:
            cid = next(iter(chats))
            with open(os.path.join(BASE, "rubika.env"), "a") as f:
                f.write(f"RUBIKA_CHAT_ID={cid}\n")
            print("saved RUBIKA_CHAT_ID =", cid)


asyncio.run(main())
