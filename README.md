# 🌉 Moki Bridge

**Telegram → Bale config bridge with real connection tests.**
Built for the days the internet gets cut or nationalized: a userbot watches the Telegram channels you are a member of, catches every VPN config the moment it is posted, **tests it for real**, and forwards it — with the test result — into a Bale channel, where it stays reachable on the national network.

> پل موکی: کانفیگ‌های کانال‌های تلگرام را با تست واقعی اتصال، خودکار به بله می‌فرستد — برای روزهای قطعی و نت ملی.

## What it does

- 👀 **Watches everything** — every channel/group the account is a member of, live, plus a resumable history backfill (200 messages per channel).
- 🔎 **Detects configs anywhere** — links (`vless`, `vmess`, `trojan`, `ss`, `hysteria2`, `tuic`) in plain text, inside **base64-wrapped** posts, inside text files, and in **QR photos**.
- 🧪 **Tests before posting** — every link gets a real tunnel test (Xray core, or sing-box where Xray refuses a config class), reporting: connected ✅️/❌️, ping, exit IP and country, and an **Iran-DNS poison check** (a public Iranian resolver compared against a global one). `.npv` / `.npvt` / `.npvs` (NapsternetV) and `.ovpn` (OpenVPN) files are tested too; zips are peeked for testable files inside.
- 🎯 **Owner filters** — send everything, or **only configs that passed the test**; limit by time window (from now / last hour / last 24h / all); files on/off; choose the connectivity-probe domain the tester uses.
- 📮 **Nothing is lost** — store-and-forward SQLite outbox, 7-day dedup, Bale `retry_after` honored, auto-reconnecting watcher.
- 🎛 **Two control panels, one brain** — a Telegram bot and a Bale bot share the same settings and logs: status, pause/resume, filters, probe domain, join-best-channels, backfill, event logs. Owner-only; everyone else gets silence.
- ✉️ **Clean posts** — plain text + Bot API entities (tap-to-copy `code` + `spoiler`), because Bale clients show markup tags raw. User-facing errors are one plain line — no jargon, ever.

## Architecture

```
Telegram channels ──► userbot (Telethon) ──► detector ──► SQLite outbox
                                                            │
Bale channel ◄── Bale Bot API ◄── sender ◄── tester (Xray / sing-box / OpenVPN)
                                                            ▲
Telegram bot ──┐                                            │
               ├── shared state.json (settings) ────────────┘
Bale bot ──────┘   bridge.db (outbox, dedup, event logs)
```

Login mirrors a normal Telegram Desktop session (StringSession). It never resets or touches the account's other sessions.

## Setup

```bash
git clone https://github.com/iliyamoki1/MokiBridge && cd MokiBridge
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp config.example.json config.json   # fill in your ids
```

You also need: `xray` and `sing-box` binaries in `bin/`, `openvpn`, and `libzbar` (QR decoding). Secrets live in env files only (`bale.env`, `bot.env`) — never in the repo.

Run as three systemd services: the bridge (`bridge.py`), the Telegram control bot (`tg_bot.py`), and the Bale control bot (`bale_bot.py`).

## Privacy

No personal data is in this repo: no tokens, no session strings, no server addresses. Owner IDs are read from environment variables. The only public contacts are the ones below.

## Contact

- 👨‍💻 **Moki**
- 🆘 Support: [@illiioiilli](https://t.me/illiioiilli)
- 💻 GitHub: [@iliyamoki1](https://github.com/iliyamoki1)
