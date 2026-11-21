#!/usr/bin/env python3
"""Real tunnel test for a single proxy config link.

Core choice: vless/vmess/trojan/ss -> Xray core (native interop, incl. Reality);
hysteria2/tuic -> sing-box. test_link(link) -> dict:
  {ok, proto, endpoint, ping_ms, tunnel_ms, exit_ip, exit_country,
   exit_country_code, exit_isp, iran_dns, error}
iran_dns: "ok" | "poisoned" | "timeout" | "ip" (host is already an IP) | "unknown"
CLI: python3 tester.py '<link>'  -> prints the result as JSON + formatted block.
"""
import asyncio
import base64
import json
import os
import random
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

BASE = os.path.dirname(os.path.abspath(__file__))
SINGBOX = os.path.join(BASE, "bin", "sing-box")
XRAY = os.path.join(BASE, "bin", "xray")
IRAN_RESOLVER = "217.66.203.211"
GLOBAL_RESOLVER = "8.8.8.8"
POISON_IPS = {"10.10.10.10", "10.10.10.11"}


def _b64(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _q(params, key, default=""):
    v = params.get(key, [default])
    return v[0] if v else default


def parse_spec(link: str):
    """Normalize any supported link into a spec dict (or None)."""
    link = link.strip()
    low = link.lower()
    sp = {"proto": "?", "host": None, "port": None, "security": "", "sni": "",
          "fp": "", "pbk": "", "sid": "", "insecure": False, "transport": "tcp",
          "ws_path": "/", "ws_host": "", "grpc_service": "", "flow": "",
          "uuid": "", "password": "", "method": "", "alter_id": 0, "cipher": "auto",
          "congestion": "bbr"}
    try:
        if low.startswith("vless://"):
            u = urllib.parse.urlparse(link)
            p = urllib.parse.parse_qs(u.query)
            sp.update(proto="vless", host=u.hostname, port=u.port,
                      uuid=urllib.parse.unquote(u.username or ""),
                      security=_q(p, "security").lower(), sni=_q(p, "sni"),
                      fp=_q(p, "fp"), pbk=_q(p, "pbk"), sid=_q(p, "sid"),
                      insecure=_q(p, "insecure", _q(p, "allowInsecure")) in ("1", "true"),
                      transport=_q(p, "type", "tcp").lower(), ws_path=_q(p, "path", "/"),
                      ws_host=_q(p, "host"), grpc_service=_q(p, "serviceName", _q(p, "path")),
                      flow=_q(p, "flow"))
            return sp
        if low.startswith("vmess://"):
            d = json.loads(_b64(link[8:].split("#")[0]))
            sp.update(proto="vmess", host=d["add"], port=int(d["port"]),
                      uuid=d["id"], alter_id=int(d.get("aid") or 0),
                      cipher=d.get("scy") or "auto",
                      security="tls" if (d.get("tls") or "").lower() == "tls" else "",
                      sni=d.get("sni") or "", transport=(d.get("net") or "tcp").lower(),
                      ws_path=d.get("path") or "/", ws_host=d.get("host") or "",
                      grpc_service=d.get("path") or "")
            return sp
        if low.startswith("trojan://"):
            u = urllib.parse.urlparse(link)
            p = urllib.parse.parse_qs(u.query)
            sp.update(proto="trojan", host=u.hostname, port=u.port,
                      password=urllib.parse.unquote(u.username or ""),
                      security=_q(p, "security", "tls").lower() or "tls", sni=_q(p, "sni"),
                      fp=_q(p, "fp"), pbk=_q(p, "pbk"), sid=_q(p, "sid"),
                      insecure=_q(p, "insecure", _q(p, "allowInsecure")) in ("1", "true"),
                      transport=_q(p, "type", "tcp").lower(), ws_path=_q(p, "path", "/"),
                      ws_host=_q(p, "host"), grpc_service=_q(p, "serviceName", _q(p, "path")))
            return sp
        if low.startswith("ss://"):
            rest = link[5:].split("#")[0]
            if "@" in rest:
                userinfo, hostport = rest.rsplit("@", 1)
                if ":" in userinfo and "%" not in userinfo:
                    method, password = userinfo.split(":", 1)
                    password = urllib.parse.unquote(password)
                else:
                    dec = _b64(urllib.parse.unquote(userinfo)).decode()
                    method, password = dec.split(":", 1)
                host = hostport.rsplit(":", 1)[0].strip("[]")
                port = int(hostport.rsplit(":", 1)[1].split("?")[0].split("/")[0])
            else:
                dec = _b64(rest.split("?")[0]).decode()
                creds, hostport = dec.rsplit("@", 1)
                method, password = creds.split(":", 1)
                host = hostport.rsplit(":", 1)[0].strip("[]")
                port = int(hostport.rsplit(":", 1)[1])
            sp.update(proto="ss", host=host, port=port, method=method, password=password)
            return sp
        if low.startswith(("hysteria2://", "hy2://")):
            u = urllib.parse.urlparse(link)
            p = urllib.parse.parse_qs(u.query)
            sp.update(proto="hysteria2", host=u.hostname, port=u.port,
                      password=urllib.parse.unquote(u.username or ""),
                      security="tls", sni=_q(p, "sni"),
                      insecure=_q(p, "insecure") in ("1", "true"))
            return sp
        if low.startswith("tuic://"):
            u = urllib.parse.urlparse(link)
            p = urllib.parse.parse_qs(u.query)
            sp.update(proto="tuic", host=u.hostname, port=u.port,
                      uuid=u.username or "",
                      password=urllib.parse.unquote(u.password or ""),
                      security="tls", sni=_q(p, "sni"),
                      insecure=_q(p, "insecure") in ("1", "true"),
                      congestion=_q(p, "congestion_control", "bbr"))
            return sp
    except Exception:
        return None
    return None


# ---------------- sing-box outbound (all protos) ----------------

def _sb_tls(sp, alpn=None):
    if sp["security"] not in ("tls", "reality") and sp["proto"] not in ("hysteria2", "tuic", "trojan"):
        return None
    tls = {"enabled": True, "server_name": sp["sni"] or sp["host"],
           "insecure": sp["insecure"]}
    if sp["fp"]:
        tls["utls"] = {"enabled": True, "fingerprint": sp["fp"]}
    if sp["security"] == "reality":
        tls["reality"] = {"enabled": True, "public_key": sp["pbk"],
                          "short_id": sp["sid"]}
    if alpn:
        tls["alpn"] = alpn
    return tls


def _sb_transport(sp):
    t = sp["transport"]
    if t == "ws":
        tr = {"type": "ws", "path": sp["ws_path"]}
        if sp["ws_host"]:
            tr["headers"] = {"Host": sp["ws_host"]}
        return tr
    if t == "grpc":
        return {"type": "grpc", "service_name": sp["grpc_service"]}
    if t == "http":
        tr = {"type": "http", "path": sp["ws_path"]}
        if sp["ws_host"]:
            tr["host"] = [sp["ws_host"]]
        return tr
    return None


def build_singbox_outbound(sp):
    p = sp["proto"]
    base = {"server": sp["host"], "server_port": sp["port"]}
    if p == "hysteria2":
        return {"type": "hysteria2", **base, "password": sp["password"],
                "tls": _sb_tls(sp, alpn=["h3"])}
    if p == "tuic":
        return {"type": "tuic", **base, "uuid": sp["uuid"],
                "password": sp["password"],
                "congestion_control": sp["congestion"],
                "tls": _sb_tls(sp, alpn=["h3"])}
    if p == "vless":
        ob = {"type": "vless", **base, "uuid": sp["uuid"]}
        if sp["flow"]:
            ob["flow"] = sp["flow"]
    elif p == "vmess":
        ob = {"type": "vmess", **base, "uuid": sp["uuid"],
              "alter_id": sp["alter_id"], "security": sp["cipher"]}
    elif p == "trojan":
        ob = {"type": "trojan", **base, "password": sp["password"]}
    elif p == "ss":
        return {"type": "shadowsocks", **base, "method": sp["method"],
                "password": sp["password"]}
    else:
        return None
    tls = _sb_tls(sp)
    if tls:
        ob["tls"] = tls
    tr = _sb_transport(sp)
    if tr:
        ob["transport"] = tr
    return ob


def use_singbox(sp) -> bool:
    """Xray 26 refuses VLESS/VMess/Trojan with security=none to public
    servers; sing-box has no such rule. Reality goes to Xray (sing-box's
    Reality client fails against Xray 26 servers)."""
    if sp["proto"] in ("hysteria2", "tuic"):
        return True
    if sp["security"] == "reality":
        return False
    if sp["security"] in ("", "none"):
        return True
    return False


# ---------------- xray outbound (vless / vmess / trojan / ss) ----------------

def _stream(sp):
    ss = {"network": sp["transport"] if sp["transport"] in ("tcp", "ws", "grpc", "http") else "tcp",
          "security": sp["security"] if sp["security"] in ("tls", "reality") else "none"}
    if ss["security"] == "tls":
        ss["tlsSettings"] = {"serverName": sp["sni"] or sp["host"],
                             "allowInsecure": sp["insecure"],
                             "fingerprint": sp["fp"] or "chrome"}
    elif ss["security"] == "reality":
        ss["realitySettings"] = {"serverName": sp["sni"] or sp["host"],
                                 "fingerprint": sp["fp"] or "chrome",
                                 "publicKey": sp["pbk"], "shortId": sp["sid"],
                                 "spiderX": "/"}
    if ss["network"] == "ws":
        ws = {"path": sp["ws_path"]}
        if sp["ws_host"]:
            ws["headers"] = {"Host": sp["ws_host"]}
        ss["wsSettings"] = ws
    elif ss["network"] == "grpc":
        ss["grpcSettings"] = {"serviceName": sp["grpc_service"], "multiMode": False}
    elif ss["network"] == "http":
        hs = {"path": sp["ws_path"]}
        if sp["ws_host"]:
            hs["host"] = [sp["ws_host"]]
        ss["httpSettings"] = hs
    return ss


def build_xray_outbound(sp):
    p = sp["proto"]
    if p == "vless":
        user = {"id": sp["uuid"], "encryption": "none"}
        if sp["flow"]:
            user["flow"] = sp["flow"]
        return {"protocol": "vless",
                "settings": {"vnext": [{"address": sp["host"], "port": sp["port"],
                                        "users": [user]}]},
                "streamSettings": _stream(sp)}
    if p == "vmess":
        return {"protocol": "vmess",
                "settings": {"vnext": [{"address": sp["host"], "port": sp["port"],
                                        "users": [{"id": sp["uuid"],
                                                   "alterId": sp["alter_id"],
                                                   "security": sp["cipher"]}]}]},
                "streamSettings": _stream(sp)}
    if p == "trojan":
        return {"protocol": "trojan",
                "settings": {"servers": [{"address": sp["host"], "port": sp["port"],
                                          "password": sp["password"]}]},
                "streamSettings": _stream(sp)}
    if p == "ss":
        return {"protocol": "shadowsocks",
                "settings": {"servers": [{"address": sp["host"], "port": sp["port"],
                                          "method": sp["method"],
                                          "password": sp["password"]}]},
                "streamSettings": {"network": "tcp", "security": "none"}}
    return None


# ---------------- network probes ----------------

def _dns_a(host: str, resolver: str, timeout=3.0):
    tid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(x)]) + x.encode() for x in host.split(".")) + b"\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (resolver, 53))
            data, _ = s.recvfrom(4096)
    except Exception:
        return None
    try:
        ancount = struct.unpack(">H", data[6:8])[0]
        off = 12
        while data[off] != 0:
            off += data[off] + 1
        off += 5
        ips = set()
        for _ in range(ancount):
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while data[off] != 0:
                    off += data[off] + 1
                off += 1
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 1 and rdlen == 4:
                ips.add(socket.inet_ntoa(data[off:off + 4]))
            off += rdlen
        return ips
    except Exception:
        return set()


def iran_dns_status(host: str) -> str:
    try:
        socket.inet_aton(host)
        return "ip"
    except Exception:
        pass
    iran = _dns_a(host, IRAN_RESOLVER)
    if iran is None:
        return "timeout"
    if iran & POISON_IPS:
        return "poisoned"
    glob = _dns_a(host, GLOBAL_RESOLVER)
    if glob and iran and not (iran & glob):
        return "poisoned"
    if iran:
        return "ok"
    return "unknown"


def _tcp_ping(host: str, port: int, timeout=4.0):
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return None
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return round((time.monotonic() - t0) * 1000)
    except Exception:
        return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _curl_socks(port: int, url: str, timeout: int):
    t0 = time.monotonic()
    try:
        out = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), "--socks5-hostname",
             f"127.0.0.1:{port}", "-w", "\n%{http_code}", url],
            capture_output=True, text=True, timeout=timeout + 5)
        body, _, code = out.stdout.rpartition("\n")
        return body.strip(), int(code or 0), round((time.monotonic() - t0) * 1000)
    except Exception:
        return "", 0, round((time.monotonic() - t0) * 1000)


DEFAULT_PROBE = "http://cp.cloudflare.com/generate_204"


async def test_link(link: str, timeout: int = 22, probe_url: str = DEFAULT_PROBE) -> dict:
    sp = parse_spec(link)
    res = {"ok": False, "proto": sp["proto"] if sp else "?",
           "endpoint": "", "ping_ms": None, "tunnel_ms": None, "exit_ip": "",
           "exit_country": "", "exit_country_code": "", "exit_isp": "",
           "iran_dns": "unknown", "error": ""}
    if not sp or not sp["host"] or not sp["port"]:
        res["error"] = "parse_failed"
        return res
    host, port, proto = sp["host"], sp["port"], sp["proto"]
    res["endpoint"] = f"{host}:{port}"
    loop = asyncio.get_running_loop()
    res["iran_dns"] = await loop.run_in_executor(None, iran_dns_status, host)
    if proto not in ("hysteria2", "tuic"):
        res["ping_ms"] = await loop.run_in_executor(None, _tcp_ping, host, port)
    sport = _free_port()
    if use_singbox(sp):
        ob = build_singbox_outbound(sp)
        if not ob:
            res["error"] = "parse_failed"
            return res
        cfg = {"log": {"level": "error"},
               "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": sport}],
               "outbounds": [dict(ob, tag="proxy")], "route": {"final": "proxy"}}
        cmd = [SINGBOX, "run", "-c"]
    else:
        ob = build_xray_outbound(sp)
        if not ob:
            res["error"] = "parse_failed"
            return res
        cfg = {"log": {"loglevel": "error"},
               "inbounds": [{"listen": "127.0.0.1", "port": sport, "protocol": "socks",
                             "settings": {"udp": True}}],
               "outbounds": [ob]}
        cmd = [XRAY, "run", "-c"]
    cfg_path = f"/tmp/cfgtest-{sport}.json"
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cfg_path, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        return await _wait_and_probe(proc, sport, probe_url, res)
    finally:
        if proc and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        try:
            os.unlink(cfg_path)
        except Exception:
            pass


async def _wait_and_probe(proc, sport, probe_url, res):
    """Shared tail of every core-based test: wait for the local socks
    port, probe through the tunnel, fill res."""
    loop = asyncio.get_running_loop()
    up = False
    for _ in range(30):
        if proc.returncode is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", sport), timeout=0.3):
                up = True
                break
        except Exception:
            await asyncio.sleep(0.2)
    if not up:
        err = b""
        if proc.returncode is not None and proc.stdout:
            try:
                err = await asyncio.wait_for(proc.stdout.read(), 1)
            except Exception:
                pass
        tail = err.decode(errors="replace").strip().splitlines()
        res["error"] = ("core_exit: " + (tail[-1][:110] if tail else "?")) \
            if proc.returncode is not None else "core_not_up"
        return res
    body, code, ms = await loop.run_in_executor(
        None, _curl_socks, sport, probe_url, 10)
    if code not in (200, 204):
        res["error"] = f"tunnel_http_{code or 'timeout'}"
        return res
    res["tunnel_ms"] = ms
    body, code, _ms = await loop.run_in_executor(
        None, _curl_socks, sport,
        "http://ip-api.com/json/?fields=query,country,countryCode,isp", 10)
    if code == 200 and body:
        try:
            d = json.loads(body)
            res["exit_ip"] = d.get("query", "")
            res["exit_country"] = d.get("country", "")
            res["exit_country_code"] = d.get("countryCode", "")
            res["exit_isp"] = d.get("isp", "")
        except Exception:
            pass
    res["ok"] = True
    return res


def _blank_res(proto):
    return {"ok": False, "proto": proto, "endpoint": "", "ping_ms": None,
            "tunnel_ms": None, "exit_ip": "", "exit_country": "",
            "exit_country_code": "", "exit_isp": "", "iran_dns": "unknown",
            "error": ""}


async def test_npv(data: bytes, probe_url: str = DEFAULT_PROBE) -> dict:
    """Test a NapsternetV (.npv/.npvt/.npvs) file: it carries a full
    v2ray/sing-box config JSON — lift its proxy outbound and run the
    same tunnel probes against it."""
    res = _blank_res("npv")
    try:
        doc = json.loads(data.decode("utf-8", "ignore"))
    except Exception:
        res["error"] = "npv_parse"
        return res
    outbounds = doc.get("outbounds") or []
    proxy = None
    for o in outbounds:
        kind = o.get("protocol") or o.get("type") or ""
        if kind.lower() not in ("freedom", "blackhole", "direct", "block", "dns"):
            proxy = o
            break
    if not proxy:
        res["error"] = "npv_parse"
        return res
    # endpoint + ping, best effort from the outbound's settings
    try:
        st = proxy.get("settings") or {}
        vn = (st.get("vnext") or [{}])[0]
        sv = (st.get("servers") or [{}])[0]
        host = vn.get("address") or sv.get("address") or proxy.get("server")
        port = vn.get("port") or sv.get("port") or proxy.get("server_port")
        if host and port:
            res["endpoint"] = f"{host}:{port}"
            loop = asyncio.get_running_loop()
            res["iran_dns"] = await loop.run_in_executor(None, iran_dns_status, str(host))
            res["ping_ms"] = await loop.run_in_executor(None, _tcp_ping, str(host), int(port))
    except Exception:
        pass
    sport = _free_port()
    if "protocol" in proxy:  # xray/v2ray shape
        cfg = {"log": {"loglevel": "error"},
               "inbounds": [{"listen": "127.0.0.1", "port": sport,
                             "protocol": "socks", "settings": {"udp": True}}],
               "outbounds": [proxy]}
        cmd = [XRAY, "run", "-c"]
    else:  # sing-box shape
        cfg = {"log": {"level": "error"},
               "inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                             "listen_port": sport}],
               "outbounds": [dict(proxy, tag="proxy")],
               "route": {"final": "proxy"}}
        cmd = [SINGBOX, "run", "-c"]
    cfg_path = f"/tmp/cfgtest-{sport}.json"
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cfg_path, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        return await _wait_and_probe(proc, sport, probe_url, res)
    finally:
        if proc and proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        try:
            os.unlink(cfg_path)
        except Exception:
            pass


async def test_ovpn(data: bytes, probe_url: str = DEFAULT_PROBE) -> dict:
    """Test an OpenVPN (.ovpn) file with a real openvpn handshake.
    Success = 'Initialization Sequence Completed'. If the host lacks a
    tun device, fall back to endpoint reachability and say so in note."""
    res = _blank_res("openvpn")
    text = data.decode("utf-8", "ignore")
    host = port = None
    proto = "udp"
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        if parts[0] == "remote" and len(parts) >= 2:
            host = parts[1]
            port = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 1194
        if parts[0] == "proto" and len(parts) >= 2:
            proto = parts[1]
    if not host:
        res["error"] = "npv_parse"
        return res
    res["endpoint"] = f"{host}:{port}"
    loop = asyncio.get_running_loop()
    res["iran_dns"] = await loop.run_in_executor(None, iran_dns_status, host)
    if proto.startswith("tcp"):
        res["ping_ms"] = await loop.run_in_executor(None, _tcp_ping, host, port)
    path = f"/tmp/ovpn-{random.randint(1000, 9999)}.ovpn"
    with open(path, "wb") as f:
        f.write(data)
    try:
        proc = await asyncio.create_subprocess_exec(
            "openvpn", "--config", path, "--connect-retry-max", "1",
            "--connect-timeout", "8", "--auth-nocache", "--route-nopull",
            "--verb", "3",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            out, _ = await proc.communicate()
        log = out.decode(errors="replace")
        if "Initialization Sequence Completed" in log:
            res["ok"] = True
            res["note"] = "handshake_ok"
        elif "AUTH_FAILED" in log or "auth-user-pass" in log:
            res["error"] = "ovpn_auth"
        elif "Cannot open TUN/TAP" in log or "ERROR: Cannot open" in log:
            # no tun on this host: degrade to reachability verdict
            if res["ping_ms"] is not None:
                res["error"] = "ovpn_no_tun"
                res["note"] = "endpoint reachable; tun unavailable on tester host"
            else:
                res["error"] = "ovpn_unreachable"
        else:
            res["error"] = "ovpn_unreachable"
        return res
    except FileNotFoundError:
        res["error"] = "ovpn_unreachable"
        res["note"] = "openvpn binary missing"
        return res
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


async def test_file(data: bytes, filename: str, probe_url: str = DEFAULT_PROBE) -> dict:
    ext = os.path.splitext(filename or "")[1].lower()
    if ext in (".npv", ".npvt", ".npvs"):
        return await test_npv(data, probe_url)
    if ext == ".ovpn":
        return await test_ovpn(data, probe_url)
    return _blank_res("file")


def flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())


def user_reason(res: dict) -> str:
    """The ONLY failure text a user ever sees: plain Persian, no jargon,
    no internals. Technical detail stays in the owner log (res['error'])."""
    raw = str(res.get("error", ""))
    if raw == "parse_failed":
        return "لینک کانفیگ خوانا نیست"
    if raw.startswith("tunnel_http"):
        return "سرور جواب نداد (احتمالاً خاموش یا پر است)"
    if raw.startswith("core_exit") or raw == "core_not_up":
        return "قالب این کانفیگ پشتیبانی نشد"
    if raw == "ovpn_auth":
        return "نیاز به یوزر/پسورد دارد"
    if raw == "ovpn_unreachable":
        return "سرور در دسترس نیست"
    if raw == "ovpn_no_tun":
        return "از روی سرور تست قابل بررسی نیست"
    if raw == "npv_parse":
        return "فایل خوانا نیست"
    return "وصل نشد"


def format_result(res: dict) -> str:
    """Short PLAIN-TEXT Persian result block written under each posted
    config (Bale renders entities, not markup — no tags here, ever)."""
    if res.get("ok"):
        ping = res.get("ping_ms")
        ping_s = f"{ping}ms" if ping is not None else f"{res.get('tunnel_ms')}ms"
        loc = f"{flag(res.get('exit_country_code', ''))} {res.get('exit_country', '')}".strip()
        dns = {"ok": "سالم ✅️", "poisoned": "مسموم/فیلتر ❌️", "timeout": "بدون پاسخ ⚠️",
               "ip": "—", "unknown": "نامشخص"}.get(res.get("iran_dns"), "نامشخص")
        lines = ["✅️ وصل شد", f"📶 پینگ: {ping_s}"]
        if loc:
            lines.append(f"🌍 خروجی: {loc}")
        if res.get("exit_ip"):
            lines.append(f"🔢 آی‌پی خروجی: {res['exit_ip']}")
        lines.append(f"🧪 DNS ایران: {dns}")
        return "\n".join(lines)
    return f"❌️ وصل نشد\n📝 دلیل: {user_reason(res)}"


if __name__ == "__main__":
    r = asyncio.run(test_link(sys.argv[1]))
    print(json.dumps(r, ensure_ascii=False, indent=1))
    print("---")
    print(format_result(r))
