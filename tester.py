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
import re
import urllib.parse

import httpx

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


_iran_reach_cache = {}


async def iran_reach(host: str):
    """Iran-vantage reachability (Iliya's order: tests must speak for
    IRAN, not just Germany). A Globalping probe inside Tehran pings the
    config's server. Returns (reachable True/False/None, avg_ms|None);
    None = no Iran probe answered in time — stated honestly, never
    guessed. Cached 10 min per host."""
    if not host:
        return None, None
    now = time.time()
    hit = _iran_reach_cache.get(host)
    if hit and now - hit[0] < 600:
        return hit[1], hit[2]
    out = (None, None)
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post("https://api.globalping.io/v1/measurements",
                             json={"type": "ping", "target": host,
                                   "locations": [{"country": "IR",
                                                  "city": "Tehran"}],
                                   "limit": 1})
            mid = r.json().get("id")
            if mid:
                for _ in range(10):
                    await asyncio.sleep(2)
                    g = await c.get(
                        f"https://api.globalping.io/v1/measurements/{mid}")
                    d = g.json()
                    if d.get("status") == "finished":
                        res0 = (d.get("results") or [{}])[0]
                        stats = ((res0.get("result") or {})
                                 .get("stats") or {})
                        rcv = stats.get("rcv")
                        if rcv is not None:
                            out = (rcv > 0,
                                   stats.get("avg") if rcv > 0 else None)
                        break
    except Exception:
        out = (None, None)
    _iran_reach_cache[host] = (now, out[0], out[1])
    return out


def iran_dns_status(host: str) -> str:
    """Legacy sync check (kept for compat; iran_dns_check is primary)."""
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


_gp_cache = {}


async def iran_dns_check(host: str) -> str:
    """REAL in-Iran DNS check via a Globalping probe in Tehran — Iranian
    resolvers refuse foreign clients, so asking them from Germany timed
    out for most domains. Cached 10 min per host.
    Returns ok / poisoned / timeout / ip / unknown."""
    try:
        socket.inet_aton(host)
        return "ip"
    except Exception:
        pass
    now = time.time()
    hit = _gp_cache.get(host)
    if hit and now - hit[1] < 600:
        return hit[0]
    verdict = "unknown"
    try:
        async with httpx.AsyncClient(timeout=20) as cl:
            r = await cl.post("https://api.globalping.io/v1/measurements", json={
                "type": "dns", "target": host,
                "locations": [{"country": "IR"}], "limit": 1})
            if r.status_code in (200, 202):
                mid = r.json().get("id")
                raw = ""
                for _ in range(8):
                    await asyncio.sleep(1.6)
                    g = await cl.get(
                        f"https://api.globalping.io/v1/measurements/{mid}")
                    d = g.json()
                    if d.get("status") == "finished":
                        res0 = (d.get("results") or [{}])[0]
                        raw = (res0.get("result") or {}).get("rawOutput", "")
                        break
                if raw:
                    ips = re.findall(r"\bIN\s+A\s+(\d+\.\d+\.\d+\.\d+)", raw)
                    glob = await asyncio.get_running_loop().run_in_executor(
                        None, _dns_a, host, GLOBAL_RESOLVER)
                    if any(ip in POISON_IPS or ip.startswith("10.") for ip in ips):
                        verdict = "poisoned"
                    elif not ips and glob:
                        verdict = "poisoned"  # resolves globally, dead in Iran
                    elif ips:
                        verdict = "ok"
                    else:
                        verdict = "timeout"
    except Exception:
        verdict = "unknown"
    _gp_cache[host] = (verdict, now)
    return verdict


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
    res["iran_dns"] = await iran_dns_check(host)
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
        reach_task = asyncio.create_task(iran_reach(host))
        out = await _wait_and_probe(proc, sport, probe_url, res)
        out["iran_reach"], out["iran_ping_ms"] = await reach_task
        return out
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
    # MULTI-DOMAIN VERDICT (Iliya's law): the tunnel is probed against
    # several different domains. ALL answer -> «وصل» (connected). SOME
    # answer -> «نامعلوم» (unknown). NONE answer -> «قطع» (disconnected).
    probe_urls = list(dict.fromkeys([
        probe_url,
        "http://cp.cloudflare.com/generate_204",
        "http://www.google.com/generate_204",
        "http://connectivitycheck.gstatic.com/generate_204",
        "https://cp.cloudflare.com/generate_204",
    ]))[:4]
    results = await asyncio.gather(*[
        loop.run_in_executor(None, _curl_socks, sport, u, 10)
        for u in probe_urls])
    oks = [c in (200, 204) for _b, c, _m in results]
    probes_ok = sum(oks)
    res["probes_ok"] = probes_ok
    res["probes_total"] = len(probe_urls)
    res["tunnel_ms"] = next((m for _b, c, m in results if c in (200, 204)), None)
    if probes_ok == 0:
        res["error"] = "tunnel_http_timeout"
        return res
    # real-data layer: an actual 25 KB download through the same tunnel
    dl, code3, dl_ms = await loop.run_in_executor(
        None, _curl_socks, sport,
        "http://speed.cloudflare.com/__down?bytes=25000", 12)
    data_ok = code3 == 200 and bool(dl) and len(dl) >= 10000
    if data_ok:
        res["dl_ms"] = dl_ms
        if dl_ms:
            res["speed_kbps"] = round(len(dl) / max(dl_ms, 1) * 1000 / 1024, 1)
    if probes_ok < len(probe_urls) or not data_ok:
        res["partial"] = True
        res["error"] = "verdict_unknown"
        # still collect exit info below for the «نامعلوم» post
    else:
        res["https_ok"] = True
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
    if not res.get("partial"):
        res["ok"] = True
        res["error"] = ""
    return res


def _blank_res(proto):
    return {"ok": False, "proto": proto, "endpoint": "", "ping_ms": None,
            "tunnel_ms": None, "exit_ip": "", "exit_country": "",
            "exit_country_code": "", "exit_isp": "", "iran_dns": "unknown",
            "error": ""}


NPVT_DECODER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "tools", "npvt-decoder", "decode_json.php")


async def _decrypt_npvt(data: bytes):
    """NPVT1 = NapsternetV white-box AES-CTR export. Decoded with the
    community PHP whitebox decoder; returns the Xray config dicts of
    the servers inside the file."""
    path = f"/tmp/npvt-{random.randint(10000, 99999)}.npvt"
    with open(path, "wb") as f:
        f.write(data)
    try:
        proc = await asyncio.create_subprocess_exec(
            "php", NPVT_DECODER, path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
        doc = json.loads(out.decode(errors="ignore"))
        configs = []
        for srv in doc.get("servers", []):
            vj = (srv.get("v2rayProfile") or {}).get("v2rayJson")
            if vj:
                try:
                    configs.append(json.loads(vj))
                except Exception:
                    pass
        return configs
    except Exception:
        return []
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def spec_from_xray_outbound(ob):
    """Translate a v2ray/xray-format outbound into the tester's spec
    dict, so plain (no-TLS) configs can be routed to sing-box — Xray 26
    refuses vless/vmess/trojan without TLS to public servers, and most
    NapsternetV exports are exactly that."""
    proto = (ob.get("protocol") or "").lower()
    if proto not in ("vless", "vmess", "trojan", "shadowsocks"):
        return None
    st = ob.get("settings") or {}
    vn = (st.get("vnext") or [{}])[0]
    sv = (st.get("servers") or [{}])[0]
    user = (vn.get("users") or [{}])[0]
    ss = ob.get("streamSettings") or {}
    tls = ss.get("tlsSettings") or {}
    real = ss.get("realitySettings") or {}
    ws = ss.get("wsSettings") or {}
    grpc = ss.get("grpcSettings") or {}
    sp = {"proto": "ss" if proto == "shadowsocks" else proto,
          "host": vn.get("address") or sv.get("address") or "",
          "port": int(vn.get("port") or sv.get("port") or 0),
          "uuid": user.get("id") or "", "password": sv.get("password") or user.get("pass") or "",
          "method": sv.get("method") or "", "cipher": user.get("security") or "auto",
          "alter_id": int(user.get("alterId") or 0), "flow": user.get("flow") or "",
          "security": ss.get("security") or "none",
          "sni": tls.get("serverName") or real.get("serverName") or "",
          "fp": tls.get("fingerprint") or real.get("fingerprint") or "",
          "pbk": real.get("publicKey") or "", "sid": real.get("shortId") or "",
          "insecure": bool(tls.get("allowInsecure")),
          "transport": ss.get("network") or "tcp",
          "ws_path": ws.get("path") or "/",
          "ws_host": (ws.get("headers") or {}).get("Host") or "",
          "grpc_service": grpc.get("serviceName") or "",
          "congestion": "bbr", "raw": ""}
    return sp


async def _test_config_doc(doc, probe_url):
    """Run the full tunnel test stack against one parsed config doc
    (a v2ray/xray or sing-box JSON with outbounds)."""
    res = _blank_res("npv")
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
    try:
        st = proxy.get("settings") or {}
        vn = (st.get("vnext") or [{}])[0]
        sv = (st.get("servers") or [{}])[0]
        host = vn.get("address") or sv.get("address") or proxy.get("server")
        port = vn.get("port") or sv.get("port") or proxy.get("server_port")
        if host and port:
            res["endpoint"] = f"{host}:{port}"
            loop = asyncio.get_running_loop()
            res["iran_dns"] = await iran_dns_check(str(host))
            res["ping_ms"] = await loop.run_in_executor(
                None, _tcp_ping, str(host), int(port))
    except Exception:
        pass
    sport = _free_port()
    sp = spec_from_xray_outbound(proxy) if "protocol" in proxy else None
    if sp and use_singbox(sp):
        # plain no-TLS config: Xray would refuse it — sing-box takes it
        cfg = {"log": {"level": "error"},
               "inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                             "listen_port": sport}],
               "outbounds": [dict(build_singbox_outbound(sp), tag="proxy")],
               "route": {"final": "proxy"}}
        cmd = [SINGBOX, "run", "-c"]
    elif "protocol" in proxy:  # xray/v2ray shape
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
        ep_host = (res.get("endpoint") or "").rsplit(":", 1)[0]
        reach_task = asyncio.create_task(iran_reach(ep_host))
        out = await _wait_and_probe(proc, sport, probe_url, res)
        out["iran_reach"], out["iran_ping_ms"] = await reach_task
        return out
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


def parse_wg_conf(text: str):
    """Parse a WireGuard .conf (INI). Returns (interface, peer) dicts or
    None when the text is not a WireGuard config."""
    if "[interface]" not in text.lower() or "privatekey" not in text.lower():
        return None
    iface, peer, cur = {}, {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        low = line.lower()
        if low == "[interface]":
            cur = iface
        elif low == "[peer]":
            cur = peer
        elif "=" in line and cur is not None:
            k, v = line.split("=", 1)
            cur[k.strip().lower()] = v.strip()
    if not iface.get("privatekey") or not peer.get("publickey") \
            or not peer.get("endpoint"):
        return None
    return iface, peer


async def test_wireguard(data: bytes, probe_url: str = DEFAULT_PROBE) -> dict:
    """Full tunnel test of a WireGuard .conf through sing-box (wireguard
    endpoint, sing-box >= 1.11). Same multi-layer stack as links."""
    res = _blank_res("wireguard")
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        res["error"] = "parse_failed"
        return res
    parsed = parse_wg_conf(text)
    if not parsed:
        res["error"] = "parse_failed"
        return res
    iface, peer = parsed
    ep = peer["endpoint"].rsplit(":", 1)
    if len(ep) != 2:
        res["error"] = "parse_failed"
        return res
    host, port = ep[0].strip("[]"), int(ep[1])
    res["endpoint"] = f"{host}:{port}"
    res["iran_dns"] = await iran_dns_check(host)
    addrs = [a.strip() for a in (iface.get("address") or "10.0.0.2/32").split(",")]
    peer_cfg = {"address": host, "port": port,
                "public_key": peer["publickey"],
                "allowed_ips": [a.strip() for a in
                                (peer.get("allowedips") or "0.0.0.0/0").split(",")]}
    if peer.get("presharedkey"):
        peer_cfg["pre_shared_key"] = peer["presharedkey"]
    sport = _free_port()
    cfg = {"log": {"level": "error"},
           "inbounds": [{"type": "mixed", "listen": "127.0.0.1",
                         "listen_port": sport}],
           "endpoints": [{"type": "wireguard", "tag": "proxy",
                          "address": addrs,
                          "private_key": iface["privatekey"],
                          "peers": [peer_cfg]}],
           "outbounds": [{"type": "direct", "tag": "direct"}],
           "route": {"final": "proxy"}}
    cfg_path = f"/tmp/cfgtest-{sport}.json"
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            SINGBOX, "run", "-c", cfg_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        reach_task = asyncio.create_task(iran_reach(host))
        out = await _wait_and_probe(proc, sport, probe_url, res)
        out["iran_reach"], out["iran_ping_ms"] = await reach_task
        return out
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


async def test_npv(data: bytes, probe_url: str = DEFAULT_PROBE) -> dict:
    """Test a NapsternetV file. Plain .npv = config JSON; .npvt (NPVT1)
    is the app's encrypted export — decrypted first. Multi-server files
    are tested server by server (up to 6, stop at 3 healthy) and the
    counts are reported."""
    res = _blank_res("npv")
    if data[:5] == b"NPVT1":
        docs = await _decrypt_npvt(data)
        if not docs:
            res["error"] = "npv_parse"
            return res
    else:
        try:
            docs = [json.loads(data.decode("utf-8", "ignore"))]
        except Exception:
            res["error"] = "npv_parse"
            return res
    total = len(docs)
    tested = ok_count = partial_count = 0
    best = best_partial = None
    last_err = ""
    for doc in docs[:6]:
        r = await _test_config_doc(doc, probe_url)
        tested += 1
        last_err = r.get("error", "")
        if r.get("ok"):
            ok_count += 1
            if best is None:
                best = r
            if ok_count >= 3:
                break
        elif r.get("partial"):
            partial_count += 1
            if best_partial is None:
                best_partial = r
    res["servers_total"] = total
    res["servers_tested"] = tested
    res["servers_ok"] = ok_count
    res["servers_partial"] = partial_count
    chosen = best if best is not None else best_partial
    if chosen is not None:
        for k in ("endpoint", "ping_ms", "tunnel_ms", "exit_ip", "exit_country",
                  "exit_country_code", "exit_isp", "iran_dns", "dl_ms",
                  "speed_kbps", "https_ok", "probes_ok", "probes_total",
                  "iran_reach", "iran_ping_ms"):
            res[k] = chosen.get(k)
        if best is not None:
            res["ok"] = True
            res["error"] = ""
        else:
            res["partial"] = True
            res["error"] = "verdict_unknown"
        return res
    res["error"] = last_err or "tunnel_http_timeout"
    return res


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
    res["iran_dns"] = await iran_dns_check(host)
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
    if ext in (".conf", ".txt"):
        head = data[:4096].decode("utf-8", "replace")
        if parse_wg_conf(head):
            return await test_wireguard(data, probe_url)
        if ext == ".conf" and "remote " in head and "client" in head:
            return await test_ovpn(data, probe_url)  # ovpn saved as .conf
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
    if raw == "tunnel_unstable":
        return "اتصال ناپایدار بود (یه بار وصل شد، بار دوم نه)"
    if raw == "tunnel_nodata":
        return "وصل شد ولی دیتا رد نشد (عملاً کار نمی‌کنه)"
    if raw == "tunnel_https_fail":
        return "ترافیک امن (HTTPS) از تونل رد نشد"
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
        lines = ["✅️ وصل شد",
                 f"🔗 تست اتصال: {res.get('probes_ok', 4)}/{res.get('probes_total', 4)} دامنه ✅️",
                 f"📶 پینگ: {ping_s}"]
        if res.get("speed_kbps"):
            lines.append(f"🚀 سرعت تقریبی: {res['speed_kbps']} KB/s")
        if loc:
            lines.append(f"🌍 خروجی: {loc}")
        if res.get("exit_ip"):
            lines.append(f"🔢 آی‌پی خروجی: {res['exit_ip']}")
        if res.get("exit_isp"):
            lines.append(f"🏢 اپراتور خروجی: {res['exit_isp']}")
        if res.get("servers_total", 0) > 1:
            lines.append(f"🗂 سرورهای فایل: {res.get('servers_ok', 0)} از "
                         f"{res['servers_total']} سالم")
        if res.get("iran_reach") is True:
            ip_ms = res.get("iran_ping_ms")
            lines.append("🇮🇷 دسترسی از ایران: در دسترس ✅️" +
                         (f" (پینگ {round(ip_ms)}ms)" if ip_ms else ""))
        elif res.get("iran_reach") is False:
            lines.append("🇮🇷 دسترسی از ایران: در دسترس نیست ⚠️")
        if res.get("iran_dns") in ("ok", "poisoned", "timeout"):
            lines.append(f"🧪 DNS ایران: {dns}")
        lines.append("📍 تست از: سرور آلمان")
        return "\n".join(lines)
    return f"❌️ وصل نشد\n📝 دلیل: {user_reason(res)}"


def format_partial(res: dict) -> str:
    """The «نامعلوم» block (Iliya's three-state verdict): some probe
    domains answered, some didn't. Neutral status — NOT an error text:
    no ❌️, no reason line."""
    ping = res.get("ping_ms")
    ping_s = f"{ping}ms" if ping is not None else "—"
    loc = f"{flag(res.get('exit_country_code', ''))} {res.get('exit_country', '')}".strip()
    lines = [f"⚠️ وضعیت اتصال: نامعلوم ({res.get('probes_ok', '؟')} از "
             f"{res.get('probes_total', 4)} دامنه جواب دادن)",
             f"📶 پینگ: {ping_s}"]
    if res.get("servers_total", 0) > 1:
        lines.append(f"🗂 سرورهای فایل: {res.get('servers_ok', 0)} سالم، "
                     f"{res.get('servers_partial', 0)} نامعلوم از {res['servers_total']}")
    if loc:
        lines.append(f"🌍 خروجی: {loc}")
    if res.get("exit_ip"):
        lines.append(f"🔢 آی‌پی خروجی: {res['exit_ip']}")
    if res.get("iran_reach") is True:
        lines.append("🇮🇷 دسترسی از ایران: در دسترس ✅️")
    elif res.get("iran_reach") is False:
        lines.append("🇮🇷 دسترسی از ایران: در دسترس نیست ⚠️")
    lines.append("📍 تست از: سرور آلمان")
    return "\n".join(lines)


if __name__ == "__main__":
    r = asyncio.run(test_link(sys.argv[1]))
    print(json.dumps(r, ensure_ascii=False, indent=1))
    print("---")
    print(format_result(r))
