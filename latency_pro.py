#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
优选IP 精测工具（本地可视化版）
================================
零依赖：只用 Python 标准库，无需 pip install。
运行: python latency_pro.py
然后自动打开 http://127.0.0.1:8765

功能:
  1. 握手测速 —— TCP 连接 + 真实 SNI 的 TLS 握手（可自定义 SNI，多端口取最优；
     vless 输入自动用每条链接自带的 SNI）
  2. 下载测速 —— SNI=speed.cloudflare.com 拉取指定大小数据，实测下行带宽
  3. 混合模式 —— 先握手筛一遍，再对最快的 N 个测带宽
所有测试都在你本机网络里进行，结果最贴近真实使用体验。
（节点的真实链路速度建议用 v2rayN 批量测速：与日常上网同指纹，不触发干扰）
"""
import json
import os
import re
import socket
import ssl
import threading
import time
import uuid as uuidmod
import webbrowser
import contextlib
import http.server
import socketserver
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor

HOST = "127.0.0.1"
PORT_CANDIDATES = range(8765, 8776)
DEFAULT_SNI = "www.cloudflare.com"   # 用户未填 SNI 时的兜底，不含任何私人域名
DEFAULT_PORTS = "443,2053,2083,2087,2096,8443"

# 握手测试用的 SSL 上下文（IP 直连证书必然不匹配，关闭校验只测连通和延迟）
HS_CTX = ssl.create_default_context()
HS_CTX.check_hostname = False
HS_CTX.verify_mode = ssl.CERT_NONE
HS_CTX.set_alpn_protocols(["http/1.1"])

# 下载测速用的上下文（SNI=speed.cloudflare.com，证书能对上，走默认校验）
DL_CTX = ssl.create_default_context()
DL_CTX.set_alpn_protocols(["http/1.1"])

JOB = {
    "running": False,
    "stop": False,
    "phase": "",
    "done": 0,
    "total": 0,
    "results": [],
    "sni": DEFAULT_SNI,
    "error": None,
    "ok": 0,
    "fail": 0,
    "dl_ok": 0,
    "dl_fail": 0,
    "log": [],
}
LOCK = threading.Lock()


def log(msg):
    """同时写到终端和网页运行日志。"""
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    with LOCK:
        JOB["log"].append(line)
        if len(JOB["log"]) > 400:
            del JOB["log"][:-400]
    print(line, flush=True)


def reason_of(e):
    """把异常翻译成人话。"""
    if isinstance(e, socket.timeout):
        return "连接/握手超时（IP可能已死或被墙）"
    if isinstance(e, ConnectionRefusedError):
        return "连接被拒绝（端口没开）"
    if isinstance(e, ConnectionResetError):
        return "连接被重置（可能被干扰）"
    if isinstance(e, socket.gaierror):
        return "域名解析失败（DNS有问题）"
    if isinstance(e, ssl.SSLError):
        return "TLS握手错误: " + str(e)[:80]
    return type(e).__name__ + ": " + str(e)[:80]


# ---------------------------------------------------------------- 测试核心

def parse_targets(text, ports, tgt_type="host"):
    """把用户输入解析成 [(host, port)]。
    tgt_type: host=IP/域名(用下拉选的端口) | hostport=IP:端口(自带) | vless=链接(自动提取)
    非 host 模式下，目标没写端口时用 443 兜底。"""
    out, seen = [], set()
    n_raw = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        m = re.match(r"^vless://[^@]+@([^:/?#]+)(?::(\d+))?", s)
        if m:
            s = m.group(1) + (":" + m.group(2) if m.group(2) else "")
        elif tgt_type == "vless":
            continue  # vless 模式下只接受 vless 链接
        s = re.sub(r"^[a-zA-Z]+://", "", s).split("/")[0].strip()
        idx = s.rfind(":")
        if idx > -1 and s[idx + 1:].isdigit():
            host, plist = s[:idx], [int(s[idx + 1:])]
        else:
            host = s
            plist = ports if tgt_type == "host" else [443]
        if not host:
            continue
        for p in plist:
            n_raw += 1
            key = host + ":" + str(p)
            if key not in seen:
                seen.add(key)
                out.append((host, p))
    return out, n_raw


def handshake_test(host, port, sni, timeout_s, rounds):
    """真实 SNI 的 TLS 握手，多轮取最优。返回 dict 或 None。"""
    best = None
    last_reason = ""
    for _ in range(max(1, rounds)):
        if JOB["stop"]:
            break
        s = None
        try:
            s = socket.socket()
            s.settimeout(timeout_s)
            t0 = time.perf_counter()
            s.connect((host, port))
            tcp = (time.perf_counter() - t0) * 1000
            ss = HS_CTX.wrap_socket(s, server_hostname=sni)
            tls = (time.perf_counter() - t0) * 1000
            # 发一个请求确认链路真的活着
            with contextlib.suppress(Exception):
                ss.sendall(("GET / HTTP/1.1\r\nHost: " + sni + "\r\n\r\n").encode())
                ss.recv(64)
            with contextlib.suppress(Exception):
                ss.close()
            s = None
            if best is None or tls < best["tls"]:
                best = {"host": host, "port": port, "tcp": tcp, "tls": tls,
                        "mbps": None, "ok": True, "type": "hs"}
        except Exception as e:  # noqa: BLE001
            last_reason = reason_of(e)
        finally:
            if s is not None:
                with contextlib.suppress(Exception):
                    s.close()
    if best:
        log("✓ %s:%s  TCP %.0fms  TLS %.0fms" % (host, port, best["tcp"], best["tls"]))
    else:
        log("✗ %s:%s  %s" % (host, port, last_reason or "未知错误"))
    return best


def download_test(host, port, mb, timeout_s):
    """SNI=speed.cloudflare.com 下载实测带宽。返回 dict 或 None。"""
    total_need = int(mb * 1_000_000)
    timeout = max(timeout_s, 12)
    s = None
    try:
        s = socket.socket()
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.connect((host, port))
        ss = DL_CTX.wrap_socket(s, server_hostname="speed.cloudflare.com")
        s = None
        hs = (time.perf_counter() - t0) * 1000
        ss.sendall(("GET /__down?bytes=" + str(total_need) +
                    " HTTP/1.1\r\nHost: speed.cloudflare.com\r\n"
                    "User-Agent: Mozilla/5.0\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = ss.recv(4096)
            if not chunk:
                log("✗ %s:%s  下载失败  连接中断（未收到HTTP响应，可能不是CF边缘）" % (host, port))
                return None
            buf += chunk
        header, body = buf.split(b"\r\n\r\n", 1)
        status_line = header.split(b"\r\n")[0].decode("utf-8", "ignore")
        if b"200" not in header.split(b"\r\n")[0]:
            log("✗ %s:%s  下载失败  服务器返回: %s" % (host, port, status_line[:40]))
            return None
        total = len(body)
        t1 = time.perf_counter()
        while total < total_need and time.perf_counter() - t1 < timeout:
            chunk = ss.recv(65536)
            if not chunk:
                break
            total += len(chunk)
        elapsed = time.perf_counter() - t1
        with contextlib.suppress(Exception):
            ss.close()
        mbps = total * 8 / elapsed / 1e6
        log("✓ %s:%s  带宽 %.1f Mbps（%dMB 拉满）" % (host, port, mbps, mb))
        return {"host": host, "port": port, "tcp": None, "tls": hs,
                "mbps": round(mbps, 1), "ok": True, "type": "dl"}
    except Exception as e:  # noqa: BLE001
        log("✗ %s:%s  下载失败  %s" % (host, port, reason_of(e)))
        return None
    finally:
        if s is not None:
            with contextlib.suppress(Exception):
                s.close()


CHAIN_URL_DEFAULT = "http://ipv4.download.thinkbroadband.com/10MB.zip"

VLESS_FULL_RE = re.compile(r"^vless://([^@/?#\s]+)@([^:/?#]+)(?::(\d+))?(\?[^#]*)?", re.I)


def parse_vless_links(text):
    """解析 vless 链接，返回 {host:port → 节点参数}。"""
    nodes = {}
    for line in text.splitlines():
        s = line.strip()
        m = VLESS_FULL_RE.match(s)
        if not m:
            continue
        uid_raw, host, port_s, qs = m.groups()
        try:
            uid = str(uuidmod.UUID(uid_raw.strip()))
        except ValueError:
            continue
        params = dict(re.findall(r"([a-zA-Z0-9_]+)=([^&]*)", qs or ""))
        node = {
            "host": host,
            "port": int(port_s) if port_s else 443,
            "uuid": uid,
            "path": unquote(params.get("path") or "/"),
            "sni": unquote(params.get("sni") or "") or host,
            "ws_host": unquote(params.get("host") or "") or host,
            "type": params.get("type", "ws"),
        }
        nodes[host + ":" + str(node["port"])] = node
    return nodes


def run_job(params):
    mode = params.get("mode", "hs") or "hs"
    try:
        sni = params.get("sni") or DEFAULT_SNI
        ports = [int(p) for p in re.split(r"[,，\s]+", params.get("ports", "")) if p.isdigit()]
        if not ports:
            ports = [443]
        timeout_s = min(30, max(1, float(params.get("timeout", 5000)) / 1000))
        rounds = min(5, max(1, int(params.get("rounds", 1))))
        conc = min(200, max(1, int(params.get("conc", 40))))
        dl_mb = min(10, max(1, int(params.get("dl_mb", 10))))
        dl_top = min(100, max(0, int(params.get("dl_top", 10))))
        tgt_type = params.get("tgt_type", "host") or "host"
        nodes = parse_vless_links(params.get("targets", "")) if tgt_type == "vless" else {}

        targets, n_raw = parse_targets(params.get("targets", ""), ports,
                                tgt_type)
        if not targets:
            hint = {"host": "IP / 域名", "hostport": "IP:端口",
                    "vless": "vless 链接"}.get(tgt_type, "目标")
            JOB["error"] = "没有解析到有效目标（当前格式要求：" + hint + "，请检查输入）"
            return
        if n_raw > len(targets):
            dedup_msg = "去重：原始 %d 个目标 → 重复剔除 %d 个 → 实测 %d 个唯一目标" % (
                n_raw, n_raw - len(targets), len(targets))
        else:
            dedup_msg = None

        with LOCK:
            JOB.update(running=True, stop=False, done=0, results=[],
                       error=None, ok=0, fail=0, dl_ok=0, dl_fail=0, log=[])
        if dedup_msg:
            log(dedup_msg)
        log("开始测试 · SNI=%s · %d 个目标 · 模式=%s" % (sni, len(targets), mode))

        # ---- 握手阶段
        need_hs = mode in ("hs", "both")
        need_dl = mode in ("dl", "both")
        if need_hs:
            with LOCK:
                JOB.update(phase="握手测速", total=len(targets), done=0)
            log("── 握手测速开始（%d 个目标）──" % len(targets))
            hs_ok = []
            with ThreadPoolExecutor(min(conc, len(targets))) as ex:
                futs = [ex.submit(handshake_test, h, p,
                                  (nodes.get(h + ":" + str(p)) or {}).get("sni") or sni,
                                  timeout_s, rounds)
                        for h, p in targets]
                for f in futs:
                    r = f.result()
                    with LOCK:
                        JOB["done"] += 1
                        if r:
                            hs_ok.append(r)
                            JOB["results"].append(r)
                            JOB["ok"] += 1
                        else:
                            JOB["fail"] += 1
                    if JOB["stop"]:
                        break
            hs_ok.sort(key=lambda r: r["tls"])
            log("── 握手测速结束：成功 %d / 失败 %d ──" % (JOB["ok"], JOB["fail"]))
        else:
            hs_ok = []

        # ---- 下载阶段
        if need_dl and not JOB["stop"]:
            if mode == "both":
                dl_targets = [(r["host"], r["port"]) for r in hs_ok[:dl_top]]
            else:
                dl_targets = targets
            if dl_targets:
                with LOCK:
                    JOB.update(phase="下载测速", total=len(dl_targets), done=0)
                log("── 下载测速开始（%d 个目标，每个 %dMB）──" % (len(dl_targets), dl_mb))
                with ThreadPoolExecutor(min(6, len(dl_targets))) as ex:
                    futs = [ex.submit(download_test, h, p, dl_mb, timeout_s)
                            for h, p in dl_targets]
                    for f in futs:
                        r = f.result()
                        with LOCK:
                            JOB["done"] += 1
                            if r:
                                JOB["dl_ok"] += 1
                            else:
                                JOB["dl_fail"] += 1
                        if r:
                            with LOCK:
                                if mode == "both":
                                    # 把带宽结果合并回握手记录
                                    for old in JOB["results"]:
                                        if old["host"] == r["host"] and old["port"] == r["port"]:
                                            old["mbps"] = r["mbps"]
                                            break
                                else:
                                    JOB["results"].append(r)
                        if JOB["stop"]:
                            break
    except Exception as e:  # noqa: BLE001
        JOB["error"] = str(e)
    finally:
        with LOCK:
            if mode == "dl":
                JOB["results"].sort(key=lambda r: -(r.get("mbps") or 0))
            else:
                JOB["results"].sort(key=lambda r: r.get("tls") if r.get("tls") is not None else 1e9)
        JOB["running"] = False
        JOB["phase"] = ""


# ---------------------------------------------------------------- 页面

PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>优选IP 精测 · 本地版</title>
<style>
:root{--bg:#f4f4f8;--card:rgba(255,255,255,.72);--line:rgba(28,25,55,.10);--text:#211f33;
--muted:#6b6880;--accent:#7c3aed;--accent2:#db2777;--ok:#22a55a;--warn:#e08700;--bad:#dc2626}
*{margin:0;padding:0;box-sizing:border-box}
body{background:radial-gradient(700px 380px at 12% -6%,rgba(124,58,237,.12),transparent 60%),
radial-gradient(700px 380px at 90% 8%,rgba(219,39,119,.09),transparent 60%),#f4f4f8;
color:var(--text);font-family:"PingFang SC","Microsoft YaHei",system-ui,sans-serif;line-height:1.7;min-height:100vh}
.wrap{max-width:1120px;margin:0 auto;padding:0 24px}
header{padding:36px 0 20px}
h1{font-size:30px;font-weight:900}
h1 em{font-style:normal;background:linear-gradient(90deg,var(--accent),var(--accent2));
-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{color:var(--muted);margin-top:6px;font-size:14px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:22px;
backdrop-filter:blur(10px);box-shadow:0 8px 28px rgba(90,60,180,.08);margin-bottom:20px}
.panel h2{font-size:16px;margin-bottom:10px}
textarea{width:100%;min-height:130px;resize:vertical;font:13px/1.7 Consolas,monospace;
border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:rgba(255,255,255,.8);outline:none}
textarea:focus{border-color:var(--accent)}
textarea.err{border-color:var(--bad)}
.row{display:flex;gap:16px;flex-wrap:wrap;margin-top:12px}
.f{flex:1;min-width:180px}
.f label{display:block;font-size:13px;color:var(--muted);margin-bottom:4px}
.f input{width:100%;padding:8px 12px;border:1px solid var(--line);border-radius:10px;
font-size:14px;background:rgba(255,255,255,.8);outline:none}
.f input:focus{border-color:var(--accent)}
.f.off{opacity:.45;pointer-events:none}
.hint-msg{font-size:12px;color:var(--warn);margin-top:4px;line-height:1.4}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border:1px solid var(--line);
border-radius:99px;font-size:14px;cursor:pointer;background:rgba(255,255,255,.8);transition:.15s;user-select:none}
.chip input{width:auto;accent-color:var(--accent);margin:0;cursor:pointer}
.chip:has(input:checked){border-color:var(--accent);background:rgba(124,58,237,.1);color:var(--accent);font-weight:700}
.dd{position:relative}
.dd-btn{width:100%;padding:8px 12px;border:1px solid var(--line);border-radius:10px;
font-size:14px;background:rgba(255,255,255,.8);cursor:pointer;color:var(--text);text-align:left}
.dd-btn:hover,.dd.open .dd-btn{border-color:var(--accent)}
.dd-btn::after{content:"▾";float:right;color:var(--muted)}
.dd-list{display:none;position:absolute;top:calc(100% + 6px);left:0;right:0;z-index:30;
background:#fff;border:1px solid var(--line);border-radius:12px;
box-shadow:0 10px 30px rgba(40,30,80,.15);padding:10px;flex-direction:column;gap:8px}
.dd.open .dd-list{display:flex}
.quick-sel{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;min-height:0}
.quick-sel:empty{margin-bottom:0}
.qbtn{padding:4px 14px;font-size:13px;border:1px solid var(--line);border-radius:99px;
background:rgba(255,255,255,.8);cursor:pointer;color:var(--text);transition:.15s}
.qbtn:hover{border-color:var(--accent);color:var(--accent)}
.seg{display:flex;gap:0;border:1px solid var(--line);border-radius:10px;overflow:hidden;width:fit-content}
.seg button{padding:8px 18px;border:none;background:transparent;cursor:pointer;font-size:14px;color:var(--muted)}
.seg button.on{background:var(--accent);color:#fff}
.btnrow{display:flex;gap:12px;margin-top:16px;align-items:center;flex-wrap:wrap}
.btn{padding:10px 26px;border-radius:12px;border:none;font-size:15px;font-weight:700;cursor:pointer;transition:.2s}
.bp{color:#fff;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.bp:hover{filter:brightness(1.08)}
.bg2{color:var(--muted);background:transparent;border:1px solid var(--line);font-weight:500}
.bg2:hover{border-color:var(--accent);color:var(--accent)}
.btn:disabled{opacity:.5;cursor:not-allowed}
#status{font-size:14px;color:var(--muted)}
#status b{color:var(--accent)}
.bar{height:6px;border-radius:99px;background:rgba(124,58,237,.12);margin-top:14px;overflow:hidden;display:none}
.bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width .2s}
details{margin-top:12px}
summary{cursor:pointer;font-size:13px;color:var(--muted);user-select:none}
summary:hover{color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:9px 10px;text-align:left;border-bottom:1px solid var(--line)}
th{font-size:12px;color:var(--muted);font-weight:600;white-space:nowrap;position:sticky;top:0;background:#fff;z-index:1}
th.sortable:hover{color:var(--accent)}
td.mono{font:13px Consolas,monospace}
tr:hover td{background:rgba(124,58,237,.04)}
.empty{text-align:center;color:var(--muted);font-size:14px;padding:26px 0}
pre#log{font:12px/1.7 Consolas,monospace;max-height:240px;overflow:auto;background:rgba(255,255,255,.65);
padding:12px 14px;border-radius:10px;white-space:pre-wrap;word-break:break-all}
footer{border-top:1px solid var(--line);padding:26px 0;text-align:center;color:var(--muted);font-size:13px}
.tips{margin:0;padding:0;list-style:none;font-size:14px}
.tips li{position:relative;padding:7px 0 7px 26px}
.tips li::before{content:"";position:absolute;left:2px;top:16px;width:8px;height:8px;border-radius:50%;
background:linear-gradient(90deg,var(--accent),var(--accent2))}
.tips b{color:var(--accent)}
.muted{color:var(--muted);font-size:13px;margin-top:8px}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>优选IP <em>精测工具</em> <span style="font-size:13px;color:var(--muted);font-weight:400">本地版 · 数据不出你的电脑</span></h1>
  <div class="sub">真实 SNI 握手 + 实测下载带宽，跑在你自己的网络里，结果最准确。</div>
</header>

<div class="panel">
  <h2>⚠️ 测速前检查</h2>
  <ul class="tips">
    <li>代理软件（v2rayN / Clash / VPN）<b>不用关</b>，但必须确认<b>没开 TUN / 虚拟网卡模式</b> —— TUN 会把测速流量塞进代理隧道，结果完全失真</li>
    <li><b>对照法</b>：把你的 SNI 域名直接加进目标列表一起测 —— 它通而某些 IP 不通 = 那些 IP 质量差；它不通而某些 IP 通 = DNS 给你解析到了坏 IP（这正是优选的意义）。同一批结果<b>挑延迟最低、带宽最好的即可</b>，绝对数值因地区/运营商/时段差异很大，没有全球统一基准</li>
    <li>测带宽时暂停下载、网盘同步、视频等抢带宽的任务，否则 Mbps 会明显偏低</li>
    <li>本工具永远<b>直连</b>目标（不走系统代理），所以系统代理开着不影响结果</li>
    <li><b>如果几乎全部目标都是「连接被重置」</b>，但你代理软件上网正常 —— 说明你的 Python TLS 指纹与 SNI 的组合被针对性干扰了。原因：每个 Python 发行版捆绑的 <b>OpenSSL 版本不同，TLS 握手指纹就不同</b>，实测老版本（如 3.0.x）的指纹更容易被 RST，3.5.x 以上可通过。查看自己的版本：<code>python -c "import ssl; print(ssl.OPENSSL_VERSION)"</code>；解决办法：<b>安装 python.org 官方最新版</b> Python 再运行本工具</li>
  </ul>
  <div class="muted">测过的节点腐得很快（几天前的结果不可信），换配置前建议都重测一遍。</div>
</div>

<div class="panel">
  <h2>目标列表 <small style="font-weight:400;color:var(--muted);font-size:13px">先选输入格式</small></h2>
  <div class="seg" id="tgt-type" style="margin-bottom:10px">
    <button data-v="host" class="on">IP / 域名</button>
    <button data-v="hostport">IP:端口</button>
    <button data-v="vless">vless 链接</button>
  </div>
  <textarea id="targets" placeholder="每行一个，例如：&#10;47.57.189.209&#10;104.16.123.96&#10;www.cloudflare.com"></textarea>
</div>

<div class="panel" style="position:relative;z-index:2">
  <h2>测试模式</h2>
  <div class="seg" id="mode">
    <button data-v="hs" class="on">握手延迟</button>
    <button data-v="both">握手 + 带宽</button>
    <button data-v="dl">仅带宽</button>
  </div>
  <div class="row">
    <div class="f"><label>真实 SNI（你的 Worker 域名）</label><input id="sni" placeholder="留空则用官方域名兜底"></div>
    <div class="f" id="ports-f"><label id="ports-label">端口（可多选）</label>
      <div class="dd" id="ports-dd">
        <button type="button" class="dd-btn" id="ports-btn">443</button>
        <div class="dd-list" id="ports">
          <label class="chip"><input type="checkbox" value="443" checked>443</label>
          <label class="chip"><input type="checkbox" value="2053">2053</label>
          <label class="chip"><input type="checkbox" value="2083">2083</label>
          <label class="chip"><input type="checkbox" value="2087">2087</label>
          <label class="chip"><input type="checkbox" value="2096">2096</label>
          <label class="chip"><input type="checkbox" value="8443">8443</label>
        </div>
      </div>
    </div>
    <div class="f"><label>延迟过滤（TLS 毫秒，0=不限）</label><input id="f_tls" type="number" value="0" min="0" step="50"></div>
    <div class="f off" id="fmbps-f"><label id="fmbps-label">带宽过滤（测带宽后生效）</label><input id="f_mbps" type="number" value="0" min="0" step="1"></div>
  </div>
  <details>
    <summary>高级选项</summary>
    <div class="row">
      <div class="f"><label>单次超时（毫秒）</label><input id="timeout" type="number" value="5000" min="1000" max="30000" step="500"></div>
      <div class="f"><label>握手轮次（取最优）</label><input id="rounds" type="number" value="1" min="1" max="5"></div>
      <div class="f"><label>并发数（握手）</label><input id="conc" type="number" value="40" min="1" max="200"></div>
      <div class="f"><label>下载大小（MB）</label><input id="dl_mb" type="number" value="10" min="1" max="10"><div class="hint-msg" id="dl-mb-hint" style="display:none">超出上限，已自动调整为 10</div></div>
      <div class="f"><label>混合模式取前 N 个</label><input id="dl_top" type="number" value="10" min="1" max="100"><div class="hint-msg" id="dl-top-hint" style="display:none">超出上限，已自动调整为 100</div></div>
    </div>
  </details>
  <div class="btnrow">
    <button class="btn bp" id="start">开测</button>
    <button class="btn bg2" id="stop" disabled>停止</button>
    <button class="btn bp" id="btn-dl" disabled>⚡ 测所选带宽</button>
    <button class="btn bg2" id="copy" disabled>复制结果</button>
    <span id="status">等待开始</span>
  </div>
  <div class="bar" id="bar"><i id="barin"></i></div>
</div>

<div class="panel">
  <h2>结果（按延迟/带宽排序）<span id="result-count" style="font-weight:400;color:var(--muted);font-size:14px"></span></h2>
  <div class="quick-sel" id="quick-sel"></div>
  <div id="box"><div class="empty">还没有结果</div></div>
</div>

<div class="panel">
  <details id="logpanel">
    <summary>📜 运行日志（每个目标的成败和失败原因都在这里）</summary>
    <pre id="log">尚未开始</pre>
  </details>
</div>

<footer>latency_pro.py · 本地运行 · 关掉本窗口和命令行即可退出</footer>
</div>

<script>
var mode="hs",timer=null;
document.querySelectorAll("#mode button").forEach(function(b){
  b.onclick=function(){
    document.querySelectorAll("#mode button").forEach(function(x){x.classList.remove("on")});
    b.classList.add("on");mode=b.dataset.v;
    var ff=document.getElementById("fmbps-f");
    if(mode==="hs"){
      ff.classList.add("off");
      document.getElementById("fmbps-label").textContent="带宽过滤（测带宽后生效）";
    }else{
      ff.classList.remove("off");
      document.getElementById("fmbps-label").textContent="带宽过滤（Mbps，0=不限）";
    }
  };
});
document.getElementById("targets").addEventListener("input",function(){
  this.classList.remove("err");
});
var dlTopEl=document.getElementById("dl_top"),dlTopHint=document.getElementById("dl-top-hint");
dlTopEl.addEventListener("input",function(){
  var v=parseInt(dlTopEl.value,10);
  if(isFinite(v)&&v>100){dlTopEl.value=100;dlTopHint.style.display="block";}
  else{dlTopHint.style.display="none";}
});
dlTopEl.addEventListener("change",function(){
  var v=parseInt(dlTopEl.value,10);
  if(dlTopEl.value!==""&&(!isFinite(v)||v<1)){dlTopEl.value=1;dlTopHint.style.display="none";}
});
var dlMbEl=document.getElementById("dl_mb"),dlMbHint=document.getElementById("dl-mb-hint");
dlMbEl.addEventListener("input",function(){
  var v=parseInt(dlMbEl.value,10);
  if(isFinite(v)&&v>10){dlMbEl.value=10;dlMbHint.style.display="block";}
  else{dlMbHint.style.display="none";}
});
dlMbEl.addEventListener("change",function(){
  var v=parseInt(dlMbEl.value,10);
  if(dlMbEl.value!==""&&(!isFinite(v)||v<1)){dlMbEl.value=1;dlMbHint.style.display="none";}
});
function updateTgtCounts(){
  var lines=val("targets").split(/\\n+/).map(function(s){return s.trim()})
    .filter(function(s){return s&&s.charAt(0)!=="#"&&s.slice(0,2)!=="//"});
  var nVless=0,nPort=0;
  lines.forEach(function(s){
    var isV=/^vless:\\/\\//.test(s);
    if(isV)nVless++;
    var t=s.replace(/^vless:\\/\\/[^@]*@/,"");
    if(isV||/^[a-z0-9.\\-]+:\\d+$/i.test(t))nPort++;
  });
  document.querySelector('#tgt-type [data-v="host"]').textContent="IP / 域名 ("+lines.length+")";
  document.querySelector('#tgt-type [data-v="hostport"]').textContent="IP:端口 ("+nPort+")";
  document.querySelector('#tgt-type [data-v="vless"]').textContent="vless 链接 ("+nVless+")";
}
document.getElementById("targets").addEventListener("input",updateTgtCounts);
updateTgtCounts();
var dd=document.getElementById("ports-dd"),ddBtn=document.getElementById("ports-btn");
function refreshPortBtn(){
  var c=checkedPorts();
  ddBtn.textContent=c.length?(c.length===1?c[0]:c[0]+" 等 "+c.length+" 个"):"请选择端口";
}
ddBtn.onclick=function(e){e.stopPropagation();dd.classList.toggle("open")};
document.querySelectorAll("#ports input").forEach(function(c){
  c.addEventListener("change",refreshPortBtn);
});
document.addEventListener("click",function(e){
  if(!dd.contains(e.target))dd.classList.remove("open");
});
refreshPortBtn();
var tgtType="host";
var tgtPh={
  host:"每行一个 IP 或域名，端口用下方选的，例如：\\n47.57.189.209\\n104.16.123.96\\nwww.cloudflare.com",
  hostport:"每行一个 IP:端口 或 域名:端口，例如：\\n47.57.189.209:443\\nwww.cloudflare.com:8443",
  vless:"每行一条 vless 链接，例如：\\nvless://uuid-xxx@1.2.3.4:443?encryption=none&security=tls&sni=your-domain.com"};
var tgtName={host:"IP / 域名",hostport:"IP:端口",vless:"vless 链接"};
function validateTargets(){
  var ta=document.getElementById("targets");
  ta.classList.remove("err");
  var lines=val("targets").split(/\\n+/).map(function(s){return s.trim()})
    .filter(function(s){return s&&s.charAt(0)!=="#"&&s.slice(0,2)!=="//"});
  if(!lines.length)return{ok:false,msg:"目标列表是空的，请先粘贴目标"};
  var reHost=/^[a-z0-9.\\-]+(:\\d+)?$/i, reHostPort=/^[a-z0-9.\\-]+:\\d+$/i, bad=0, sample="";
  lines.forEach(function(s){
    var ok=true;
    if(tgtType==="hostport")ok=reHostPort.test(s.replace(/^vless:\\/\\/[^@]*@/,""));
    else if(tgtType==="vless")ok=/^vless:\\/\\//.test(s);
    else ok=reHost.test(s.replace(/^vless:\\/\\/[^@]*@/,""));
    if(!ok){bad++;if(!sample)sample=s.slice(0,42);}
  });
  if(bad)return{ok:false,msg:"有 "+bad+" 行不符合「"+tgtName[tgtType]+"」格式，例如："+sample+" —— 请切换输入格式或修改内容"};
  return{ok:true};
}
document.querySelectorAll("#tgt-type button").forEach(function(b){
  b.onclick=function(){
    document.querySelectorAll("#tgt-type button").forEach(function(x){x.classList.remove("on")});
    b.classList.add("on");tgtType=b.dataset.v;
    document.getElementById("targets").placeholder=tgtPh[tgtType];
    var pf=document.getElementById("ports-f");
    if(tgtType==="host"){
      pf.classList.remove("off");
      document.getElementById("ports-label").textContent="端口（可多选）";
    }else{
      pf.classList.add("off");
      document.getElementById("ports-label").textContent="端口（由目标自带）";
    }
  };
});
function val(id){return document.getElementById(id).value}
function checkedPorts(){
  return Array.from(document.querySelectorAll("#ports input:checked")).map(function(c){return c.value});
}
function post(url,obj){
  return fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(obj)});
}
document.getElementById("start").onclick=function(){
  var st=document.getElementById("status");
  var nSel=Object.keys(checkedSet).filter(function(k){return checkedSet[k]}).length;
  if(nSel>0&&!confirm("「开测」会重新测试目标列表，并清空当前全部结果和 "+nSel+" 条勾选。\\n\\n如果只想测结果表中勾选的目标，请改用「⚡ 测所选带宽」。\\n\\n确定要重新开测吗？")){
    return;
  }
  var chk=validateTargets();
  var st=document.getElementById("status");
  if(!chk.ok){
    st.innerHTML="<b style='color:#dc2626'>✗ "+chk.msg+"</b>";
    document.getElementById("targets").classList.add("err");
    return;
  }
  var ports=checkedPorts();
  if(tgtType==="host"&&!ports.length){
    st.innerHTML="<b style='color:#dc2626'>请至少勾选一个端口</b>";
    return;
  }
  post("/api/start",{
    targets:val("targets"),mode:mode,tgt_type:tgtType,sni:val("sni").trim(),
    ports:(tgtType==="host"?ports.join(","):""),
    timeout:+val("timeout"),rounds:+val("rounds"),conc:+val("conc"),
    dl_mb:+val("dl_mb"),dl_top:+val("dl_top"),
    f_tls:+val("f_tls"),f_mbps:+val("f_mbps")
  }).then(function(){poll()});
  this.disabled=true;document.getElementById("stop").disabled=false;
  document.getElementById("btn-dl").disabled=true;
  checkedSet={};baseResults=null;selecting=false;
  updateDlBtn();
};
document.getElementById("stop").onclick=function(){post("/api/stop",{})};
document.getElementById("btn-dl").onclick=function(){
  var st=document.getElementById("status");
  var keys=Object.keys(checkedSet).filter(function(k){return checkedSet[k]});
  if(!keys.length){
    st.innerHTML="<b style='color:#dc2626'>请先在结果表中勾选要实测带宽的目标</b>";
    return;
  }
  baseResults=curResults.slice();
  selecting=true;
  this.disabled=true;
  document.getElementById("start").disabled=true;
  document.getElementById("stop").disabled=false;
  st.innerHTML="⚡ 带宽实测中（仅勾选的 "+keys.length+" 个目标）...";
  post("/api/start",{
    targets:keys.join("\\n"),mode:"dl",tgt_type:"hostport",sni:val("sni").trim(),ports:"",
    timeout:+val("timeout"),rounds:1,conc:Math.min(6,+val("conc")),
    dl_mb:+val("dl_mb"),dl_top:50,f_tls:0,f_mbps:0
  }).then(function(){poll()});
};
function updateDlBtn(){
  var n=Object.keys(checkedSet).filter(function(k){return checkedSet[k]}).length;
  document.getElementById("btn-dl").textContent="⚡ 测所选带宽"+(n?"（"+n+"）":"");
}
document.getElementById("box").addEventListener("change",function(e){
  var t=e.target;
  if(t.classList&&t.classList.contains("ck-all")){
    document.querySelectorAll("#box .rowck").forEach(function(c){
      c.checked=t.checked;checkedSet[c.getAttribute("data-k")]=t.checked;
    });
  }else if(t.classList&&t.classList.contains("rowck")){
    checkedSet[t.getAttribute("data-k")]=t.checked;
    var boxes=document.querySelectorAll("#box .rowck"),all=boxes.length>0;
    for(var i=0;i<boxes.length;i++){if(!boxes[i].checked){all=false;break}}
    var ca=document.querySelector("#box .ck-all");if(ca)ca.checked=all;
  }
  updateDlBtn();
});
document.getElementById("quick-sel").addEventListener("click",function(e){
  if(!e.target.classList||!e.target.classList.contains("qbtn"))return;
  var st=document.getElementById("status");
  var act=e.target.getAttribute("data-act");
  if(act==="invert"){
    for(var i=0;i<last.length;i++){
      if(last[i].show){var k=last[i].key;checkedSet[k]=!checkedSet[k]}
    }
    render(curResults);updateDlBtn();
    st.innerHTML="已反选当前结果";
    return;
  }
  if(act==="clear"){
    checkedSet={};render(curResults);updateDlBtn();
    st.innerHTML="已清空全部勾选";
    return;
  }
  var a=parseInt(e.target.getAttribute("data-a"),10),b=parseInt(e.target.getAttribute("data-b"),10);
  var idxs=[];
  for(var i=0;i<last.length;i++){if(last[i].show)idxs.push(i)}
  var range=idxs.slice(a-1,b),keys=range.map(function(i){return last[i].key});
  var allChecked=keys.every(function(k){return checkedSet[k]});
  keys.forEach(function(k){checkedSet[k]=!allChecked});
  render(curResults);
  updateDlBtn();
  st.innerHTML=(allChecked?"已取消勾选 ":"已勾选 ")+"第 "+a+"-"+b+" 个目标（共 "+keys.length+" 条）";
});
document.getElementById("box").addEventListener("click",function(e){
  var t=e.target;
  if(t.classList&&t.classList.contains("sortable")){
    var k=t.getAttribute("data-key");
    if(sortKey===k)sortDir*=-1;
    else{sortKey=k;sortDir=(k==="mbps"?-1:1)}
    render(curResults);
  }
});
document.getElementById("copy").onclick=function(){
  var st=document.getElementById("status");
  var selKeys=Object.keys(checkedSet).filter(function(k){return checkedSet[k]});
  var lines,tag;
  if(selKeys.length){
    lines=last.filter(function(item){return checkedSet[item.key]}).map(function(r){return r.text});
    tag="勾选的 "+lines.length+" 条";
  }else{
    lines=last.filter(function(r){return r.show}).map(function(r){return r.text});
    tag="全部 "+lines.length+" 条";
  }
  if(!lines.length){
    st.innerHTML="<b style='color:#dc2626'>没有可复制的结果</b>";
    return;
  }
  var text=lines.join("\\n");
  function done(){st.innerHTML="已复制 <b>"+tag+"</b>（IP:端口 [优选 延迟 带宽] 格式，可直接粘贴到优选IP替代工具）";}
  function fail(){
    var ta=document.createElement("textarea");
    ta.value=text;document.body.appendChild(ta);ta.select();
    var ok=false;
    try{ok=document.execCommand("copy");}catch(e){}
    document.body.removeChild(ta);
    if(ok)done();
    else st.innerHTML="<b style='color:#dc2626'>复制失败，请手动选择结果复制</b>";
  }
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(done,fail);
  }else{fail();}
};
var last=[];
var curResults=[];
var baseResults=null;
var selecting=false;
var checkedSet={};
function poll(){
    fetch("/api/progress").then(function(r){return r.json()}).then(function(d){
      var st=document.getElementById("status");
      var dlPhase=(d.phase==="下载测速");
      var okN=dlPhase?(d.dl_ok||0):(d.ok||0);
      var failN=dlPhase?(d.dl_fail||0):(d.fail||0);
      if(d.error){st.innerHTML="<b style='color:#dc2626'>出错: "+d.error+"</b>"}
      else if(d.running){st.innerHTML=d.phase+" <b>"+d.done+"</b> / "+d.total+"（成功 "+okN+" · 失败 "+failN+"）"}
      else{
        st.innerHTML="完成：成功 <b>"+(d.ok||0)+"</b> · 失败 <b>"+(d.fail||0)+"</b>"
          +((d.dl_ok||d.dl_fail)?"；带宽实测成功 <b>"+d.dl_ok+"</b> · 失败 <b>"+d.dl_fail+"</b>":"")
          +(d.fail||d.dl_fail?"（失败原因见运行日志）":"");
      }
      var lg=document.getElementById("log");
      if(d.log&&d.log.length){lg.textContent=d.log.join("\\n");lg.scrollTop=lg.scrollHeight;
        document.getElementById("logpanel").open=d.running||(d.fail>0);}
      document.getElementById("bar").style.display=d.running?"block":"none";
    if(d.total>0){document.getElementById("barin").style.width=(d.done/d.total*100)+"%"}
    document.getElementById("stop").disabled=!d.running;
    if(!d.running&&selecting){
      selecting=false;
      (d.results||[]).forEach(function(r){
        var hit=null;
        for(var i=0;i<baseResults.length;i++){
          if(baseResults[i].host===r.host&&baseResults[i].port===r.port){hit=baseResults[i];break}
        }
        if(hit)hit.mbps=r.mbps;else baseResults.push(r);
      });
      baseResults.sort(function(a,b){return(a.tls!=null?a.tls:1e9)-(b.tls!=null?b.tls:1e9)});
      curResults=baseResults;
      st.innerHTML="⚡ 带宽实测完成，已合并进结果表（勾选状态保留）";
      document.getElementById("start").disabled=false;
      document.getElementById("btn-dl").disabled=false;
      document.getElementById("copy").disabled=false;
      render(curResults);
      return;
    }
    if(!d.running){
      document.getElementById("start").disabled=false;
      document.getElementById("btn-dl").disabled=!(d.results&&d.results.length);
      render(d.results);return}
    if(!selecting){curResults=d.results;render(d.results);}
    timer=setTimeout(poll,500);
  }).catch(function(){timer=setTimeout(poll,1000)});
}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){
  return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
var sortKey=null,sortDir=1;
function render(results){
  curResults=results;
  document.getElementById("result-count").textContent=results.length?("（"+results.length+" 条）"):"";
  var order=[];
  for(var i=0;i<results.length;i++)order.push(i);
  if(sortKey){
    order.sort(function(a,b){
      var va=results[a][sortKey],vb=results[b][sortKey];
      if(va==null)va=(sortKey==="mbps"?-1e9:1e9);
      if(vb==null)vb=(sortKey==="mbps"?-1e9:1e9);
      return(va-vb)*sortDir;
    });
  }
  last=[];
  order.forEach(function(idx){
    var r=results[idx];
    var show=true;
    if(r.mbps===null||r.mbps===undefined){
      if(modeCur()==="dl")show=false;
      else show=(+val("f_tls")<=0||r.tls<=+val("f_tls"));
    }else{show=(+val("f_mbps")<=0||r.mbps>=+val("f_mbps"))}
    var text=r.host+":"+r.port+" [优选 "
      +(r.tls!=null?r.tls.toFixed(2)+"ms":"-")+" "
      +(r.mbps!=null?r.mbps.toFixed(2)+"Mbps":"-")+"]";
    last.push({show:show,text:text,key:r.host+":"+r.port});
  });
  document.getElementById("copy").disabled=!last.some(function(r){return r.show});
  var box=document.getElementById("box");
  if(!last.length){box.innerHTML='<div class="empty">还没有结果</div>';
    document.getElementById("quick-sel").innerHTML="";return}
  function arrow(k){return sortKey===k?(sortDir===1?" ▲":" ▼"):" ↕"}
  var rows=last.map(function(item,di){
    var r=results[order[di]];
    if(!item.show)return"";
    var k=item.key;
    return"<tr><td><input type='checkbox' class='rowck' data-k='"+k+"'"+(checkedSet[k]?" checked":"")+"></td>"
      +"<td class='mono'>"+(di+1)+"</td>"
      +"<td class='mono'>"+esc(r.host)+"</td><td>"+r.port+"</td>"
      +"<td class='mono'>"+(r.tcp!=null?r.tcp.toFixed(0):"-")+"</td>"
      +"<td class='mono'>"+(r.tls!=null?r.tls.toFixed(0):"-")+"</td>"
      +"<td class='mono'>"+(r.mbps!=null?r.mbps:"-")+"</td></tr>";
  }).join("");
  box.innerHTML='<div style="overflow:auto;max-height:60vh;border:1px solid var(--line);border-radius:10px"><table><thead><tr><th style="width:34px"><input type="checkbox" class="ck-all"></th><th style="width:44px">#</th><th>目标</th><th>端口</th>'
    +'<th>TCP(ms)</th><th class="sortable" data-key="tls" style="cursor:pointer">TLS/握手(ms)'+arrow("tls")+'</th><th class="sortable" data-key="mbps" style="cursor:pointer">Mbps'+arrow("mbps")+'</th></tr></thead><tbody>'
    +rows+"</tbody></table></div>";
  var qs=document.getElementById("quick-sel"),idxs=[];
  for(var i=0;i<last.length;i++){if(last[i].show)idxs.push(i)}
  var h="";
  if(idxs.length>8){
    var n=Math.ceil(idxs.length/100);
    for(var c=0;c<n;c++){
      var a=c*100+1,b=Math.min((c+1)*100,idxs.length);
      h+='<button type="button" class="qbtn" data-act="range" data-a="'+a+'" data-b="'+b+'">勾选 '+a+'-'+b+'</button>';
    }
  }
  h+='<button type="button" class="qbtn" data-act="invert">反选</button>';
  h+='<button type="button" class="qbtn" data-act="clear">清空已选</button>';
  qs.innerHTML="<span style='font-size:13px;color:var(--muted);align-self:center'>快捷勾选：</span>"+h;
}
function modeCur(){return mode}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------- HTTP 服务

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默访问日志
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/progress":
            with LOCK:
                snap = {k: JOB[k] for k in
                        ("running", "phase", "done", "total", "results", "error",
                         "sni", "ok", "fail", "dl_ok", "dl_fail", "log")}
            self._json(snap)
        else:
            self.send_error(404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            data = {}
        if self.path == "/api/start":
            if JOB["running"]:
                self._json({"ok": False, "error": "已有任务在跑"})
            else:
                threading.Thread(target=run_job, args=(data,), daemon=True).start()
                self._json({"ok": True})
        elif self.path == "/api/stop":
            JOB["stop"] = True
            self._json({"ok": True})
        else:
            self.send_error(404)


def main():
    srv = None
    port = None
    # Windows 上禁用 SO_REUSEADDR（它允许两个实例同时绑同一端口，请求会串到旧实例）
    socketserver.TCPServer.allow_reuse_address = (os.name != "nt")
    for p in PORT_CANDIDATES:
        try:
            srv = http.server.ThreadingHTTPServer((HOST, p), Handler)
            port = p
            break
        except OSError:
            continue
    if srv is None:
        print("8765-8775 端口都被占用：可能已有一个实例在跑。")
        print("  浏览器直接访问 http://127.0.0.1:8765 即可使用旧实例，")
        print("  或先关闭旧的命令行窗口再启动本程序。")
        return
    url = "http://%s:%d" % (HOST, port)
    print("=" * 46)
    print("  优选IP 精测工具 已启动")
    print("  浏览器访问: " + url)
    if port != PORT_CANDIDATES[0]:
        print("  注意: 默认端口被占用, 已自动改用 %d" % port)
    print("  关闭本窗口(或 Ctrl+C) 即退出")
    print("=" * 46)
    threading.Timer(0.8, webbrowser.open, args=[url]).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")


if __name__ == "__main__":
    main()
