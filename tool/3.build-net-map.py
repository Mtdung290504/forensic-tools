import json
import ipaddress
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from collections import defaultdict

from config import VOLATILITY_PATH, OUTPUT_DIR

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

NETSCAN_JSON = OUTPUT_DIR / "netscan.json"
NETSCAN_DIR = OUTPUT_DIR / "netscan"
DETAIL_DIR = NETSCAN_DIR / "detail"
MD_INDEX = NETSCAN_DIR / "Network_Map.md"
IP_CACHE_JSON = NETSCAN_DIR / "ip_cache.json"
FLAGGED_PIDS_JSON = OUTPUT_DIR / "flagged_pids.json"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

NOISE_LOCAL_PORTS = {7, 9, 13, 17, 19}

COMMON_FOREIGN_PORTS = {
    80,
    443,
    53,
    67,
    68,
    123,
    135,
    137,
    138,
    139,
    445,
    5353,
}

# Org substring → nhãn thân thiện (match case-insensitive)
KNOWN_ORGS = {
    "google": "Google",
    "amazon": "Amazon/AWS",
    "akamai": "Akamai CDN",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly CDN",
    "microsoft": "Microsoft",
    "facebook": "Meta/Facebook",
    "apple": "Apple",
    "mozilla": "Mozilla",
    "cdn": "CDN",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_public_ip(ip):
    if not ip or ip in {"*", "0.0.0.0", "::"}:
        return False
    try:
        obj = ipaddress.ip_address(ip)
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_multicast
            or obj.is_link_local
            or obj.is_reserved
        )
    except ValueError:
        return False


def is_wildcard(addr):
    return not addr or addr in {"0.0.0.0", "::", "*"}


def save_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_flagged_pids():
    if not FLAGGED_PIDS_JSON.exists():
        return {}
    with open(FLAGGED_PIDS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# IP enrichment — ip-api.com batch (free, no key, max 100/req)
# ---------------------------------------------------------------------------


def load_ip_cache():
    if IP_CACHE_JSON.exists():
        with open(IP_CACHE_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def friendly_org(org_str):
    """Rút gọn tên org thành nhãn thân thiện nếu nhận ra, giữ nguyên nếu không."""
    if not org_str:
        return "Unknown"
    lower = org_str.lower()
    for keyword, label in KNOWN_ORGS.items():
        if keyword in lower:
            return label
    return org_str


def enrich_ips(public_ips):
    """
    Gọi ip-api.com/batch để tra ASN + org cho danh sách IP public.
    Trả về dict { ip: { "org": ..., "country": ..., "label": ... } }
    Dùng cache để tránh gọi lại IP đã tra.
    """
    cache = load_ip_cache()
    to_lookup = [ip for ip in public_ips if ip not in cache]

    if not to_lookup:
        print(f"[+] IP cache hit: {len(cache)} IPs, không cần gọi API.")
        return cache

    print(f"[+] Tra cứu {len(to_lookup)} IP mới qua ip-api.com...")

    # ip-api batch: tối đa 100 IP/request
    BATCH = 100
    for i in range(0, len(to_lookup), BATCH):
        batch = to_lookup[i : i + BATCH]
        payload = json.dumps(
            [{"query": ip, "fields": "query,org,country,as,status"} for ip in batch]
        ).encode("utf-8")

        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                results = json.loads(resp.read().decode("utf-8"))

            for r in results:
                ip = r.get("query")
                if r.get("status") == "success":
                    org = r.get("org") or r.get("as") or ""
                    cache[ip] = {
                        "org": org,
                        "label": friendly_org(org),
                        "country": r.get("country", ""),
                        "as": r.get("as", ""),
                    }
                else:
                    cache[ip] = {
                        "org": "",
                        "label": "Lookup failed",
                        "country": "",
                        "as": "",
                    }

            # ip-api free: 45 req/min → chờ nếu có nhiều batch
            if i + BATCH < len(to_lookup):
                time.sleep(1.5)

        except urllib.error.URLError as ex:
            print(f"[-] Không gọi được ip-api.com: {ex}. Bỏ qua enrich.")
            break

    save_json(IP_CACHE_JSON, cache)
    print(f"[+] Đã tra {len(to_lookup)} IP, cache tổng: {len(cache)}")
    return cache


# ---------------------------------------------------------------------------
# Volatility
# ---------------------------------------------------------------------------


def run_volatility(image_path):
    print("[+] Đang chạy windows.netscan...")
    NETSCAN_DIR.mkdir(parents=True, exist_ok=True)
    with open(NETSCAN_JSON, "w", encoding="utf-8") as out:
        subprocess.run(
            [
                "python",
                str(VOLATILITY_PATH),
                "-f",
                image_path,
                "-r",
                "json",
                "windows.netscan",
            ],
            stdout=out,
        )


# ---------------------------------------------------------------------------
# Load + deduplicate
# ---------------------------------------------------------------------------


def load_netscan():
    for enc in ("utf-8", "utf-16"):
        try:
            with open(NETSCAN_JSON, "r", encoding=enc) as f:
                data = json.load(f)
            print(f"[+] Loaded {len(data)} entries (encoding: {enc})")
            return data
        except Exception:
            continue
    raise RuntimeError("Không đọc được netscan.json")


def deduplicate(data):
    seen = set()
    result = []
    for e in data:
        key = (
            e.get("PID"),
            e.get("Proto"),
            e.get("LocalAddr"),
            e.get("LocalPort"),
            e.get("ForeignAddr"),
            e.get("ForeignPort"),
            e.get("State"),
        )
        if key not in seen:
            seen.add(key)
            result.append(e)
    return result


# ---------------------------------------------------------------------------
# Tag priority — không bỏ gì, chỉ đánh cờ
# ---------------------------------------------------------------------------

SYSTEM_OWNERS = {
    "system",
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "csrss.exe",
}


def tag_priority(e, flagged_pids):
    """
    Trả về (priority, [reasons])
      high   — flagged process từ bước 3, hoặc public IP + foreign port lạ
      medium — public IP bất kỳ, state đang đóng dở, CLOSED từng có public
      low    — localhost, system process internal, mDNS/SSDP noise
    Không bỏ entry nào.
    """
    state = (e.get("State") or "").upper()
    local_port = e.get("LocalPort")
    foreign_addr = e.get("ForeignAddr") or ""
    foreign_port = e.get("ForeignPort")
    owner = (e.get("Owner") or "").lower()
    pid = str(e.get("PID") or "")
    proto = (e.get("Proto") or "").upper()

    # HIGH
    high = []
    if pid in flagged_pids:
        high.append("flagged_process")
    if (
        is_public_ip(foreign_addr)
        and foreign_port
        and foreign_port not in COMMON_FOREIGN_PORTS
    ):
        high.append("unusual_foreign_port")
    if high:
        return "high", high

    # LOW
    low = []
    if local_port in NOISE_LOCAL_PORTS:
        low.append("noise_port")
    if foreign_addr.startswith("127.") or foreign_addr == "::1":
        low.append("localhost")
    if owner in SYSTEM_OWNERS and not is_public_ip(foreign_addr):
        low.append("system_internal")
    if "V6" in proto and local_port in {5353, 1900, 3702}:
        low.append("mdns_ssdp")
    if low:
        return "low", low

    # MEDIUM
    med = []
    if is_public_ip(foreign_addr):
        med.append("public_ip")
    if state in {"FIN_WAIT2", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT"}:
        med.append(f"state_{state.lower()}")
    if state == "CLOSED" and is_public_ip(foreign_addr):
        med.append("closed_had_public")
    return "medium", med or ["other"]


# ---------------------------------------------------------------------------
# Classify + enrich
# ---------------------------------------------------------------------------


def classify(data, flagged_pids, ip_info):
    groups = {
        "high": [],
        "medium": [],
        "low": [],
    }

    for e in data:
        foreign_addr = e.get("ForeignAddr")
        pid = str(e.get("PID") or "")
        proto = (e.get("Proto") or "").upper()

        # Enrich IP
        if is_public_ip(foreign_addr) and foreign_addr in ip_info:
            info = ip_info[foreign_addr]
            e["_org"] = info.get("org", "")
            e["_label"] = info.get("label", "")
            e["_country"] = info.get("country", "")
            e["_as"] = info.get("as", "")

        # Gắn process flags
        if pid in flagged_pids:
            e["_process_flags"] = flagged_pids[pid]

        # Tag priority
        priority, reasons = tag_priority(e, flagged_pids)
        e["_priority"] = priority
        e["_reasons"] = reasons
        groups[priority].append(e)

    return groups


# ---------------------------------------------------------------------------
# Render HTML
# ---------------------------------------------------------------------------

HTML_OUTPUT = NETSCAN_DIR / "Network_Map.html"


def entry_filename(idx):
    return f"entry_{idx:04d}.json"


def build_html(all_entries, summary):
    DETAIL_DIR.mkdir(parents=True, exist_ok=True)
    for i, e in enumerate(all_entries):
        save_json(DETAIL_DIR / entry_filename(i), e)

    rows_js = json.dumps(all_entries, ensure_ascii=False)
    summary_js = json.dumps(summary, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>Network Map — Memory Forensics</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0d1117;--surface:#161b22;--border:#30363d;
  --text:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;
  --high:#f85149;--medium:#e3b341;--low-text:#656d76;--low-bg:#1c2128;
  --green:#3fb950;--purple:#bc8cff;
}}
body{{background:var(--bg);color:var(--text);font-family:'IBM Plex Sans',sans-serif;font-size:13px;min-height:100vh}}
header{{padding:20px 28px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
header h1{{font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:700;color:#fff;flex:1}}
.chip{{background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:3px 11px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted)}}
.chip b{{color:var(--text)}}
.filterbar{{padding:10px 28px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:var(--surface);position:sticky;top:0;z-index:100}}
.filterbar label{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-right:2px}}
.sep{{width:1px;height:18px;background:var(--border);margin:0 4px}}
.btn{{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600;padding:4px 12px;border-radius:5px;border:1.5px solid transparent;cursor:pointer;transition:all .15s;user-select:none}}
.btn.high{{border-color:var(--high);color:var(--high);background:transparent}}
.btn.medium{{border-color:var(--medium);color:var(--medium);background:transparent}}
.btn.low{{border-color:var(--border);color:var(--low-text);background:transparent}}
.btn.proc{{border-color:var(--purple);color:var(--purple);background:transparent}}
.btn.public{{border-color:var(--accent);color:var(--accent);background:transparent}}
.btn.active.high{{background:var(--high);color:#fff}}
.btn.active.medium{{background:var(--medium);color:#000}}
.btn.active.low{{background:var(--border);color:var(--text)}}
.btn.active.proc{{background:var(--purple);color:#000}}
.btn.active.public{{background:var(--accent);color:#000}}
.search{{margin-left:auto;background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:4px 11px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:12px;width:210px;outline:none}}
.search:focus{{border-color:var(--accent)}}
.count{{padding:7px 28px;font-size:11px;color:var(--muted);font-family:'JetBrains Mono',monospace}}
.wrap{{overflow-x:auto;padding:0 28px 28px}}
table{{width:100%;border-collapse:collapse;margin-top:12px;font-family:'JetBrains Mono',monospace;font-size:12px}}
thead th{{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.8px;white-space:nowrap}}
tbody tr{{border-bottom:1px solid #1c2128;transition:background .1s}}
tbody tr:hover{{background:#1c2128}}
tbody tr.hidden{{display:none}}
td{{padding:6px 10px;vertical-align:middle;white-space:nowrap}}
.badge{{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}}
.badge.high{{background:#3d1a19;color:var(--high)}}
.badge.medium{{background:#2d2006;color:var(--medium)}}
.badge.low{{background:var(--low-bg);color:var(--low-text)}}
.sc{{display:inline-block;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:600}}
.sc-established{{background:#0d2119;color:var(--green)}}
.sc-listening{{background:#0d1c2d;color:var(--accent)}}
.sc-closed{{background:#1c2128;color:var(--muted)}}
.sc-fin_wait2,.sc-time_wait,.sc-close_wait{{background:#2d2006;color:var(--medium)}}
.sc-syn_sent{{background:#2d1a00;color:#f0883e}}
.sc-other{{background:#1c2128;color:var(--muted)}}
.pflag{{display:inline-block;padding:2px 5px;border-radius:3px;background:#1e1232;color:var(--purple);font-size:10px;margin-right:2px}}
.rtag{{display:inline-block;padding:2px 5px;border-radius:3px;background:#161b22;color:var(--muted);font-size:10px;border:1px solid var(--border);margin-right:2px}}
.org-link{{color:var(--accent);text-decoration:none;border-bottom:1px dotted var(--accent)}}
.org-link:hover{{color:#fff;border-color:#fff}}
.jlink{{color:var(--muted);text-decoration:none;font-size:10px;padding:2px 5px;border:1px solid var(--border);border-radius:3px;transition:all .1s}}
.jlink:hover{{color:var(--text);border-color:var(--muted)}}
.empty{{text-align:center;padding:40px;color:var(--muted);display:none}}
</style>
</head>
<body>
<header>
  <h1>⬡ NETWORK MAP</h1>
  <div class="chip">raw <b id="s-raw"></b></div>
  <div class="chip">dedup <b id="s-dedup"></b></div>
  <div class="chip" style="border-color:#f8514940;color:var(--high)">high <b id="s-high"></b></div>
  <div class="chip" style="border-color:#e3b34140;color:var(--medium)">medium <b id="s-medium"></b></div>
  <div class="chip" style="color:var(--low-text)">low <b id="s-low"></b></div>
</header>
<div class="filterbar">
  <label>Priority</label>
  <button class="btn high active"   data-filter="high"   onclick="toggleP(this)">🔴 High</button>
  <button class="btn medium active" data-filter="medium" onclick="toggleP(this)">🟡 Medium</button>
  <button class="btn low"           data-filter="low"    onclick="toggleP(this)">⚪ Low</button>
  <div class="sep"></div>
  <label>Quick</label>
  <button class="btn proc"   data-filter="flagged_process" onclick="toggleR(this)">⚑ Proc flagged</button>
  <button class="btn public" data-filter="public_ip"       onclick="toggleR(this)">🌐 Public IP</button>
  <input class="search" type="text" placeholder="Search PID / owner / IP..." oninput="apply()">
</div>
<div class="count">Showing <b id="vis">0</b> of <b id="tot">0</b> entries</div>
<div class="wrap">
<table>
  <thead><tr>
    <th>Priority</th><th>PID</th><th>Owner</th><th>Proto</th>
    <th>Local</th><th>Foreign IP</th><th>F.Port</th>
    <th>Org</th><th>State</th><th>Reasons</th><th>Proc Flags</th><th>Detail</th>
  </tr></thead>
  <tbody id="tb"></tbody>
</table>
<div class="empty" id="empty">No entries match current filters.</div>
</div>
<script>
const ROWS={rows_js};
const SUM={summary_js};
document.getElementById('s-raw').textContent   = SUM.total_raw    ?? '-';
document.getElementById('s-dedup').textContent = SUM.after_dedup  ?? '-';
document.getElementById('s-high').textContent  = SUM.high         ?? '-';
document.getElementById('s-medium').textContent= SUM.medium        ?? '-';
document.getElementById('s-low').textContent   = SUM.low           ?? '-';
function sc(s){{
  if(!s)return'sc-other';
  const m={{'ESTABLISHED':'sc-established','LISTENING':'sc-listening','CLOSED':'sc-closed',
    'FIN_WAIT2':'sc-fin_wait2','TIME_WAIT':'sc-time_wait','CLOSE_WAIT':'sc-close_wait','SYN_SENT':'sc-syn_sent'}};
  return m[s.toUpperCase()]||'sc-other';
}}
const tb=document.getElementById('tb');
ROWS.forEach((e,i)=>{{
  const p=e._priority||'low';
  const r=(e._reasons||[]).join(' ');
  const pf=e._process_flags||[];
  const label=e._label||'';
  const org=e._org||'';
  const country=e._country?` (${{e._country}})`:'';
  const state=e.State||'';
  const local=`${{e.LocalAddr||'*'}}:${{e.LocalPort||'*'}}`;
  const fip=e.ForeignAddr||'*';
  const fp=e.ForeignPort||'*';
  const df=`detail/entry_${{String(i).padStart(4,'0')}}.json`;
  const orgHTML=label||org
    ?`<a class="org-link" href="https://www.google.com/search?q=${{encodeURIComponent((label||org)+' IP range')}}" target="_blank">${{label||org}}</a>${{country}}`
    :'';
  const rtags=(e._reasons||[]).map(x=>`<span class="rtag">${{x}}</span>`).join('');
  const ptags=pf.map(x=>`<span class="pflag">${{x}}</span>`).join('');
  const tr=document.createElement('tr');
  tr.dataset.priority=p;
  tr.dataset.reasons=r;
  tr.dataset.search=[e.PID,e.Owner,fip,e.LocalAddr,state,label,org].join(' ').toLowerCase();
  tr.innerHTML=`
    <td><span class="badge ${{p}}">${{p.toUpperCase()}}</span></td>
    <td>${{e.PID??''}}</td><td>${{e.Owner||'?'}}</td><td>${{e.Proto||''}}</td>
    <td>${{local}}</td><td>${{fip}}</td><td>${{fp}}</td>
    <td>${{orgHTML}}</td>
    <td><span class="sc ${{sc(state)}}">${{state}}</span></td>
    <td>${{rtags}}</td><td>${{ptags}}</td>
    <td><a class="jlink" href="${{df}}" target="_blank">JSON</a></td>`;
  tb.appendChild(tr);
}});
document.getElementById('tot').textContent=ROWS.length;
const AP=new Set(['high','medium']);
const AR=new Set();
function toggleP(btn){{
  const f=btn.dataset.filter;
  AP.has(f)?AP.delete(f):AP.add(f);
  btn.classList.toggle('active');
  apply();
}}
function toggleR(btn){{
  const f=btn.dataset.filter;
  AR.has(f)?AR.delete(f):AR.add(f);
  btn.classList.toggle('active');
  apply();
}}
function apply(){{
  const q=document.querySelector('.search').value.toLowerCase();
  let v=0;
  document.querySelectorAll('#tb tr').forEach(tr=>{{
    const ok=AP.has(tr.dataset.priority)
      &&(AR.size===0||[...AR].some(r=>tr.dataset.reasons.includes(r)))
      &&(!q||tr.dataset.search.includes(q));
    tr.classList.toggle('hidden',!ok);
    if(ok)v++;
  }});
  document.getElementById('vis').textContent=v;
  document.getElementById('empty').style.display=v===0?'block':'none';
}}
apply();
</script>
</body></html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def clean_old_workspace():
    import shutil

    print("[+] Đang dọn dẹp workspace cũ...")
    if NETSCAN_DIR.exists():
        shutil.rmtree(NETSCAN_DIR)
    NETSCAN_DIR.mkdir(parents=True, exist_ok=True)
    DETAIL_DIR.mkdir(parents=True, exist_ok=True)
    if NETSCAN_JSON.exists():
        NETSCAN_JSON.unlink()
    print("[+] Workspace sạch!")


def analyze(image_path):
    clean_old_workspace()
    run_volatility(image_path)

    raw = load_netscan()
    deduped = deduplicate(raw)

    public_ips = list(
        {e.get("ForeignAddr") for e in deduped if is_public_ip(e.get("ForeignAddr"))}
    )
    ip_info = enrich_ips(public_ips)

    flagged_pids = load_flagged_pids()
    groups = classify(deduped, flagged_pids, ip_info)

    all_tagged = groups["high"] + groups["medium"] + groups["low"]

    summary = {
        "total_raw": len(raw),
        "after_dedup": len(deduped),
        "high": len(groups["high"]),
        "medium": len(groups["medium"]),
        "low": len(groups["low"]),
    }
    save_json(NETSCAN_DIR / "summary.json", summary)

    html = build_html(all_tagged, summary)
    with open(HTML_OUTPUT, "w", encoding="utf-8") as f:
        f.write(html)

    print("\n========== SUMMARY ==========")
    for k, v in summary.items():
        print(f"  {k:25}: {v}")
    print(f"\n[✓] HTML   : {HTML_OUTPUT}")
    print(f"    Detail : {DETAIL_DIR}/")
    print(f"    Cache  : {IP_CACHE_JSON}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Cách dùng: python netscan_analyzer.py <đường_dẫn_file_ram>")
        sys.exit(1)
    analyze(sys.argv[1])
