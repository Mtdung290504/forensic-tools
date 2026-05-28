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
# Filter noise
# ---------------------------------------------------------------------------


def filter_noise(data):
    result = []
    for e in data:
        state = (e.get("State") or "").upper()
        local_port = e.get("LocalPort")
        local_addr = e.get("LocalAddr")
        foreign_addr = e.get("ForeignAddr")

        if state == "CLOSED":
            continue
        if local_port in NOISE_LOCAL_PORTS:
            continue
        if (
            state == "LISTENING"
            and is_wildcard(local_addr)
            and is_wildcard(foreign_addr)
        ):
            continue

        result.append(e)
    return result


# ---------------------------------------------------------------------------
# Classify + enrich
# ---------------------------------------------------------------------------


def classify(data, flagged_pids, ip_info):
    groups = {
        "established": [],
        "public_ip": [],
        "suspicious_port": [],
        "flagged_process": [],
        "listening": [],
        "ipv6": [],
    }

    for e in data:
        state = (e.get("State") or "").upper()
        foreign_addr = e.get("ForeignAddr")
        foreign_port = e.get("ForeignPort")
        proto = (e.get("Proto") or "").upper()
        pid = str(e.get("PID") or "")

        # Gắn IP info vào entry nếu có
        if is_public_ip(foreign_addr) and foreign_addr in ip_info:
            info = ip_info[foreign_addr]
            e["_org"] = info.get("org", "")
            e["_label"] = info.get("label", "")
            e["_country"] = info.get("country", "")
            e["_as"] = info.get("as", "")

        if state in {"ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"}:
            groups["established"].append(e)

        if is_public_ip(foreign_addr):
            groups["public_ip"].append(e)

        if (
            foreign_port
            and not is_wildcard(foreign_addr)
            and foreign_port not in COMMON_FOREIGN_PORTS
        ):
            groups["suspicious_port"].append(e)

        if pid in flagged_pids:
            e["_process_flags"] = flagged_pids[pid]
            groups["flagged_process"].append(e)

        if state == "LISTENING":
            groups["listening"].append(e)

        if "V6" in proto:
            groups["ipv6"].append(e)

    return groups


# ---------------------------------------------------------------------------
# Render markdown
# ---------------------------------------------------------------------------

TABLE_HEADER = (
    "| PID | Owner | Proto | Local | Foreign IP | Port | Org | State | Ghi chú |\n"
    "|-----|-------|-------|-------|------------|------|-----|-------|----------|\n"
)


def row(e, note=""):
    pid = e.get("PID", "")
    owner = e.get("Owner") or "?"
    proto = e.get("Proto") or ""
    local = f"{e.get('LocalAddr')}:{e.get('LocalPort')}"
    foreign_addr = e.get("ForeignAddr") or "*"
    foreign_port = e.get("ForeignPort") or "*"
    state = e.get("State") or ""
    org = e.get("_label") or ""
    proc_flags = e.get("_process_flags", [])
    flag_str = " ".join(proc_flags) if proc_flags else ""
    full_note = f"{note} {flag_str}".strip()
    return (
        f"| {pid} | {owner} | {proto} | {local} | "
        f"{foreign_addr} | {foreign_port} | {org} | {state} | {full_note} |\n"
    )


def section(title, entries, note_fn=None):
    if not entries:
        return f"### {title}\n\n_Không có._\n\n"
    md = f"### {title} ({len(entries)})\n\n"
    md += TABLE_HEADER
    for e in entries:
        note = note_fn(e) if note_fn else ""
        md += row(e, note)
    md += "\n"
    return md


def build_index(groups, summary):
    md = "# NETWORK MAP\n\n"
    md += "> **Cờ process:** kế thừa từ bước 3 (map_builder)\n\n"

    md += "## Summary\n\n"
    md += "| Nhóm | Số lượng |\n|------|----------|\n"
    for k, v in summary.items():
        md += f"| {k} | {v} |\n"
    md += "\n---\n\n"

    md += "## Chi tiết\n\n"

    md += section(
        "🔴 Tiến trình bị gắn cờ từ bước 3",
        groups["flagged_process"],
        note_fn=lambda e: " ".join(e.get("_process_flags", [])),
    )
    md += section("🌐 Public IP", groups["public_ip"])
    md += section("⚡ ESTABLISHED / SYN_SENT / CLOSE_WAIT", groups["established"])
    md += section(
        "🟡 Foreign port không phổ biến",
        groups["suspicious_port"],
        note_fn=lambda e: f"port {e.get('ForeignPort')}",
    )
    md += section("👂 Listening", groups["listening"])
    md += section("IPv6", groups["ipv6"])

    return md


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
    filtered = filter_noise(deduped)

    # Thu thập tất cả public IP để enrich một lần
    public_ips = list(
        {e.get("ForeignAddr") for e in filtered if is_public_ip(e.get("ForeignAddr"))}
    )
    ip_info = enrich_ips(public_ips)

    flagged_pids = load_flagged_pids()
    groups = classify(filtered, flagged_pids, ip_info)

    for name, entries in groups.items():
        save_json(DETAIL_DIR / f"{name}.json", entries)

    summary = {
        "total_raw": len(raw),
        "after_dedup": len(deduped),
        "after_filter": len(filtered),
        **{k: len(v) for k, v in groups.items()},
    }
    save_json(NETSCAN_DIR / "summary.json", summary)

    md = build_index(groups, summary)
    with open(MD_INDEX, "w", encoding="utf-8") as f:
        f.write(md)

    print("\n========== SUMMARY ==========")
    for k, v in summary.items():
        print(f"  {k:25}: {v}")
    print(f"\n[✓] Index  : {MD_INDEX}")
    print(f"    Detail : {DETAIL_DIR}/")
    print(f"    Cache  : {IP_CACHE_JSON}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Cách dùng: python netscan_analyzer.py <đường_dẫn_file_ram>")
        sys.exit(1)
    analyze(sys.argv[1])
