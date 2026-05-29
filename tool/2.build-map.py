import subprocess
import json
import sys
import shutil
from collections import defaultdict
from datetime import datetime

from config import (
    VOLATILITY_PATH,
    OUTPUT_DIR,
    ORPHAN_WHITELIST,
    SUSPICIOUS_PATH_KEYWORDS,
    SAFE_PATH_PREFIXES,
)

PSTREE_JSON = OUTPUT_DIR / "pstree.json"
PSSCAN_JSON = OUTPUT_DIR / "psscan.json"
MALFIND_JSON = OUTPUT_DIR / "malfind.json"
RAW_NODES_DIR = OUTPUT_DIR / "raw_nodes"
HTML_OUTPUT = OUTPUT_DIR / "Process_Map.html"


def is_suspicious_path(path):
    if not path:
        return False
    p = path.lower()
    # Nếu bắt đầu bằng safe prefix → bỏ qua keyword check
    for safe in SAFE_PATH_PREFIXES:
        if p.startswith(safe):
            return False
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in p:
            return True
    return False


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


def clean_old_workspace():
    print("[+] Đang dọn dẹp workspace cũ...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for f in [PSTREE_JSON, PSSCAN_JSON, MALFIND_JSON, HTML_OUTPUT]:
        if f.exists():
            f.unlink()
    if RAW_NODES_DIR.exists():
        shutil.rmtree(RAW_NODES_DIR)
    RAW_NODES_DIR.mkdir(parents=True, exist_ok=True)
    print("[+] Workspace sạch!")


# ---------------------------------------------------------------------------
# Volatility helpers
# ---------------------------------------------------------------------------


def _run_vol(image_path, plugin, out_path, extra_args=None):
    cmd = ["python", str(VOLATILITY_PATH), "-f", image_path, "-r", "json", plugin]
    if extra_args:
        cmd.extend(extra_args)
    with open(out_path, "w", encoding="utf-8") as out:
        subprocess.run(cmd, stdout=out)


def load_vol_json(filepath):
    if not filepath.exists():
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        start_idx = content.find("[")
        if start_idx == -1:
            start_idx = content.find("{")
        if start_idx != -1:
            return json.loads(content[start_idx:])
        return []
    except Exception as e:
        print(f"[-] Lỗi đọc JSON từ {filepath.name}: {e}")
        return []


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------


def flatten_pstree(nodes, result=None):
    if result is None:
        result = {}
    for node in nodes:
        pid = str(node.get("PID", "N/A"))
        children = node.get("__children", [])
        result[pid] = {k: v for k, v in node.items() if k != "__children"}
        if children:
            flatten_pstree(children, result)
    return result


def get_best_path(rec):
    raw_path = str(rec.get("Path") or "").lower().strip()
    audit_path = str(rec.get("Audit") or "").lower().strip()
    best = raw_path if raw_path and raw_path != "null" else audit_path
    if best.startswith("\\device\\harddiskvolume"):
        parts = best.split("\\", 3)
        if len(parts) >= 4:
            return "c:\\" + parts[3]
    return best


def build_duplicate_index(flat_processes):
    name_groups = defaultdict(list)
    for pid, rec in flat_processes.items():
        name = str(rec.get("ImageFileName", "")).lower()
        path = get_best_path(rec)
        name_groups[name].append((pid, path))
    flagged = set()
    for name, members in name_groups.items():
        paths = {p for _, p in members if p}
        if len(paths) > 1:
            for pid, _ in members:
                flagged.add(pid)
    return flagged


def build_malfind_index():
    malfind_map = defaultdict(list)
    for entry in load_vol_json(MALFIND_JSON):
        pid = str(entry.get("PID", "N/A"))
        malfind_map[pid].append(
            {
                "StartVPN": entry.get("Start VPN"),
                "Protection": entry.get("Protection"),
                "Hexdump": entry.get("Hexdump", ""),
            }
        )
    return malfind_map


def format_time(t_str):
    if not t_str or t_str == "N/A":
        return "N/A"
    try:
        dt = datetime.strptime(str(t_str)[:19], "%Y-%m-%dT%H:%M:%S")
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return str(t_str)


# ---------------------------------------------------------------------------
# Suspect detection (for targeted malfind)
# ---------------------------------------------------------------------------


def find_suspect_pids(pstree_data, psscan_data):
    flat_pstree = flatten_pstree(pstree_data)
    psscan_dict = {str(r.get("PID")): r for r in psscan_data}
    processes = dict(flat_pstree)
    for pid, rec in psscan_dict.items():
        if pid not in processes:
            processes[pid] = rec

    pstree_pids = set(flat_pstree.keys())
    duplicate_flagged = build_duplicate_index(flat_pstree)
    suspects = set()

    for pid, rec in processes.items():
        ppid = str(rec.get("PPID", "N/A"))
        name = str(rec.get("ImageFileName", "Unknown")).lower()
        session_id = rec.get("SessionId")
        extime = rec.get("ExitTime")
        best_path = get_best_path(rec)

        if pid not in pstree_pids and not extime:
            suspects.add(pid)

        is_orphan = ppid not in processes and pid != "4" and ppid != "0"
        if is_orphan:
            if name in ORPHAN_WHITELIST:
                valid_paths, target_session = ORPHAN_WHITELIST[name]
                if best_path not in valid_paths or (
                    target_session is not None and session_id != target_session
                ):
                    suspects.add(pid)
            else:
                suspects.add(pid)

        if pid in duplicate_flagged:
            suspects.add(pid)

        if is_suspicious_path(best_path):
            suspects.add(pid)

    return list(suspects)


# ---------------------------------------------------------------------------
# Tree builder
# ---------------------------------------------------------------------------


def build_process_tree(pstree_data, psscan_data):
    flat_pstree = flatten_pstree(pstree_data)
    psscan_dict = {str(r.get("PID")): r for r in psscan_data}
    duplicate_flagged = build_duplicate_index(flat_pstree)
    malfind_map = build_malfind_index()

    processes = dict(flat_pstree)
    for pid, rec in psscan_dict.items():
        if pid not in processes:
            processes[pid] = rec

    flagged_pids = {}
    children_map = defaultdict(list)
    for pid, rec in processes.items():
        ppid = str(rec.get("PPID", "N/A"))
        children_map[ppid].append(pid)

    roots = sorted(
        [
            pid
            for pid, rec in processes.items()
            if str(rec.get("PPID", "N/A")) not in processes
        ],
        key=lambda x: int(x) if x.isdigit() else 0,
    )
    pstree_pids = set(flat_pstree.keys())

    nodes = []  # list of node dicts để render HTML

    def walk(node_pid, depth=0, is_last=True, prefix=""):
        rec = processes[node_pid]
        ppid = str(rec.get("PPID", "N/A"))
        name = str(rec.get("ImageFileName", "Unknown"))
        session_id = rec.get("SessionId")
        ctime = format_time(rec.get("CreateTime", "N/A"))
        extime = rec.get("ExitTime")
        best_path = get_best_path(rec)
        cmd = str(rec.get("Cmd") or "")

        flags = []  # list of (emoji, reason, search_url)

        # 🔴 Tàng hình
        if node_pid not in pstree_pids:
            if extime:
                flags.append(
                    ("⚪", "Tiến trình đã Exit — còn dấu vết trong psscan", "")
                )
            else:
                flags.append(
                    ("🔴", "Tàng hình — có trong psscan nhưng bị ẩn khỏi pslist", "")
                )

        # 🟠 Mồ côi
        is_orphan = ppid not in processes and node_pid != "4" and ppid != "0"
        if is_orphan:
            if name.lower() in ORPHAN_WHITELIST:
                valid_paths, target_session = ORPHAN_WHITELIST[name.lower()]
                if best_path not in valid_paths or (
                    target_session is not None and session_id != target_session
                ):
                    flags.append(
                        (
                            "🟠",
                            f"Mồ côi dị thường — cha PID {ppid} không tồn tại, path hoặc session không khớp whitelist",
                            "",
                        )
                    )
            else:
                flags.append(
                    (
                        "🟠",
                        f"Mồ côi — cha PID {ppid} không tồn tại trong danh sách tiến trình",
                        "",
                    )
                )

        # 🟡 Trùng tên khác path
        if node_pid in duplicate_flagged:
            flags.append(
                (
                    "🟡",
                    "Trùng tên với tiến trình khác nhưng path khác nhau — có thể giả mạo tên hệ thống",
                    "",
                )
            )

        # 🔵 Path đáng ngờ
        if is_suspicious_path(best_path):
            flags.append(
                (
                    "🔵",
                    f"Path đáng ngờ: {best_path} — tiến trình hệ thống hợp lệ không chạy từ đây",
                    "",
                )
            )

        # 🟣 RWX memory
        if node_pid in malfind_map:
            flags.append(
                (
                    "🟣",
                    f"Vùng nhớ RWX anonymous — {len(malfind_map[node_pid])} vùng bị malfind đánh dấu",
                    "",
                )
            )

        # Build flag strings
        flag_emojis = [f[0] for f in flags]
        detail_flags = [f"{f[0]} {f[1]}" for f in flags]

        if flags:
            flagged_pids[node_pid] = detail_flags

        # Raw node JSON
        raw_file = f"pid_{node_pid}.json"
        detail = dict(rec)
        detail["_flags"] = detail_flags
        detail["_best_extracted_path"] = best_path
        detail["MemoryAnomalies"] = malfind_map.get(node_pid, [])
        with open(RAW_NODES_DIR / raw_file, "w", encoding="utf-8") as f:
            json.dump(detail, f, indent=4, ensure_ascii=False)

        # Tree connector string (cho visual indentation)
        connector = "└─" if is_last else "├─"
        tree_prefix = prefix + connector

        google_url = f"https://www.google.com/search?q={name}+process+windows"

        nodes.append(
            {
                "pid": node_pid,
                "ppid": ppid,
                "name": name,
                "path": best_path,
                "cmd": cmd,
                "ctime": ctime,
                "depth": depth,
                "prefix": tree_prefix,
                "indent": prefix,
                "is_last": is_last,
                "flags": flags,  # [(emoji, reason, url)]
                "flag_emojis": flag_emojis,
                "raw_file": raw_file,
                "google_url": google_url,
                "threads": rec.get("Threads", ""),
                "handles": rec.get("Handles", ""),
                "session": session_id,
            }
        )

        children = sorted(
            children_map.get(node_pid, []),
            key=lambda x: int(x) if x.isdigit() else 0,
        )
        for i, child_pid in enumerate(children):
            child_is_last = i == len(children) - 1
            ext = "    " if is_last else "│   "
            walk(child_pid, depth + 1, child_is_last, prefix + ext)

    for i, root_pid in enumerate(roots):
        walk(root_pid, depth=0, is_last=(i == len(roots) - 1), prefix="")

    return nodes, flagged_pids


# ---------------------------------------------------------------------------
# HTML render
# ---------------------------------------------------------------------------


def build_html(nodes, flagged_pids):
    nodes_js = json.dumps(nodes, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>Process Map — Memory Forensics</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,500;0,700;1,400&family=Syne:wght@400;700;800&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#09090b;--surface:#111113;--border:#27272a;
  --text:#d4d4d8;--muted:#71717a;--accent:#60a5fa;
  --red:#f87171;--orange:#fb923c;--yellow:#fbbf24;
  --blue:#60a5fa;--purple:#a78bfa;--white:#e4e4e7;
  --green:#4ade80;
}}
body{{
  background:var(--bg);color:var(--text);
  font-family:'JetBrains Mono',monospace;
  font-size:13px;line-height:1.6;min-height:100vh;
}}
header{{
  padding:20px 28px 16px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:baseline;gap:16px;
}}
header h1{{
  font-family:'Syne',sans-serif;font-size:20px;font-weight:800;
  color:#fff;letter-spacing:-0.5px;
}}
header .sub{{font-size:11px;color:var(--muted)}}
.legend{{
  padding:10px 28px;border-bottom:1px solid var(--border);
  display:flex;gap:16px;flex-wrap:wrap;align-items:center;
  background:var(--surface);font-size:11px;color:var(--muted);
}}
.legend span{{display:flex;align-items:center;gap:4px}}
.tree-wrap{{padding:16px 28px 40px;overflow-x:auto}}
.node{{
  display:flex;align-items:baseline;gap:0;
  padding:2px 0;white-space:nowrap;
  animation:fadein .15s ease;
}}
@keyframes fadein{{from{{opacity:0;transform:translateY(-2px)}}to{{opacity:1;transform:none}}}}
.indent{{color:var(--border);font-size:12px;user-select:none}}
.connector{{color:#3f3f46;font-size:12px;user-select:none;margin-right:4px}}
.proc-name{{
  font-weight:700;color:#e4e4e7;cursor:pointer;
  text-decoration:none;
  border-bottom:1px solid transparent;
  transition:border-color .15s,color .15s;
}}
.proc-name:hover{{color:var(--accent);border-color:var(--accent)}}
.pid{{color:var(--muted);font-size:11px;margin-left:6px}}
.flags{{margin-left:6px;display:inline-flex;gap:3px}}
.flag{{
  cursor:help;font-size:13px;
  position:relative;display:inline-block;
}}
.flag .tip{{
  display:none;position:absolute;bottom:calc(100% + 6px);left:50%;
  transform:translateX(-50%);
  background:#1c1c1e;border:1px solid var(--border);
  color:var(--text);font-size:11px;font-weight:400;
  padding:6px 10px;border-radius:6px;white-space:nowrap;
  max-width:360px;white-space:normal;width:max-content;
  z-index:999;line-height:1.5;pointer-events:none;
  box-shadow:0 4px 20px rgba(0,0,0,.6);
}}
.flag:hover .tip{{display:block}}
.ctime{{color:var(--muted);font-size:11px;margin-left:8px}}
.detail-link{{
  color:var(--border);font-size:10px;margin-left:6px;
  text-decoration:none;padding:1px 5px;border:1px solid var(--border);
  border-radius:3px;transition:all .1s;
}}
.detail-link:hover{{color:var(--muted);border-color:var(--muted)}}
.path-line{{
  padding:0 0 3px 0;margin-left:0;
  color:#3f3f46;font-size:11px;font-style:italic;
  display:flex;align-items:center;gap:4px;white-space:nowrap;
}}
.path-text{{color:#52525b}}
.path-suspicious{{color:var(--orange)!important}}
.cmd-line{{color:#3f3f46;font-size:10px;font-style:italic;padding-bottom:2px}}
.flagged-row .proc-name{{color:var(--yellow)}}
.stats{{
  padding:8px 28px;border-bottom:1px solid var(--border);
  font-size:11px;color:var(--muted);
  display:flex;gap:16px;flex-wrap:wrap;
}}
.stats b{{color:var(--text)}}
</style>
</head>
<body>
<header>
  <h1>PROCESS MAP</h1>
  <span class="sub" id="hdr-sub">Loading...</span>
</header>
<div class="legend">
  <span>🔴 Tàng hình</span>
  <span>⚪ Đã Exit</span>
  <span>🟠 Mồ côi</span>
  <span>🟡 Trùng tên</span>
  <span>🔵 Path đáng ngờ</span>
  <span>🟣 RWX memory</span>
  <span style="margin-left:auto;font-size:10px">hover cờ → lý do &nbsp;|&nbsp; click tên → Google</span>
</div>
<div class="stats" id="stats"></div>
<div class="tree-wrap" id="tree"></div>
<script>
const NODES = {nodes_js};

// Stats
const total   = NODES.length;
const flagged = NODES.filter(n => n.flags.length > 0).length;
document.getElementById('hdr-sub').textContent =
  `${{total}} processes · ${{flagged}} flagged`;
document.getElementById('stats').innerHTML =
  `<span>Total: <b>${{total}}</b></span>` +
  `<span>Flagged: <b style="color:var(--yellow)">${{flagged}}</b></span>` +
  `<span>🔴 <b>${{NODES.filter(n=>n.flags.some(f=>f[0]==='🔴')).length}}</b></span>` +
  `<span>🟠 <b>${{NODES.filter(n=>n.flags.some(f=>f[0]==='🟠')).length}}</b></span>` +
  `<span>🟡 <b>${{NODES.filter(n=>n.flags.some(f=>f[0]==='🟡')).length}}</b></span>` +
  `<span>🔵 <b>${{NODES.filter(n=>n.flags.some(f=>f[0]==='🔵')).length}}</b></span>` +
  `<span>🟣 <b>${{NODES.filter(n=>n.flags.some(f=>f[0]==='🟣')).length}}</b></span>`;

const tree = document.getElementById('tree');

NODES.forEach(n => {{
  const hasFlagged = n.flags.length > 0;
  const isSuspPath = n.flags.some(f => f[0] === '🔵');

  // Node line
  const nodeDiv = document.createElement('div');
  nodeDiv.className = 'node' + (hasFlagged ? ' flagged-row' : '');

  // Indent + connector
  const indentEl   = document.createElement('span');
  indentEl.className = 'indent';
  indentEl.textContent = n.indent;

  const connEl = document.createElement('span');
  connEl.className = 'connector';
  connEl.textContent = n.prefix.slice(-2); // last 2 chars = connector

  // Process name (clickable → Google)
  const nameEl = document.createElement('a');
  nameEl.className   = 'proc-name';
  nameEl.href        = n.google_url;
  nameEl.target      = '_blank';
  nameEl.textContent = n.name;

  // PID
  const pidEl = document.createElement('span');
  pidEl.className   = 'pid';
  pidEl.textContent = `(PID:${{n.pid}} PPID:${{n.ppid}})`;

  // Flags
  const flagsEl = document.createElement('span');
  flagsEl.className = 'flags';
  n.flags.forEach(([emoji, reason]) => {{
    const f = document.createElement('span');
    f.className = 'flag';
    f.innerHTML = `${{emoji}}<span class="tip">${{reason}}</span>`;
    flagsEl.appendChild(f);
  }});

  // Time
  const ctimeEl = document.createElement('span');
  ctimeEl.className   = 'ctime';
  ctimeEl.textContent = n.ctime;

  // Detail link
  const detailEl = document.createElement('a');
  detailEl.className   = 'detail-link';
  detailEl.href        = `raw_nodes/${{n.raw_file}}`;
  detailEl.target      = '_blank';
  detailEl.textContent = 'JSON';

  nodeDiv.append(indentEl, connEl, nameEl, pidEl, flagsEl, ctimeEl, detailEl);
  tree.appendChild(nodeDiv);

  // Path line (chỉ hiện nếu có path)
  if (n.path) {{
    const pathDiv = document.createElement('div');
    pathDiv.className = 'path-line';
    const indentSp = document.createElement('span');
    indentSp.className   = 'indent';
    indentSp.textContent = n.indent + (n.is_last ? '    ' : '│   ');
    const pathSp = document.createElement('span');
    pathSp.className   = 'path-text' + (isSuspPath ? ' path-suspicious' : '');
    pathSp.textContent = '↳ ' + n.path;
    pathDiv.append(indentSp, pathSp);
    tree.appendChild(pathDiv);
  }}

  // Cmd line (chỉ hiện nếu cmd khác tên file)
  if (n.cmd && n.cmd.toLowerCase() !== n.name.toLowerCase() && n.cmd !== n.path) {{
    const cmdDiv = document.createElement('div');
    cmdDiv.className = 'cmd-line';
    const indentSp2 = document.createElement('span');
    indentSp2.className   = 'indent';
    indentSp2.textContent = n.indent + (n.is_last ? '    ' : '│   ');
    cmdDiv.append(indentSp2);
    cmdDiv.append(document.createTextNode('» ' + n.cmd));
    tree.appendChild(cmdDiv);
  }}
}});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def run_pipeline(image_path, is_full_scan=False):
    clean_old_workspace()

    print("\n[+] Đang chạy PSTREE và PSSCAN...")
    _run_vol(image_path, "windows.pstree", PSTREE_JSON)
    _run_vol(image_path, "windows.psscan", PSSCAN_JSON)

    pstree_data = load_vol_json(PSTREE_JSON)
    psscan_data = load_vol_json(PSSCAN_JSON)

    if not pstree_data or not psscan_data:
        print("[-] Lỗi: File cấu trúc trống hoặc không tồn tại.")
        return

    if is_full_scan:
        print("\n[!] Chế độ FULL SCAN: Đang quét malfind TOÀN BỘ RAM...")
        _run_vol(image_path, "windows.malware.malfind", MALFIND_JSON)
    else:
        print("\n[+] Chế độ FAST SCAN: Phân tích cấu trúc để chỉ điểm mục tiêu...")
        suspect_pids = find_suspect_pids(pstree_data, psscan_data)
        if not suspect_pids:
            print("[+] Không có tiến trình khả nghi. Bỏ qua malfind.")
            with open(MALFIND_JSON, "w", encoding="utf-8") as f:
                json.dump([], f)
        else:
            print(
                f"[!] Bắn malfind vào {len(suspect_pids)} mục tiêu (PID: {', '.join(suspect_pids)})..."
            )
            _run_vol(
                image_path,
                "windows.malware.malfind",
                MALFIND_JSON,
                extra_args=["--pid"] + suspect_pids,
            )

    print("\n[+] Đang tổng hợp phả hệ và vẽ cây...")
    nodes, flagged_pids = build_process_tree(pstree_data, psscan_data)

    with open(OUTPUT_DIR / "flagged_pids.json", "w", encoding="utf-8") as f:
        json.dump(flagged_pids, f, indent=2, ensure_ascii=False)

    html = build_html(nodes, flagged_pids)
    with open(HTML_OUTPUT, "w", encoding="utf-8") as f:
        f.write(html)

    total = len(nodes)
    flagged = len(flagged_pids)
    print(f"\n[✓] HOÀN THÀNH! {total} tiến trình, {flagged} bị gắn cờ.")
    print(f"    HTML     : {HTML_OUTPUT}")
    print(f"    Raw nodes: {RAW_NODES_DIR}/")
    print(f"    Flagged  : {OUTPUT_DIR / 'flagged_pids.json'}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Cách dùng: python map_builder.py <đường_dẫn_file_ram> [-full]")
        sys.exit(1)
    run_pipeline(sys.argv[1], is_full_scan="-full" in sys.argv)
