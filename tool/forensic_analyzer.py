import subprocess
import json
import re
import sys
import io
import shutil
import ipaddress
import urllib.request
import urllib.error
import time
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Force UTF-8 encoding for stdout/stderr to prevent UnicodeEncodeError on Windows
if hasattr(sys.stdout, "buffer"):
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")
    except Exception:
        pass

# Import configuration or set default values
try:
    from config import (
        VOLATILITY_PATH,
        OUTPUT_DIR,
        ORPHAN_WHITELIST,
        SUSPICIOUS_PATH_KEYWORDS,
        SAFE_PATH_PREFIXES,
    )
except ImportError:
    VOLATILITY_PATH = Path("/forensic/volatility3-stable/vol.py")
    OUTPUT_DIR = Path("output")
    ORPHAN_WHITELIST = {
        "csrss.exe": ({"c:\\windows\\system32\\csrss.exe"}, None),
        "wininit.exe": ({"c:\\windows\\system32\\wininit.exe"}, 0),
        "winlogon.exe": ({"c:\\windows\\system32\\winlogon.exe"}, None),
        "explorer.exe": ({"c:\\windows\\explorer.exe"}, None),
        "lsass.exe": ({"c:\\windows\\system32\\lsass.exe"}, 0),
        "lsm.exe": ({"c:\\windows\\system32\\lsm.exe"}, 0),
        "smss.exe": ({"c:\\windows\\system32\\smss.exe"}, 0),
    }
    SUSPICIOUS_PATH_KEYWORDS = {
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\public\\",
        "\\recycle",
        "\\users\\default\\",
    }
    SAFE_PATH_PREFIXES = {
        "c:\\windows\\system32\\",
        "c:\\windows\\syswow64\\",
        "c:\\windows\\",
        "c:\\program files\\",
        "c:\\program files (x86)\\",
        "\\systemroot\\",
        "\\device\\harddiskvolume",
    }

# Outputs inside OUTPUT_DIR
WINDOWS_INFO_JSON = OUTPUT_DIR / "windows_info_summary.json"
PSTREE_JSON = OUTPUT_DIR / "pstree.json"
PSSCAN_JSON = OUTPUT_DIR / "psscan.json"
GETSIDS_JSON = OUTPUT_DIR / "getsids.json"
MALFIND_JSON = OUTPUT_DIR / "malfind.json"
NETSCAN_JSON = OUTPUT_DIR / "netscan.json"
DLLLIST_JSON = OUTPUT_DIR / "dlllist.json"
FLAGGED_PIDS_JSON = OUTPUT_DIR / "flagged_pids.json"
RAW_NODES_DIR = OUTPUT_DIR / "raw_nodes"
NETSCAN_DIR = OUTPUT_DIR / "netscan"
NETSCAN_DETAIL_DIR = NETSCAN_DIR / "detail"
NETSCAN_IP_CACHE = NETSCAN_DIR / "ip_cache.json"
NETSCAN_SUMMARY_JSON = NETSCAN_DIR / "summary.json"
DASHBOARD_HTML = OUTPUT_DIR / "Forensic_Dashboard.html"

# Configuration constants
NOISE_LOCAL_PORTS = {7, 9, 13, 17, 19}
COMMON_FOREIGN_PORTS = {80, 443, 53, 67, 68, 123, 135, 137, 138, 139, 445, 5353}
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
SYSTEM_OWNERS = {
    "system",
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "csrss.exe",
}


# ---------------------------------------------------------------------------
# Workspace Cleaning
# ---------------------------------------------------------------------------
def clean_workspace():
    print("[+] Cleaning old workspace...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Save IP cache if it exists to preserve rate limits
    cache_data = {}
    if NETSCAN_IP_CACHE.exists():
        try:
            with open(NETSCAN_IP_CACHE, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
        except Exception:
            pass

    # Remove target files
    files_to_remove = [
        WINDOWS_INFO_JSON,
        PSTREE_JSON,
        PSSCAN_JSON,
        GETSIDS_JSON,
        MALFIND_JSON,
        NETSCAN_JSON,
        DLLLIST_JSON,
        FLAGGED_PIDS_JSON,
        DASHBOARD_HTML,
        NETSCAN_SUMMARY_JSON,
    ]
    for f in files_to_remove:
        if f.exists():
            f.unlink()

    # Clear directories
    if RAW_NODES_DIR.exists():
        shutil.rmtree(RAW_NODES_DIR)
    RAW_NODES_DIR.mkdir(parents=True, exist_ok=True)

    if NETSCAN_DETAIL_DIR.exists():
        shutil.rmtree(NETSCAN_DETAIL_DIR)
    NETSCAN_DETAIL_DIR.mkdir(parents=True, exist_ok=True)

    # Restore IP cache
    if cache_data:
        with open(NETSCAN_IP_CACHE, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)

    print("[+] Workspace is clean!")


# ---------------------------------------------------------------------------
# Volatility Execution Helpers
# ---------------------------------------------------------------------------
def run_volatility(image_path, plugin, out_path, extra_args=None):
    cmd = ["python", str(VOLATILITY_PATH), "-f", str(image_path), "-r", "json", plugin]
    if extra_args:
        cmd.extend(extra_args)

    print(f"[~] Executing Volatility: {' '.join(cmd)}")
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
        print(f"[-] Error loading JSON from {filepath.name}: {e}")
        return []


# ---------------------------------------------------------------------------
# OOP Module-based Architecture
# ---------------------------------------------------------------------------
class ForensicModule:
    """Base class for all forensic analysis and tab rendering modules."""

    def __init__(self, module_id, tab_title):
        self.module_id = module_id
        self.tab_title = tab_title

    def run_analysis(self, image_path, context):
        """Runs the volatility plugin and updates the shared context dictionary."""
        pass

    def generate_html_tab(self, context):
        """Generates and returns the HTML string content for this tab."""
        return ""

    def get_css(self):
        """Returns optional CSS styling strings for this module's tab."""
        return ""

    def get_js(self):
        """Returns optional JS strings for this module's tab."""
        return ""


# ---------------------------------------------------------------------------
# Module 1: System Info
# ---------------------------------------------------------------------------
class SystemInfoModule(ForensicModule):
    def __init__(self):
        super().__init__("sys", "🖥️ Thông tin hệ thống")

    def run_analysis(self, image_path, context):
        print("\n[=== STEP 1: READING OS INFORMATION ===]")
        raw_info_txt = OUTPUT_DIR / "windows_info_raw.txt"

        cmd = ["python", str(VOLATILITY_PATH), "-f", str(image_path), "windows.info"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )

        with open(raw_info_txt, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        if result.returncode != 0:
            print(f"[-] Error running windows.info: {result.stderr}")
            context["os_data"] = {}
            return

        parsed = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("-"):
                continue
            parts = re.split(r"\s{2,}|\t+", line)
            if len(parts) >= 2:
                key = parts[0].strip()
                value = " ".join(parts[1:]).strip()
                parsed[key] = value

        major = parsed.get("NtMajorVersion")
        minor = parsed.get("NtMinorVersion")
        version_map = {
            ("6", "1"): "Windows 7",
            ("6", "2"): "Windows 8",
            ("6", "3"): "Windows 8.1",
            ("10", "0"): "Windows 10/11",
        }
        os_name = version_map.get((major, minor), "Unknown Windows")

        useful = {
            "architecture": "64-bit" if parsed.get("Is64Bit") == "True" else "32-bit",
            "os": {
                "name": os_name,
                "service_pack": (
                    f"SP{parsed.get('CSDVersion')}" if parsed.get("CSDVersion") else ""
                ),
                "build_lab": parsed.get("NTBuildLab", ""),
            },
            "system_time_utc": parsed.get("SystemTime", "Unknown"),
            "system_root": parsed.get("NtSystemRoot", "Unknown"),
            "processors": parsed.get("KeNumberProcessors", "Unknown"),
            "kernel": {
                "base_address": parsed.get("Kernel Base"),
                "symbol_file": parsed.get("Symbols"),
            },
        }

        summary_str = f"RAM dump identified as {useful['os']['name']} {useful['os']['service_pack']} {useful['architecture']}. System time: {useful['system_time_utc']}."
        result_data = {
            "evidence_file": str(image_path.resolve()),
            "parsed": useful,
            "forensic_context": {
                "summary": " ".join(summary_str.split()),
                "analysis_notes": [
                    "OS version used as baseline for plugin compatibility.",
                    "System time used as investigation timeline reference.",
                    "System root used to validate suspicious paths.",
                    "Architecture used for process and DLL interpretation.",
                ],
            },
        }

        with open(WINDOWS_INFO_JSON, "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        print(f"[✓] Saved OS info to {WINDOWS_INFO_JSON.name}")

        context["os_data"] = result_data

    def generate_html_tab(self, context):
        os_data = context.get("os_data", {})
        sys_parsed = os_data.get("parsed", {})
        os_info = sys_parsed.get("os", {})
        kernel_info = sys_parsed.get("kernel", {})

        notes_html = ""
        for note in os_data.get("forensic_context", {}).get("analysis_notes", []):
            notes_html += f"<p>• {note}</p>"

        html = f"""
        <div class="sys-grid">
            <div class="card">
                <h3>🖥️ Hệ Điều Hành & Cấu Hình</h3>
                <table class="info-table">
                    <tr><td class="key">Hệ điều hành</td><td class="val">{os_info.get('name', 'N/A')}</td></tr>
                    <tr><td class="key">Service Pack</td><td class="val">{os_info.get('service_pack') or 'None'}</td></tr>
                    <tr><td class="key">Kiến trúc</td><td class="val">{sys_parsed.get('architecture', 'N/A')}</td></tr>
                    <tr><td class="key">Build Lab</td><td class="val">{os_info.get('build_lab', 'N/A')}</td></tr>
                    <tr><td class="key">Thư mục System Root</td><td class="val">{sys_parsed.get('system_root', 'N/A')}</td></tr>
                    <tr><td class="key">Note:</td><td class="val">Profile = [Tên OS][Service Pack][Kiến trúc]</td></tr>
                </table>
            </div>
            
            <div class="card">
                <h3>⏰ Thời Gian & Phần Cứng</h3>
                <table class="info-table">
                    <tr><td class="key">Thời gian hệ thống (UTC)</td><td class="val">{sys_parsed.get('system_time_utc', 'N/A')}</td></tr>
                    <tr><td class="key">Số vi xử lý (CPUs)</td><td class="val">{sys_parsed.get('processors', 'N/A')}</td></tr>
                    <tr><td class="key">Địa chỉ Kernel Base</td><td class="val">{kernel_info.get('base_address', 'N/A')}</td></tr>
                    <tr><td class="key">Tệp tin Symbols</td><td class="val">{kernel_info.get('symbol_file', 'N/A')}</td></tr>
                </table>
            </div>

            <div class="card">
                <h3>💡 Ghi Chú Cảnh Báo (Forensic Context)</h3>
                <div class="note-box">
                    {notes_html}
                </div>
            </div>
        </div>
        """
        return html


# ---------------------------------------------------------------------------
# Module 2: Process Map
# ---------------------------------------------------------------------------
class ProcessMapModule(ForensicModule):
    def __init__(self):
        super().__init__("proc", "🌿 Bản đồ tiến trình")

    def run_analysis(self, image_path, context):
        print("\n[=== STEP 2: ANALYZING PROCESS STRUCTURE ===]")
        run_volatility(image_path, "windows.pstree", PSTREE_JSON)
        run_volatility(image_path, "windows.psscan", PSSCAN_JSON)
        run_volatility(image_path, "windows.getsids", GETSIDS_JSON)

        pstree_data = load_vol_json(PSTREE_JSON)
        psscan_data = load_vol_json(PSSCAN_JSON)
        getsids_data = load_vol_json(GETSIDS_JSON)

        if not pstree_data or not psscan_data:
            print("[-] Error: Unable to fetch pstree or psscan data.")
            context["process_nodes"] = []
            context["flagged_pids"] = {}
            return

        is_full_scan = context.get("is_full_scan", False)
        if is_full_scan:
            print("[!] Full Scan Mode: Running malfind on all memory...")
            run_volatility(image_path, "windows.malware.malfind", MALFIND_JSON)
        else:
            print("[+] Fast Scan Mode: Isolating suspect targets to run malfind...")
            suspect_pids = find_suspect_pids(pstree_data, psscan_data)
            if not suspect_pids:
                print("[+] No suspect processes found. Skipping malfind.")
                with open(MALFIND_JSON, "w", encoding="utf-8") as f:
                    json.dump([], f)
            else:
                print(
                    f"[!] Isolated {len(suspect_pids)} suspect PIDs: {', '.join(suspect_pids)}. Running targeted malfind..."
                )
                run_volatility(
                    image_path,
                    "windows.malware.malfind",
                    MALFIND_JSON,
                    extra_args=["--pid"] + suspect_pids,
                )

        print("[+] Building process tree nodes...")
        nodes, flagged_pids = build_process_tree(pstree_data, psscan_data, getsids_data)

        with open(FLAGGED_PIDS_JSON, "w", encoding="utf-8") as f:
            json.dump(flagged_pids, f, indent=2, ensure_ascii=False)

        context["process_nodes"] = nodes
        context["flagged_pids"] = flagged_pids

    def generate_html_tab(self, context):
        html = """
        <div class="tree-container">
            <div class="legend-bar">
                <span class="legend-title">Bộ lọc bất thường:</span>
                <span class="legend-tag tag-stealth">🔴 Tàng hình</span>
                <span class="legend-tag tag-orphan">Orphaned</span>
                <span class="legend-tag tag-duplicate">🟡 Trùng tên khác path</span>
                <span class="legend-tag tag-path">🔵 Path đáng ngờ</span>
                <span class="legend-tag tag-rwx">🟣 RWX Memory (Malfind)</span>
                <span class="legend-tag tag-exited">⚪ Đã kết thúc (Exit)</span>
            </div>
            
            <div id="process-tree-root"></div>
        </div>
        """
        return html

    def get_css(self):
        css = """
        /* Tree Node Styling */
        .tree-node {
            margin: 0;
            padding: 0;
            border-radius: 4px;
            border: 1px solid transparent;
            transition: all 0.1s ease;
        }

        .tree-node[open] {
            border-color: var(--border-color);
            background: #fafafa;
            margin-top: 4px;
            margin-bottom: 8px;
            padding-bottom: 6px;
        }

        .node-summary {
            list-style: none; /* Hide default arrow */
            outline: none;
            cursor: pointer;
            padding: 0 8px;
            height: 22px; /* Fixed VS Code explorer height */
            display: flex;
            align-items: center;
            border-radius: 4px;
            transition: background 0.1s;
            user-select: none;
            box-sizing: border-box;
        }

        .node-summary::-webkit-details-marker {
            display: none; /* Hide chrome arrow */
        }

        .node-summary:hover {
            background: #f1f5f9;
        }

        .tree-indent-wrapper {
            display: inline-flex;
            height: 22px;
            align-items: stretch;
            margin-right: 6px;
            flex-shrink: 0;
        }

        .tree-indent-col {
            width: 16px;
            height: 22px;
            position: relative;
            flex-shrink: 0;
            display: inline-block;
        }

        /* VS Code styled tree guide lines */
        .tree-indent-col.line::before {
            content: '';
            position: absolute;
            left: 7px;
            top: 0;
            bottom: 0;
            width: 1px;
            background-color: #cbd5e1; /* soft slate border line */
        }

        .tree-indent-col.branch-t::before {
            content: '';
            position: absolute;
            left: 7px;
            top: 0;
            bottom: 0;
            width: 1px;
            background-color: #cbd5e1;
        }

        .tree-indent-col.branch-t::after {
            content: '';
            position: absolute;
            left: 7px;
            top: 11px; /* Half of 22px */
            width: 9px;
            height: 1px;
            background-color: #cbd5e1;
        }

        .tree-indent-col.branch-l::before {
            content: '';
            position: absolute;
            left: 7px;
            top: 0;
            height: 11px;
            width: 1px;
            background-color: #cbd5e1;
        }

        .tree-indent-col.branch-l::after {
            content: '';
            position: absolute;
            left: 7px;
            top: 11px;
            width: 9px;
            height: 1px;
            background-color: #cbd5e1;
        }

        .proc-name {
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            font-weight: 500;
            color: var(--text-primary);
            font-size: 13px;
            padding: 1px 4px;
            border-radius: 3px;
        }

        .proc-name.has-anomaly {
            background: #fffbeb;
            border: 1px solid #fef3c7;
        }

        .pid-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: var(--text-muted);
            margin-left: 6px;
            background: #f1f5f9;
            padding: 0px 4px;
            border-radius: 3px;
            border: 1px solid #e2e8f0;
        }

        .user-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: #475569;
            margin-left: 6px;
            background: #e2e8f0;
            padding: 0px 5px;
            border-radius: 3px;
            border: 1px solid #cbd5e1;
            white-space: nowrap;
        }
        
        .user-badge.user-system {
            background: #fee2e2;
            color: #991b1b;
            border-color: #fca5a5;
        }
        
        .user-badge.user-admin {
            background: #ffedd5;
            color: #c2410c;
            border-color: #fdbb2d;
        }

        .ghost-process .proc-name {
            color: #94a3b8 !important;
            font-style: italic;
            background: transparent !important;
            border: none !important;
        }
        
        .ghost-process .node-summary {
            opacity: 0.65;
        }

        .flags-container {
            margin-left: 6px;
            display: inline-flex;
            gap: 2px;
        }

        .mini-flag {
            cursor: help;
            font-size: 11px;
            position: relative;
            display: inline-block;
        }

        .mini-flag .tooltip-text {
            visibility: hidden;
            display: block;
            background-color: #0f172a;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 6px 12px;
            position: absolute;
            z-index: 99;
            bottom: 140%;
            left: 50%;
            transform: translateX(-50%);
            opacity: 0;
            transition: opacity 0.15s ease-in-out;
            width: max-content;
            max-width: 260px;
            font-size: 11px;
            font-family: system-ui, -apple-system, sans-serif;
            font-weight: normal;
            line-height: 1.4;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            pointer-events: none;
            word-break: break-all;
            white-space: normal;
        }

        .mini-flag .tooltip-text::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            transform: translateX(-50%);
            border-width: 5px;
            border-style: solid;
            border-color: #0f172a transparent transparent transparent;
        }

        .mini-flag:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }

        .time-badge {
            margin-left:auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: var(--text-muted);
        }

        .toggle-arrow {
            margin-left: 8px;
            font-size: 9px;
            color: var(--text-muted);
            transition: transform 0.1s ease;
            display: inline-block;
        }

        .tree-node[open] > .node-summary .toggle-arrow {
            transform: rotate(90deg);
        }

        /* Expandable content area */
        .node-details-card {
            border-left: 4px solid var(--accent);
            padding: 16px;
            margin-top: 4px;
            margin-bottom: 8px;
            margin-right: 12px;
            border-radius: 0 8px 8px 0;
            background: #ffffff;
            box-shadow: inset 0 1px 2px rgba(0,0,0,0.02);
        }

        .node-details-card.border-stealth { border-left-color: #ef4444; }
        .node-details-card.border-orphan { border-left-color: #f97316; }
        .node-details-card.border-duplicate { border-left-color: #eab308; }
        .node-details-card.border-path { border-left-color: #3b82f6; }
        .node-details-card.border-rwx { border-left-color: #a855f7; }

        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px 20px;
        }

        .details-grid .item {
            font-size: 13px;
        }

        .details-grid .item strong {
            color: var(--text-secondary);
        }

        .details-grid .item code {
            font-family: 'JetBrains Mono', monospace;
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            word-break: break-all;
        }

        .details-link-btn {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            color: var(--accent);
            text-decoration: none;
            font-weight: 600;
            font-size: 12px;
        }

        .details-link-btn:hover {
            text-decoration: underline;
        }

        .anomalies-section {
            margin-top: 14px;
            border-top: 1px solid var(--border-color);
            padding-top: 12px;
        }

        .anomalies-section h4 {
            font-size: 13px;
            color: #991b1b;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .hexdump-code {
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            background: #0f172a;
            color: #f8fafc;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            max-height: 250px;
            white-space: pre-wrap;
            margin-top: 4px;
        }
        """
        return css

    def get_js(self):
        js = """
        // Render Tree Prefix with VS Code style CSS lines
        function renderTreePrefix(prefix) {
            const wrapper = document.createElement('span');
            wrapper.className = 'tree-indent-wrapper';
            
            if (!prefix) return wrapper;
            
            const connector = prefix.slice(-2);
            const indents = prefix.slice(0, -2);
            
            for (let i = 0; i < indents.length; i += 4) {
                const chunk = indents.slice(i, i + 4);
                const col = document.createElement('span');
                col.className = 'tree-indent-col';
                if (chunk.includes('│')) {
                    col.classList.add('line');
                }
                wrapper.appendChild(col);
            }
            
            const col = document.createElement('span');
            col.className = 'tree-indent-col';
            if (connector === '├─') {
                col.classList.add('branch-t');
            } else if (connector === '└─') {
                col.classList.add('branch-l');
            }
            wrapper.appendChild(col);
            
            return wrapper;
        }

        // Build Process Tree View
        function renderProcessTree() {
            const container = document.getElementById('process-tree-root');
            if (!container) return;
            container.innerHTML = '';
            
            PROCESSES.forEach(n => {
                const detailsEl = document.createElement('details');
                detailsEl.className = 'tree-node';
                detailsEl.id = `node-${n.pid}`;
                detailsEl.dataset.searchstr = `${n.name} ${n.pid} ${n.ppid} ${n.path} ${n.user || ''} ${n.flag_emojis.join(' ')}`.toLowerCase();
                
                if (n.is_ghost) {
                    detailsEl.classList.add('ghost-process');
                }
                
                // Severity color border check
                let borderClass = '';
                if (n.flags.some(f => f[2] === 'hidden')) borderClass = 'border-stealth';
                else if (n.flags.some(f => f[2] === 'orphan' || f[2] === 'orphan_anomaly')) borderClass = 'border-orphan';
                else if (n.flags.some(f => f[2] === 'duplicate')) borderClass = 'border-duplicate';
                else if (n.flags.some(f => f[2] === 'suspicious_path')) borderClass = 'border-path';
                else if (n.flags.some(f => f[2] === 'malfind')) borderClass = 'border-rwx';

                // Summary Line
                const summary = document.createElement('summary');
                summary.className = 'node-summary';
                
                // Tree Indentation Guide lines
                const indentWrapper = renderTreePrefix(n.prefix);
                
                // Process Name badge
                const nameSpan = document.createElement('span');
                nameSpan.className = 'proc-name';
                if (n.anomalies.length > 0) nameSpan.classList.add('has-anomaly');
                nameSpan.textContent = n.name;
                
                // PID/PPID info
                const pidSpan = document.createElement('span');
                pidSpan.className = 'pid-badge';
                pidSpan.textContent = `PID:${n.pid} PPID:${n.ppid}`;
                
                // User info badge
                const userSpan = document.createElement('span');
                userSpan.className = 'user-badge';
                userSpan.textContent = n.is_ghost ? 'N/A' : (n.user || 'Unknown');
                if (n.user === 'SYSTEM') {
                    userSpan.classList.add('user-system');
                } else if (n.user && (n.user.toLowerCase().includes('admin') || n.user === 'LocalSystem')) {
                    userSpan.classList.add('user-admin');
                }
                
                // Flags
                const flagsSpan = document.createElement('span');
                flagsSpan.className = 'flags-container';
                n.flags.forEach(([emoji, reason]) => {
                    const f = document.createElement('span');
                    f.className = 'mini-flag';
                    f.innerHTML = `${emoji}<span class="tooltip-text">${reason}</span>`;
                    flagsSpan.appendChild(f);
                });
                
                // Creation Time
                const timeSpan = document.createElement('span');
                timeSpan.className = 'time-badge';
                timeSpan.textContent = n.ctime;
                
                // Toggle arrow
                const arrow = document.createElement('span');
                arrow.className = 'toggle-arrow';
                arrow.textContent = '▶';
                
                summary.append(indentWrapper, nameSpan, pidSpan, userSpan, flagsSpan, timeSpan, arrow);
                
                // Details Card Container
                const detailsCard = document.createElement('div');
                detailsCard.className = `node-details-card ${borderClass}`;
                // Indent content dynamically to line up with the process name, leaving visual tree connector columns clear
                detailsCard.style.marginLeft = `${(n.depth + 1) * 20}px`;
                
                // Grid Info fields
                const grid = document.createElement('div');
                grid.className = 'details-grid';
                
                if (n.is_ghost) {
                    grid.innerHTML = `
                        <div class="item" style="grid-column: 1 / -1;">
                            <strong>Trạng thái tiến trình:</strong> 
                            <span style="color: #64748b; font-style: italic;">
                                Tiến trình cha này không được tìm thấy trong RAM dump (đã kết thúc trước khi dump hoặc bị ẩn rất sâu).
                                Chỉ phát hiện được sự hiện diện của nó thông qua thuộc tính PPID của các tiến trình con.
                            </span>
                        </div>
                        <div class="item"><strong>PID tiến trình cha:</strong> <code>${n.pid}</code></div>
                        <div class="item"><strong>Hồ sơ gốc:</strong> 
                            <a href="raw_nodes/${n.raw_file}" target="_blank" class="details-link-btn">
                                Xem file JSON thô ↗
                            </a>
                        </div>
                    `;
                } else {
                    grid.innerHTML = `
                        <div class="item"><strong>Đường dẫn:</strong> <code>${n.path || 'N/A'}</code></div>
                        <div class="item"><strong>Dòng lệnh (Cmd):</strong> <code>${n.cmd || 'N/A'}</code></div>
                        <div class="item"><strong>Tài khoản (User):</strong> <code>${n.user || 'Unknown'}</code></div>
                        <div class="item"><strong>SID Tài khoản:</strong> <code>${n.sid || 'N/A'}</code></div>
                        <div class="item"><strong>Phiên làm việc (Session ID):</strong> <code>${n.session}</code></div>
                        <div class="item"><strong>Số luồng (Threads):</strong> <span>${n.threads}</span></div>
                        <div class="item"><strong>Handles:</strong> <span>${n.handles}</span></div>
                        <div class="item">
                            <strong>Hồ sơ gốc:</strong> 
                            <a href="raw_nodes/${n.raw_file}" target="_blank" class="details-link-btn">
                                Xem file JSON thô ↗
                            </a>
                        </div>
                        <div class="item">
                            <strong>Tra cứu:</strong> 
                            <a href="${n.google_url}" target="_blank" class="details-link-btn" style="color: #059669;">
                                Tìm trên Google ↗
                            </a>
                        </div>
                    `;
                }
                detailsCard.appendChild(grid);
                
                // Process Flags detail list
                if (n.flags.length > 0) {
                    const flagSection = document.createElement('div');
                    flagSection.className = 'anomalies-section';
                    flagSection.innerHTML = `
                        <h4 style="color:#c2410c">⚠️ Phát hiện bất thường</h4>
                        <ul style="margin-left: 20px; font-size: 13px; color: var(--text-secondary)">
                            ${n.flags.map(([emoji, reason]) => `<li>${emoji} ${reason}</li>`).join('')}
                        </ul>
                    `;
                    detailsCard.appendChild(flagSection);
                }
                
                // Malfind anomalies section
                if (n.anomalies.length > 0) {
                    const malfindSection = document.createElement('div');
                    malfindSection.className = 'anomalies-section';
                    malfindSection.innerHTML = `
                        <h4>🟣 Memory Injection (Malfind) — Hexdump vùng nghi vấn</h4>
                        ${n.anomalies.map((anom, aIdx) => `
                            <div style="margin-top: 8px;">
                                <span style="font-size:12px; font-weight:600; color:var(--text-secondary)">
                                    Vùng #${aIdx + 1}: Bắt đầu tại ${anom.StartVPN} (Quyền bảo vệ: ${anom.Protection})
                                </span>
                                <pre class="hexdump-code">${anom.Hexdump}</pre>
                            </div>
                        `).join('')}
                    `;
                    detailsCard.appendChild(malfindSection);
                }
                
                detailsEl.append(summary, detailsCard);
                container.appendChild(detailsEl);
            });
        }

        // Filter Process Tree
        function filterProcessTree() {
            const q = document.getElementById('proc-search').value.toLowerCase().trim();
            const nodes = document.querySelectorAll('.tree-node');
            
            nodes.forEach(n => {
                if (!q) {
                    n.style.display = '';
                    n.open = false;
                } else {
                    const isMatch = n.dataset.searchstr.includes(q);
                    n.style.display = isMatch ? '' : 'none';
                    if (isMatch) n.open = true; // Auto open if matching search
                }
            });
        }
        """
        return js


# ---------------------------------------------------------------------------
# Module 3: Network Map
# ---------------------------------------------------------------------------
class NetworkMapModule(ForensicModule):
    def __init__(self):
        super().__init__("net", "🌐 Bản đồ kết nối mạng")

    def run_analysis(self, image_path, context):
        flagged_pids = context.get("flagged_pids", {})
        all_tagged, summary = run_network_analysis(image_path, flagged_pids)

        context["network_entries"] = all_tagged
        context["net_summary"] = summary

    def generate_html_tab(self, context):
        net_summary = context.get("net_summary", {})
        html = f"""
        <div class="tree-container">
            <div class="net-controls">
                <div class="filter-group">
                    <button class="btn-filter active" id="btn-net-high" onclick="toggleNetPriority('high')">🔴 Cao ({net_summary.get('high', 0)})</button>
                    <button class="btn-filter active" id="btn-net-med" onclick="toggleNetPriority('medium')">🟡 Trung bình ({net_summary.get('medium', 0)})</button>
                    <button class="btn-filter" id="btn-net-low" onclick="toggleNetPriority('low')">⚪ Thấp ({net_summary.get('low', 0)})</button>
                </div>
                <div class="sep" style="width:1px; height:20px; background:var(--border-color)"></div>
                <div class="filter-group">
                    <button class="btn-filter" id="btn-net-flagged" onclick="toggleNetQuick('flagged_process')">⚑ Tiến trình bị cờ</button>
                    <button class="btn-filter" id="btn-net-public" onclick="toggleNetQuick('public_ip')">🌐 IP Public</button>
                </div>
                
                <input type="text" class="input-search" id="net-search" style="flex:initial; width:260px; margin-left:auto" placeholder="Tìm PID, Owner, IP..." oninput="applyNetFilters()">
            </div>

            <div class="table-wrap">
                <table class="net-table">
                    <thead>
                        <tr>
                            <th>Mức độ</th>
                            <th>PID</th>
                            <th>Owner</th>
                            <th>Proto</th>
                            <th>Local Connection</th>
                            <th>Foreign Connection</th>
                            <th>Org / ISP</th>
                            <th>State</th>
                            <th>Lý do</th>
                            <th>Cảnh báo Process</th>
                            <th>Chi tiết</th>
                        </tr>
                    </thead>
                    <tbody id="net-table-body"></tbody>
                </table>
            </div>
            <div class="empty-row" id="net-empty">Không tìm thấy kết nối mạng nào trùng khớp bộ lọc.</div>
        </div>
        """
        return html

    def get_css(self):
        css = """
        /* Tab 3: Network Map Styling */
        .net-controls {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }

        .filter-group {
            display: flex;
            gap: 6px;
        }

        .btn-filter {
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.1s ease;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .btn-filter:hover {
            background: var(--bg-main);
        }

        .btn-filter.active {
            background: var(--accent-light);
            border-color: var(--accent);
            color: var(--accent);
        }

        .table-wrap {
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            overflow-x: auto;
        }

        .net-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: left;
        }

        .net-table th {
            background: #f8fafc;
            border-bottom: 1px solid var(--border-color);
            padding: 12px 16px;
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .net-table td {
            padding: 10px 16px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
            font-family: 'JetBrains Mono', monospace;
        }

        .net-table tr:hover td {
            background: #f8fafc;
        }

        .net-table tr.hidden {
            display: none;
        }

        .badge-priority {
            font-weight: 700;
            font-size: 10px;
            text-transform: uppercase;
            padding: 3px 8px;
            border-radius: 4px;
            display: inline-block;
        }

        .badge-priority.high { background: var(--color-stealth-bg); color: var(--color-stealth-text); }
        .badge-priority.medium { background: var(--color-orphan-bg); color: var(--color-orphan-text); }
        .badge-priority.low { background: var(--color-exited-bg); color: var(--color-exited-text); }

        .badge-state {
            font-weight: 600;
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 4px;
            display: inline-block;
        }

        .badge-state.established { background: var(--color-ok-bg); color: var(--color-ok-text); }
        .badge-state.listening { background: var(--accent-light); color: var(--accent); }
        .badge-state.closed { background: var(--color-exited-bg); color: var(--color-exited-text); }
        .badge-state.closing { background: var(--color-orphan-bg); color: var(--color-orphan-text); }
        .badge-state.other { background: var(--color-exited-bg); color: var(--color-exited-text); }

        .net-flag-tag {
            background: #f3e8ff;
            color: #6b21a8;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 4px;
            margin-right: 4px;
            display: inline-block;
        }

        .net-reason-tag {
            background: #f1f5f9;
            color: #475569;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 4px;
            margin-right: 4px;
            display: inline-block;
            border: 1px solid #e2e8f0;
        }

        .org-link {
            color: var(--accent);
            text-decoration: none;
        }

        .org-link:hover {
            text-decoration: underline;
        }

        .detail-json-link {
            padding: 3px 8px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            text-decoration: none;
            color: var(--text-secondary);
            font-size: 11px;
            transition: all 0.1s;
        }

        .detail-json-link:hover {
            border-color: var(--accent);
            color: var(--accent);
            background: var(--accent-light);
        }
        """
        return css

    def get_js(self):
        js = """
        // Tab 3: Network Map Logic
        let activeNetPriorities = new Set(['high', 'medium']);
        let activeNetQuickFilters = new Set(); // 'flagged_process', 'public_ip'

        function renderNetworkTable() {
            const body = document.getElementById('net-table-body');
            if (!body) return;
            body.innerHTML = '';
            
            NETWORK.forEach(e => {
                const tr = document.createElement('tr');
                tr.dataset.priority = e._priority || 'low';
                tr.dataset.reasons = (e._reasons || []).join(' ');
                
                // Flags of processes
                const processFlags = e._process_flags || [];
                const procFlagStr = processFlags.join(' ');
                
                tr.dataset.search = `${e.PID} ${e.Owner} ${e.LocalAddr} ${e.ForeignAddr} ${e.State} ${e._label || ''} ${e._org || ''} ${procFlagStr}`.toLowerCase();
                
                // Badges
                const priorityBadge = `<span class="badge-priority ${e._priority}">${e._priority}</span>`;
                
                let stateClass = 'other';
                const stUpper = (e.State || '').toUpperCase();
                if (stUpper === 'ESTABLISHED') stateClass = 'established';
                else if (stUpper === 'LISTENING') stateClass = 'listening';
                else if (stUpper === 'CLOSED') stateClass = 'closed';
                else if (['TIME_WAIT', 'CLOSE_WAIT', 'FIN_WAIT1', 'FIN_WAIT2', 'SYN_SENT'].includes(stUpper)) stateClass = 'closing';
                
                const stateBadge = `<span class="badge-state ${stateClass}">${e.State || 'N/A'}</span>`;
                
                // Org geolocation link
                let orgHTML = '';
                if (e._label || e._org) {
                    const displayName = e._label || e._org;
                    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(displayName + ' Org / ISP')}`;
                    const country = e._country ? ` (${e._country})` : '';
                    orgHTML = `<a href="${searchUrl}" class="org-link" target="_blank">${displayName}</a>${country}`;
                }
                
                // Parse process warnings to ONLY display emojis, with description inside custom HTML tooltips
                const pTags = processFlags.map(x => {
                    const emoji = x.slice(0, 2).trim();
                    const reason = x.slice(2).trim();
                    return `<span class="mini-flag" style="margin-right:4px;">${emoji}<span class="tooltip-text">${reason}</span></span>`;
                }).join(' ');
                
                // Reasons tags
                const rTags = (e._reasons || []).map(x => `<span class="net-reason-tag">${x}</span>`).join('');
                
                tr.innerHTML = `
                    <td>${priorityBadge}</td>
                    <td>${e.PID ?? 'N/A'}</td>
                    <td style="font-weight:600; color:var(--text-secondary)">${e.Owner || '?'}</td>
                    <td>${e.Proto || ''}</td>
                    <td>${e.LocalAddr || '*'}:${e.LocalPort ?? '*'}</td>
                    <td style="font-weight:600">${e.ForeignAddr || '*'}:${e.ForeignPort ?? '*'}</td>
                    <td>${orgHTML}</td>
                    <td>${stateBadge}</td>
                    <td>${rTags}</td>
                    <td style="text-align:center">${pTags}</td>
                    <td>
                        <a href="${e._detail_file}" target="_blank" class="detail-json-link">JSON</a>
                    </td>
                `;
                
                body.appendChild(tr);
            });
            
            applyNetFilters();
        }

        function toggleNetPriority(priority) {
            const btn = document.getElementById(`btn-net-${priority.slice(0,3)}`);
            if (activeNetPriorities.has(priority)) {
                activeNetPriorities.delete(priority);
                btn.classList.remove('active');
            } else {
                activeNetPriorities.add(priority);
                btn.classList.add('active');
            }
            applyNetFilters();
        }

        // Quick filters toggler
        function toggleNetQuick(filter) {
            const btn = document.getElementById(`btn-net-${filter === 'flagged_process' ? 'flagged' : 'public'}`);
            if (activeNetQuickFilters.has(filter)) {
                activeNetQuickFilters.delete(filter);
                btn.classList.remove('active');
            } else {
                activeNetQuickFilters.add(filter);
                btn.classList.add('active');
            }
            applyNetFilters();
        }

        function applyNetFilters() {
            const q = document.getElementById('net-search').value.toLowerCase().trim();
            const rows = document.querySelectorAll('#net-table-body tr');
            let visibleCount = 0;
            
            rows.forEach(tr => {
                const prio = tr.dataset.priority;
                const reasons = tr.dataset.reasons;
                const searchstr = tr.dataset.search;
                
                const matchPriority = activeNetPriorities.has(prio);
                
                let matchQuick = true;
                if (activeNetQuickFilters.size > 0) {
                    matchQuick = [...activeNetQuickFilters].some(f => {
                        if (f === 'flagged_process') return reasons.includes('flagged_process');
                        if (f === 'public_ip') return reasons.includes('public_ip');
                        return false;
                    });
                }
                
                const matchSearch = !q || searchstr.includes(q);
                
                const isVisible = matchPriority && matchQuick && matchSearch;
                tr.classList.toggle('hidden', !isVisible);
                if (isVisible) visibleCount++;
            });
            
            const emptyEl = document.getElementById('net-empty');
            if (emptyEl) {
                emptyEl.style.display = (visibleCount === 0) ? 'block' : 'none';
            }
        }
        """
        return js


# ---------------------------------------------------------------------------
# Module 4: DLL List
# ---------------------------------------------------------------------------
class DllListModule(ForensicModule):
    def __init__(self):
        super().__init__("dll", "📚 Danh sách DLL")

    def run_analysis(self, image_path, context):
        print("\n[=== STEP 3.5: ANALYZING LOADED DLLS ===]")
        run_volatility(image_path, "windows.dlllist", DLLLIST_JSON)

        dlllist_data = load_vol_json(DLLLIST_JSON)
        if not dlllist_data:
            print("[-] Error: Unable to fetch dlllist data.")
            context["dll_entries"] = []
            return

        # Core system DLLs set for hijacking detection
        CORE_SYSTEM_DLLS = {
            "ntdll.dll",
            "kernel32.dll",
            "kernelbase.dll",
            "user32.dll",
            "gdi32.dll",
            "advapi32.dll",
            "ws2_32.dll",
            "wininet.dll",
            "shell32.dll",
            "shlwapi.dll",
            "crypt32.dll",
            "ole32.dll",
            "rpcrt4.dll",
            "dwmapi.dll",
            "uxtheme.dll",
            "version.dll",
            "comctl32.dll",
            "sechost.dll",
            "bcrypt.dll",
            "winhttp.dll",
        }

        # Build dynamic list of system DLLs based on their loaded paths across all processes
        system_dlls = set(CORE_SYSTEM_DLLS)
        for record in dlllist_data:
            path = record.get("Path")
            name = record.get("Name")
            if path and name:
                path_lower = str(path).lower()
                name_lower = str(name).lower()
                if (
                    path_lower.startswith("c:\\windows\\system32\\")
                    or path_lower.startswith("c:\\windows\\syswow64\\")
                    or path_lower.startswith("c:\\windows\\winsxs\\")
                ):
                    system_dlls.add(name_lower)

        # Build mapping of PID to Exe directory to detect same-directory side-loading
        process_exe_dirs = {}
        for record in dlllist_data:
            pid = str(record.get("PID", ""))
            path = record.get("Path")
            name = record.get("Name")
            proc = record.get("Process")
            if pid and path and name and proc:
                if name.lower() == proc.lower():
                    exe_dir = str(Path(path).parent).lower()
                    process_exe_dirs[pid] = exe_dir

        # Gather process nodes metadata from the process tab context
        process_nodes = context.get("process_nodes", [])
        process_metadata = {}
        for node in process_nodes:
            pid = str(node.get("pid"))
            process_metadata[pid] = {
                "name": node.get("name"),
                "ppid": node.get("ppid"),
                "flags": node.get("flags", []),  # Parent process flags
            }

        # Analyze DLL records and group them by host process
        grouped_dlls = defaultdict(list)
        for record in dlllist_data:
            pid = str(record.get("PID", ""))
            proc_name = str(record.get("Process", "Unknown"))
            dll_name = record.get("Name")
            dll_path = record.get("Path")
            base_addr = record.get("Base")
            size = record.get("Size")
            load_time = record.get("LoadTime")

            # Determine anomaly flags & messages
            anomaly_details = []
            category_red = False
            category_orange = False

            # 1. Structural / Format anomalies (Red Flag)
            if (
                not dll_name
                or not dll_path
                or str(dll_name).lower() == "null"
                or str(dll_path).lower() == "null"
            ):
                anomaly_details.append("• Tên/Đường dẫn trống (PEB Unlinked)")
                category_red = True
            else:
                # Weird extension check
                name_str = str(dll_name).lower()
                valid_exts = {
                    ".dll",
                    ".exe",
                    ".sys",
                    ".drv",
                    ".ocx",
                    ".cpl",
                    ".scr",
                    ".mui",
                }
                has_valid_ext = any(name_str.endswith(ext) for ext in valid_exts)
                if not has_valid_ext:
                    anomaly_details.append(
                        f"• Đuôi mở rộng lạ (Ngụy trang): {dll_name}"
                    )
                    category_red = True

            # 2. Path / Hijacking anomalies (Orange Flag)
            if dll_name and dll_path:
                name_lower = str(dll_name).lower()
                path_lower = str(dll_path).lower()
                is_system_dll = name_lower in system_dlls
                is_system_path = (
                    path_lower.startswith("c:\\windows\\system32\\")
                    or path_lower.startswith("c:\\windows\\syswow64\\")
                    or path_lower.startswith("c:\\windows\\winsxs\\")
                )

                # DLL Hijack Check (Core System DLL check & Path mismatch)
                if is_system_dll and not is_system_path:
                    anomaly_details.append("• DLL giả mạo hệ thống (Hijacking)")
                    category_orange = True

                # Same-Directory Side-loading check
                if pid in process_exe_dirs:
                    dll_dir = str(Path(dll_path).parent).lower()
                    exe_dir = process_exe_dirs[pid]
                    if dll_dir == exe_dir and is_system_dll and not is_system_path:
                        if "• DLL giả mạo hệ thống (Hijacking)" not in anomaly_details:
                            anomaly_details.append(
                                "• DLL giả mạo hệ thống (Hijacking - Same Directory)"
                            )
                            category_orange = True

                # Suspicious Path match from config
                is_suspicious = False
                for kw in SUSPICIOUS_PATH_KEYWORDS:
                    if kw in path_lower:
                        is_suspicious = True
                        break
                if is_suspicious:
                    anomaly_details.append(
                        f"• Đường dẫn đáng ngờ (Suspicious Path): {dll_path}"
                    )
                    category_orange = True

                # Untrusted Path (outside safe folders)
                is_safe = False
                for safe in SAFE_PATH_PREFIXES:
                    if path_lower.startswith(safe):
                        is_safe = True
                        break
                if not is_safe:
                    anomaly_details.append(
                        f"• Thư mục nạp lạ (Untrusted Path): {dll_path}"
                    )
                    category_orange = True

            # Address formatting
            base_str = f"0x{base_addr:012x}" if base_addr is not None else "N/A"

            # Size formatting
            if size is not None:
                size_str = (
                    f"{size / (1024 * 1024):.1f} MB"
                    if size >= 1024 * 1024
                    else f"{size / 1024:.0f} KB"
                )
            else:
                size_str = "N/A"

            # Load time formatting
            time_str = format_time(load_time)

            grouped_dlls[pid].append(
                {
                    "name": dll_name,
                    "path": dll_path,
                    "base_str": base_str,
                    "size_str": size_str,
                    "time_str": time_str,
                    "category_red": category_red,
                    "category_orange": category_orange,
                    "anomaly_details": anomaly_details,
                }
            )

        # Group and build final JSON payloads for JS mapping
        dll_groups = []
        for pid, pid_dlls in grouped_dlls.items():
            parent_flags = []
            host_name = "Unknown"

            if pid in process_metadata:
                host_name = process_metadata[pid]["name"]
                for pf in process_metadata[pid]["flags"]:
                    parent_flags.append(pf)
            else:
                if pid not in {"0", "4", ""}:
                    parent_flags.append(
                        [
                            "🔴",
                            "Tiến trình tàng hình — có trong dlllist nhưng ẩn khỏi pstree/psscan",
                            "hidden_process",
                        ]
                    )

            has_dll_red = any(d["category_red"] for d in pid_dlls)
            has_dll_orange = any(d["category_orange"] for d in pid_dlls)

            dll_groups.append(
                {
                    "pid": pid,
                    "name": host_name,
                    "parent_flags": parent_flags,
                    "dll_count": len(pid_dlls),
                    "has_red": has_dll_red,
                    "has_orange": has_dll_orange,
                    "dlls": pid_dlls,
                }
            )

        # Sort: priority with warning signs goes to top
        def get_sort_key(g):
            score = 0
            if g["has_red"] or any(f[0] in {"🔴", "🟣"} for f in g["parent_flags"]):
                score += 1000
            if g["has_orange"] or any(f[0] in {"🟠", "🔵"} for f in g["parent_flags"]):
                score += 100
            pid_num = int(g["pid"]) if g["pid"].isdigit() else 999999
            return (-score, pid_num)

        dll_groups.sort(key=get_sort_key)
        context["dll_entries"] = dll_groups

    def generate_html_tab(self, context):
        html = """
        <div class="tree-container">
            <div class="net-controls">
                <div class="filter-group">
                    <button class="btn-filter active" id="btn-dll-warn" onclick="toggleDllWarnOnly()">⚠️ Chỉ hiện có cảnh báo</button>
                    <button class="btn-filter" id="btn-dll-red" onclick="toggleDllFlag('red')">🔴 Có cờ cấu trúc</button>
                    <button class="btn-filter" id="btn-dll-orange" onclick="toggleDllFlag('orange')">🟠 Có cờ đường dẫn</button>
                </div>
                <div class="sep" style="width:1px; height:20px; background:var(--border-color)"></div>
                <input type="text" class="input-search" id="dll-search" style="flex:initial; width:280px; margin-left:auto" placeholder="Tìm PID, Tiến trình, DLL, Path..." oninput="applyDllFilters()">
            </div>

            <div id="dll-list-root"></div>
        </div>
        """
        return html

    def get_css(self):
        css = """
        /* DLL List Tab Styling */
        .dll-proc-node {
            margin-bottom: 8px;
        }
        .dll-proc-node .node-summary {
            background: #ffffff;
            border: 1px solid var(--border-color);
            padding: 10px 14px;
            height: auto;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: flex-start;
            gap: 8px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.02);
        }
        .dll-proc-node[open] > .node-summary {
            border-bottom-left-radius: 0;
            border-bottom-right-radius: 0;
            background: #f8fafc;
        }
        .dll-proc-node .node-details-card {
            border: 1px solid var(--border-color);
            border-top: none;
            border-radius: 0 0 8px 8px;
            background: #ffffff;
            margin-top: 0;
            margin-left: 0 !important;
            margin-right: 0;
            box-shadow: 0 4px 12px rgba(0,0,0,0.03);
            overflow: hidden;
        }
        .dll-row td {
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            padding: 8px 10px;
        }
        """
        return css

    def get_js(self):
        js = """
        // DLL List Controller
        let activeDllWarnOnly = true;
        let activeDllFlags = new Set(); // 'red', 'orange'

        function renderDllList() {
            const container = document.getElementById('dll-list-root');
            if (!container) return;
            container.innerHTML = '';
            
            DLL_GROUPS.forEach(g => {
                const details = document.createElement('details');
                details.className = 'tree-node dll-proc-node';
                details.id = `dll-node-${g.pid}`;
                
                const summary = document.createElement('summary');
                summary.className = 'node-summary';
                
                // Process Name Badge
                const nameSpan = document.createElement('span');
                nameSpan.className = 'proc-name';
                nameSpan.textContent = `${g.name} (PID: ${g.pid})`;
                if (g.parent_flags.length > 0 || g.has_red || g.has_orange) {
                    nameSpan.classList.add('has-anomaly');
                }
                
                // Parent Process Flags
                const pFlagsSpan = document.createElement('span');
                pFlagsSpan.className = 'flags-container';
                g.parent_flags.forEach(([emoji, reason]) => {
                    const f = document.createElement('span');
                    f.className = 'mini-flag';
                    f.innerHTML = `${emoji}<span class="tooltip-text">Tiến trình cha: ${reason}</span>`;
                    pFlagsSpan.appendChild(f);
                });
                
                // Summary of child DLL warnings
                const gFlagsSpan = document.createElement('span');
                gFlagsSpan.className = 'flags-container';
                gFlagsSpan.style.marginLeft = '12px';
                if (g.has_red) {
                    const f = document.createElement('span');
                    f.className = 'mini-flag';
                    f.innerHTML = `🔴<span class="tooltip-text">Chứa DLL có bất thường cấu trúc/định dạng</span>`;
                    gFlagsSpan.appendChild(f);
                }
                if (g.has_orange) {
                    const f = document.createElement('span');
                    f.className = 'mini-flag';
                    f.innerHTML = `🟠<span class="tooltip-text">Chứa DLL có bất thường đường dẫn/nạp tệp</span>`;
                    gFlagsSpan.appendChild(f);
                }
                
                // DLL Count Badge
                const countBadge = document.createElement('span');
                countBadge.className = 'pid-badge';
                countBadge.textContent = `${g.dll_count} DLLs`;
                
                // Toggle arrow
                const arrow = document.createElement('span');
                arrow.className = 'toggle-arrow';
                arrow.textContent = '▶';
                
                summary.append(nameSpan, pFlagsSpan, gFlagsSpan, countBadge, arrow);
                
                // Table of DLLs loaded by this process
                const detailsCard = document.createElement('div');
                detailsCard.className = 'node-details-card';
                
                const tableWrap = document.createElement('div');
                tableWrap.className = 'table-wrap';
                
                const table = document.createElement('table');
                table.className = 'net-table';
                
                table.innerHTML = `
                    <thead>
                        <tr>
                            <th style="width: 50px; text-align: center;">Cảnh báo</th>
                            <th>Base Address</th>
                            <th>Size</th>
                            <th>Load Time</th>
                            <th>DLL Name</th>
                            <th>Path</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${g.dlls.map(d => {
                            const dFlags = [];
                            if (d.category_red) dFlags.push('red');
                            if (d.category_orange) dFlags.push('orange');
                            
                            // Build flags HTML
                            let flagsHTML = '';
                            if (d.category_red) {
                                const redDetails = d.anomaly_details.filter(x => x.includes('Trống') || x.includes('lạ') || x.includes('PEB'));
                                flagsHTML += `<span class="mini-flag" style="margin-right:4px;">🔴<span class="tooltip-text">${redDetails.join('<br>')}</span></span>`;
                            }
                            if (d.category_orange) {
                                const orangeDetails = d.anomaly_details.filter(x => x.includes('giả mạo') || x.includes('đáng ngờ') || x.includes('nạp lạ') || x.includes('Hijack') || x.includes('Path') || x.includes('Prefix'));
                                flagsHTML += `<span class="mini-flag" style="margin-right:4px;">🟠<span class="tooltip-text">${orangeDetails.join('<br>')}</span></span>`;
                            }
                            
                            return `
                                <tr class="dll-row" data-flags="${dFlags.join(' ')}" data-search="${d.name || ''} ${d.path || ''}">
                                    <td style="text-align: center;">${flagsHTML}</td>
                                    <td><code>${d.base_str}</code></td>
                                    <td><code>${d.size_str}</code></td>
                                    <td><code>${d.time_str}</code></td>
                                    <td style="font-weight: 600; color: var(--text-secondary);">${d.name || 'N/A'}</td>
                                    <td style="word-break: break-all; white-space: normal;"><code>${d.path || 'N/A'}</code></td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                `;
                
                tableWrap.appendChild(table);
                detailsCard.appendChild(tableWrap);
                details.append(summary, detailsCard);
                
                // Set data attributes for searching and filtering
                const searchList = [g.pid, g.name].concat(g.dlls.map(d => `${d.name || ''} ${d.path || ''}`)).join(' ').toLowerCase();
                details.dataset.search = searchList;
                details.dataset.has_red = g.has_red;
                details.dataset.has_orange = g.has_orange;
                details.dataset.has_any_warn = (g.parent_flags.length > 0 || g.has_red || g.has_orange) ? 'true' : 'false';
                
                container.appendChild(details);
            });
            
            applyDllFilters();
        }

        function toggleDllWarnOnly() {
            activeDllWarnOnly = !activeDllWarnOnly;
            document.getElementById('btn-dll-warn').classList.toggle('active', activeDllWarnOnly);
            applyDllFilters();
        }

        function toggleDllFlag(flag) {
            const btn = document.getElementById(`btn-dll-${flag}`);
            if (activeDllFlags.has(flag)) {
                activeDllFlags.delete(flag);
                btn.classList.remove('active');
            } else {
                activeDllFlags.add(flag);
                btn.classList.add('active');
            }
            applyDllFilters();
        }

        function applyDllFilters() {
            const q = document.getElementById('dll-search').value.toLowerCase().trim();
            const nodes = document.querySelectorAll('.dll-proc-node');
            
            nodes.forEach(n => {
                const hasRed = n.dataset.has_red === 'true';
                const hasOrange = n.dataset.has_orange === 'true';
                const hasAnyWarn = n.dataset.has_any_warn === 'true';
                
                let matchWarn = true;
                if (activeDllWarnOnly) {
                    matchWarn = hasAnyWarn;
                }
                
                let matchFlags = true;
                if (activeDllFlags.size > 0) {
                    matchFlags = [...activeDllFlags].every(f => {
                        if (f === 'red') return hasRed;
                        if (f === 'orange') return hasOrange;
                        return false;
                    });
                }
                
                const matchSearch = !q || n.dataset.search.includes(q);
                
                const isVisible = matchWarn && matchFlags && matchSearch;
                n.style.display = isVisible ? '' : 'none';
                
                if (isVisible && q) {
                    n.open = true;
                    const rows = n.querySelectorAll('.dll-row');
                    rows.forEach(r => {
                        const searchstr = r.dataset.search.toLowerCase();
                        r.style.display = searchstr.includes(q) ? '' : 'none';
                    });
                } else if (isVisible) {
                    const rows = n.querySelectorAll('.dll-row');
                    rows.forEach(r => r.style.display = '');
                }
            });
        }
        """
        return js


# ---------------------------------------------------------------------------
# Dynamic Modules Registry
# ---------------------------------------------------------------------------
ACTIVE_MODULES = [
    SystemInfoModule(),
    ProcessMapModule(),
    NetworkMapModule(),
    DllListModule(),
]


# ---------------------------------------------------------------------------
# Core Analysis - Step 2 Helper Functions (Process Tree builder)
# ---------------------------------------------------------------------------
def is_suspicious_path(path):
    if not path:
        return False
    p = path.lower()
    for safe in SAFE_PATH_PREFIXES:
        if p.startswith(safe):
            return False
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in p:
            return True
    return False


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


def build_process_tree(pstree_data, psscan_data, getsids_data=None):
    pid_to_owner = {}
    if getsids_data:
        for rec in getsids_data:
            pid = str(rec.get("PID"))
            if pid not in pid_to_owner:
                owner_name = rec.get("Name")
                sid_str = rec.get("SID")
                if owner_name and not isinstance(owner_name, dict):
                    pid_to_owner[pid] = (str(owner_name), str(sid_str or "N/A"))
                elif sid_str and not isinstance(sid_str, dict):
                    pid_to_owner[pid] = (str(sid_str), str(sid_str))
                else:
                    pid_to_owner[pid] = ("Unknown", "N/A")

    flat_pstree = flatten_pstree(pstree_data)
    psscan_dict = {str(r.get("PID")): r for r in psscan_data}
    duplicate_flagged = build_duplicate_index(flat_pstree)
    malfind_map = build_malfind_index()

    processes = dict(flat_pstree)
    for pid, rec in psscan_dict.items():
        if pid not in processes:
            processes[pid] = rec

    # Generate ghost processes for missing parents to maintain hierarchy
    temp_children = defaultdict(list)
    for pid, rec in processes.items():
        ppid = str(rec.get("PPID", "N/A"))
        temp_children[ppid].append(pid)

    orphan_parents = set()
    for ppid in temp_children.keys():
        if ppid not in processes and ppid not in {"0", "N/A", "", "None"}:
            orphan_parents.add(ppid)

    for oppid in orphan_parents:
        processes[oppid] = {
            "PID": int(oppid) if oppid.isdigit() else oppid,
            "PPID": "N/A",
            "ImageFileName": "Unknown / Exited parent",
            "CreateTime": "N/A",
            "ExitTime": "N/A",
            "SessionId": "N/A",
            "is_ghost": True,
        }

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
    nodes = []

    def walk(node_pid, depth=0, is_last=True, prefix=""):
        rec = processes[node_pid]
        is_ghost = rec.get("is_ghost", False)
        ppid = str(rec.get("PPID", "N/A"))

        if is_ghost:
            name = f"<{rec.get('ImageFileName', 'Exited / Unknown')}>"
            session_id = "N/A"
            ctime = "N/A"
            extime = None
            best_path = "N/A"
            cmd = "Tiến trình cha đã kết thúc (exited) hoặc không tìm thấy trong RAM"
        else:
            name = str(rec.get("ImageFileName", "Unknown"))
            session_id = rec.get("SessionId")
            ctime = format_time(rec.get("CreateTime", "N/A"))
            extime = rec.get("ExitTime")
            best_path = get_best_path(rec)
            cmd = str(rec.get("Cmd") or "")

        flags = []

        if is_ghost:
            flags.append(
                (
                    "⚪",
                    "Tiến trình cha không tìm thấy trong RAM (đã kết thúc)",
                    "ghost_parent",
                )
            )
        else:
            # 🔴 Hidden / Stealth
            if node_pid not in pstree_pids:
                if extime:
                    flags.append(
                        (
                            "⚪",
                            "Tiến trình đã Exit — còn dấu vết trong psscan",
                            "exited",
                        )
                    )
                else:
                    flags.append(
                        (
                            "🔴",
                            "Tàng hình — có trong psscan nhưng bị ẩn khỏi pslist",
                            "hidden",
                        )
                    )

            # 🟠 Orphaned
            parent_node = processes.get(ppid, {})
            is_parent_ghost = parent_node.get("is_ghost", False)
            is_orphan = (
                (ppid not in processes or is_parent_ghost)
                and node_pid != "4"
                and ppid != "0"
            )
            if is_orphan:
                if name.lower() in ORPHAN_WHITELIST:
                    valid_paths, target_session = ORPHAN_WHITELIST[name.lower()]
                    if best_path not in valid_paths or (
                        target_session is not None and session_id != target_session
                    ):
                        flags.append(
                            (
                                "🟠",
                                "Mồ côi dị thường — cha PPID không tồn tại hoặc đã exited, path/session lệch whitelist",
                                "orphan_anomaly",
                            )
                        )
                else:
                    flags.append(
                        (
                            "🟠",
                            f"Mồ côi — cha PID {ppid} không tồn tại hoặc đã exited",
                            "orphan",
                        )
                    )

            # 🟡 Name Duplication
            if node_pid in duplicate_flagged:
                flags.append(
                    (
                        "🟡",
                        "Trùng tên với tiến trình khác nhưng khác path — có thể giả mạo hệ thống",
                        "duplicate",
                    )
                )

            # 🔵 Suspicious Path
            if is_suspicious_path(best_path):
                flags.append(("🔵", f"Path đáng ngờ: {best_path}", "suspicious_path"))

            # 🟣 RWX memory (Malfind)
            if node_pid in malfind_map:
                flags.append(
                    (
                        "🟣",
                        f"Vùng nhớ RWX ẩn danh — {len(malfind_map[node_pid])} vùng bị malfind đánh dấu",
                        "malfind",
                    )
                )

        flag_emojis = [f[0] for f in flags]
        detail_flags = [f"{f[0]} {f[1]}" for f in flags]

        if flags:
            flagged_pids[node_pid] = detail_flags

        # Save details to raw JSON
        raw_file = f"pid_{node_pid}.json"
        detail = dict(rec)
        detail["_flags"] = detail_flags
        detail["_best_extracted_path"] = best_path
        detail["MemoryAnomalies"] = malfind_map.get(node_pid, [])
        with open(RAW_NODES_DIR / raw_file, "w", encoding="utf-8") as f:
            json.dump(detail, f, indent=4, ensure_ascii=False)

        connector = "└─" if is_last else "├─"
        tree_prefix = prefix + connector

        user_info = pid_to_owner.get(node_pid, ("Unknown", "N/A"))
        user_name = user_info[0]
        user_sid = user_info[1]

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
                "flags": flags,
                "flag_emojis": flag_emojis,
                "raw_file": raw_file,
                "google_url": f"https://www.google.com/search?q={name}+process+windows",
                "threads": rec.get("Threads", "N/A"),
                "handles": rec.get("Handles", "N/A"),
                "session": session_id if session_id is not None else "N/A",
                "anomalies": malfind_map.get(node_pid, []),
                "is_ghost": is_ghost,
                "user": user_name,
                "sid": user_sid,
            }
        )

        children = sorted(
            children_map.get(node_pid, []), key=lambda x: int(x) if x.isdigit() else 0
        )
        for i, child_pid in enumerate(children):
            child_is_last = i == len(children) - 1
            ext = "    " if is_last else "│   "
            walk(child_pid, depth + 1, child_is_last, prefix + ext)

    for i, root_pid in enumerate(roots):
        walk(root_pid, depth=0, is_last=(i == len(roots) - 1), prefix="")

    return nodes, flagged_pids


# ---------------------------------------------------------------------------
# Core Analysis - Step 3 Helper Functions (Network connections analysis)
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


def load_ip_cache():
    if NETSCAN_IP_CACHE.exists():
        try:
            with open(NETSCAN_IP_CACHE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def friendly_org(org_str):
    if not org_str:
        return "Unknown"
    lower = org_str.lower()
    for keyword, label in KNOWN_ORGS.items():
        if keyword in lower:
            return label
    return org_str


def enrich_ips(public_ips):
    cache = load_ip_cache()
    to_lookup = [ip for ip in public_ips if ip not in cache]

    if not to_lookup:
        print(f"[+] IP cache hit: {len(cache)} IPs, no API lookup needed.")
        return cache

    print(f"[+] Looking up {len(to_lookup)} new IPs via ip-api.com...")

    # ip-api batch: max 100 IPs/request
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

            if i + BATCH < len(to_lookup):
                time.sleep(1.5)

        except urllib.error.URLError as ex:
            print(f"[-] Cannot call ip-api.com: {ex}. Skipping enrich.")
            break

    try:
        NETSCAN_IP_CACHE.parent.mkdir(parents=True, exist_ok=True)
        with open(NETSCAN_IP_CACHE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception as ex:
        print(f"[-] Cannot save IP cache: {ex}")

    print(f"[+] IP Geolocation enrichment done. Cached: {len(cache)}")
    return cache


def deduplicate_connections(data):
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


def tag_net_priority(e, flagged_pids):
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


def run_network_analysis(image_path, flagged_pids):
    run_volatility(image_path, "windows.netscan", NETSCAN_JSON)

    try:
        raw_netscan = load_vol_json(NETSCAN_JSON)
    except Exception as e:
        print(f"[-] Error reading netscan.json: {e}")
        return [], {}

    deduped = deduplicate_connections(raw_netscan)
    public_ips = list(
        {e.get("ForeignAddr") for e in deduped if is_public_ip(e.get("ForeignAddr"))}
    )
    ip_info = enrich_ips(public_ips)

    groups = {"high": [], "medium": [], "low": []}
    for idx, e in enumerate(deduped):
        foreign_addr = e.get("ForeignAddr")
        pid = str(e.get("PID") or "")

        # Geolocation ASN injection
        if is_public_ip(foreign_addr) and foreign_addr in ip_info:
            info = ip_info[foreign_addr]
            e["_org"] = info.get("org", "")
            e["_label"] = info.get("label", "")
            e["_country"] = info.get("country", "")
            e["_as"] = info.get("as", "")

        if pid in flagged_pids:
            e["_process_flags"] = flagged_pids[pid]

        priority, reasons = tag_net_priority(e, flagged_pids)
        e["_priority"] = priority
        e["_reasons"] = reasons

        # Save connection details JSON
        detail_file = f"entry_{idx:04d}.json"
        with open(NETSCAN_DETAIL_DIR / detail_file, "w", encoding="utf-8") as f:
            json.dump(e, f, indent=4, ensure_ascii=False)
        e["_detail_file"] = f"netscan/detail/{detail_file}"

        groups[priority].append(e)

    summary = {
        "total_raw": len(raw_netscan),
        "after_dedup": len(deduped),
        "high": len(groups["high"]),
        "medium": len(groups["medium"]),
        "low": len(groups["low"]),
    }

    with open(NETSCAN_SUMMARY_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    all_tagged = groups["high"] + groups["medium"] + groups["low"]
    return all_tagged, summary


# ---------------------------------------------------------------------------
# Global Dashboard Compiler
# ---------------------------------------------------------------------------
def generate_combined_dashboard(context):
    print("\n[=== STEP 4: GENERATING UNIFIED HTML DASHBOARD ===]")

    os_data = context.get("os_data", {})
    evidence_file = os_data.get("evidence_file", "Unknown")
    process_nodes = context.get("process_nodes", [])
    net_summary = context.get("net_summary", {})

    flagged_pids_count = len([n for n in process_nodes if len(n["flags"]) > 0])

    # 1. Build Tab Navigation Buttons
    tab_buttons_html = ""
    for idx, mod in enumerate(ACTIVE_MODULES):
        active_class = "active" if idx == 0 else ""
        tab_buttons_html += f'<button class="tab-btn {active_class}" onclick="switchTab(event, \'tab-{mod.module_id}\')">{mod.tab_title}</button>\n'

    # 2. Build Tab Contents
    tab_contents_html = ""
    for idx, mod in enumerate(ACTIVE_MODULES):
        active_class = "active" if idx == 0 else ""
        tab_contents_html += f'<div id="tab-{mod.module_id}" class="tab-content {active_class}">\n{mod.generate_html_tab(context)}\n</div>\n'

    # 3. Collect CSS & JS rules from all modules
    combined_css = ""
    combined_js = ""
    for mod in ACTIVE_MODULES:
        combined_css += (
            f"\n/* --- CSS for Module: {mod.module_id} --- */\n" + mod.get_css()
        )
        combined_js += f"\n// --- JS for Module: {mod.module_id} ---\n" + mod.get_js()

    # Read dashboard template and replace variables (avoids f-string curly brace escaping issues)
    html_template = get_dashboard_html_template()

    html_output = (
        html_template.replace("{EVIDENCE_FILE}", evidence_file)
        .replace("{TOTAL_PROCESSES}", str(len(process_nodes)))
        .replace("{FLAGGED_PROCESSES}", str(flagged_pids_count))
        .replace("{TOTAL_CONNECTIONS}", str(net_summary.get("after_dedup", 0)))
        .replace("{TAB_BUTTONS}", tab_buttons_html)
        .replace("{TAB_CONTENTS}", tab_contents_html)
        .replace("{EMBEDDED_CSS}", combined_css)
        .replace("{EMBEDDED_JS}", combined_js)
        .replace("{PROCESS_NODES_JSON}", json.dumps(process_nodes, ensure_ascii=False))
        .replace(
            "{NETWORK_ENTRIES_JSON}",
            json.dumps(context.get("network_entries", []), ensure_ascii=False),
        )
        .replace(
            "{DLL_ENTRIES_JSON}",
            json.dumps(context.get("dll_entries", []), ensure_ascii=False),
        )
    )

    with open(DASHBOARD_HTML, "w", encoding="utf-8") as f:
        f.write(html_output)

    print(f"[✓] Saved Unified Dashboard to {DASHBOARD_HTML.name}")


# ---------------------------------------------------------------------------
# HTML Core Dashboard Base Template
# ---------------------------------------------------------------------------
def get_dashboard_html_template():
    return """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Báo Cáo Phân Tích RAM Forensic</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

:root {
    --bg-main: #f8fafc;
    --bg-surface: #ffffff;
    --border-color: #e2e8f0;
    --text-primary: #0f172a;
    --text-secondary: #475569;
    --text-muted: #64748b;
    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --accent-light: #eff6ff;
    
    /* Flags Light Pastel Colors */
    --color-stealth-bg: #fee2e2;
    --color-stealth-text: #991b1b;
    
    --color-orphan-bg: #ffedd5;
    --color-orphan-text: #9a3412;
    
    --color-duplicate-bg: #fef9c3;
    --color-duplicate-text: #854d0e;
    
    --color-path-bg: #dbeafe;
    --color-path-text: #1e40af;
    
    --color-rwx-bg: #f3e8ff;
    --color-rwx-text: #6b21a8;
    
    --color-exited-bg: #f1f5f9;
    --color-exited-text: #334155;
    
    --color-ok-bg: #dcfce7;
    --color-ok-text: #166534;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    background-color: var(--bg-main);
    color: var(--text-primary);
    font-family: 'IBM Plex Sans', sans-serif;
    font-size: 14px;
    line-height: 1.5;
    padding: 24px;
}

.dashboard {
    max-width: 1440px;
    margin: 0 auto;
}

/* Header */
header {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
}

.header-title h1 {
    font-size: 22px;
    font-weight: 700;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 8px;
}

.header-title p {
    font-size: 13px;
    color: var(--text-muted);
    margin-top: 4px;
    word-break: break-all;
}

.header-stats {
    display: flex;
    gap: 16px;
}

.stat-pill {
    background: var(--bg-main);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 10px 16px;
    text-align: center;
}

.stat-pill .num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
}

.stat-pill .label {
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 2px;
}

/* Navigation Tabs */
.tabs {
    display: flex;
    gap: 8px;
    border-bottom: 2px solid var(--border-color);
    margin-bottom: 24px;
    padding-bottom: 2px;
}

.tab-btn {
    background: none;
    border: none;
    padding: 12px 20px;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-secondary);
    cursor: pointer;
    border-radius: 8px 8px 0 0;
    transition: all 0.15s ease;
    border-bottom: 3px solid transparent;
    display: flex;
    align-items: center;
    gap: 8px;
}

.tab-btn:hover {
    color: var(--accent);
    background: var(--accent-light);
}

.tab-btn.active {
    color: var(--accent);
    border-bottom: 3px solid var(--accent);
    background: var(--accent-light);
}

.tab-content {
    display: none;
    animation: fadeIn 0.2s ease-in-out;
}

.tab-content.active {
    display: block;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(4px); }
    to { opacity: 1; transform: translateY(0); }
}

/* Base Tab Layout Grid and Cards (System Info) */
.sys-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 20px;
    margin-bottom: 24px;
}

.card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
}

.card h3 {
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 10px;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.info-table {
    width: 100%;
    border-collapse: collapse;
}

.info-table td {
    padding: 8px 0;
    vertical-align: top;
}

.info-table td.key {
    font-weight: 500;
    color: var(--text-secondary);
    width: 40%;
}

.info-table td.val {
    font-family: 'JetBrains Mono', monospace;
    color: var(--text-primary);
    word-break: break-all;
}

.note-box {
    background: #f8fafc;
    border-left: 4px solid var(--accent);
    padding: 12px 16px;
    border-radius: 0 8px 8px 0;
    margin-top: 10px;
}

.note-box p {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 6px;
}

.note-box p:last-child {
    margin-bottom: 0;
}

/* Embedded CSS from Modules */
{EMBEDDED_CSS}
</style>
</head>
<body>
<div class="dashboard">
    <header>
        <div class="header-title">
            <h1>🔬 Báo Cáo RAM Forensic</h1>
            <p>File Dump: {EVIDENCE_FILE}</p>
        </div>
        <div class="header-stats">
            <div class="stat-pill">
                <div class="num" id="stat-total-proc">{TOTAL_PROCESSES}</div>
                <div class="label">Tiến trình</div>
            </div>
            <div class="stat-pill">
                <div class="num" id="stat-flagged-proc" style="color:var(--color-orphan-text)">{FLAGGED_PROCESSES}</div>
                <div class="label">Tiến trình bị cờ</div>
            </div>
            <div class="stat-pill">
                <div class="num" id="stat-total-connections">{TOTAL_CONNECTIONS}</div>
                <div class="label">Kết kết nối mạng</div>
            </div>
        </div>
    </header>

    <div class="tabs">
        {TAB_BUTTONS}
    </div>

    {TAB_CONTENTS}
</div>

<script>
// Combined injected data from analysis
const PROCESSES = {PROCESS_NODES_JSON};
const NETWORK = {NETWORK_ENTRIES_JSON};
const DLL_GROUPS = {DLL_ENTRIES_JSON};

// Tab Switcher Controller
function switchTab(evt, tabId) {
    const contents = document.querySelectorAll('.tab-content');
    contents.forEach(c => c.classList.remove('active'));

    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(b => b.classList.remove('active'));

    document.getElementById(tabId).classList.add('active');
    evt.currentTarget.classList.add('active');
}

// Embedded JavaScript logic from Modules
{EMBEDDED_JS}

// Initialize rendering on load
window.onload = function() {
    if (typeof renderProcessTree === 'function') renderProcessTree();
    if (typeof renderNetworkTable === 'function') renderNetworkTable();
    if (typeof renderDllList === 'function') renderDllList();
};
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Main Runner Pipeline
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python tool/forensic_analyzer.py <ram_dump_path> [-full]")
        sys.exit(1)

    ram_path = Path(sys.argv[1])
    is_full_scan = "-full" in sys.argv

    if not ram_path.exists():
        print(f"[-] Error: RAM dump file not found: {ram_path}")
        sys.exit(1)

    # Initialize shared context for modules
    context = {
        "is_full_scan": is_full_scan,
        "os_data": {},
        "process_nodes": [],
        "flagged_pids": {},
        "network_entries": [],
        "net_summary": {},
    }

    # Initialize workspace
    clean_workspace()

    # Execute analysis on all active modules sequentially
    for mod in ACTIVE_MODULES:
        mod.run_analysis(ram_path, context)

    # Generate final combined report
    generate_combined_dashboard(context)

    print("\n[✓] ANALYSIS COMPLETED SUCCESSFULLY!")
    print(f"    Dashboard: {DASHBOARD_HTML.resolve()}")
    print(f"    Nodes details: {RAW_NODES_DIR.resolve()}")
    print(f"    Connection details: {NETSCAN_DETAIL_DIR.resolve()}")


if __name__ == "__main__":
    main()
