import subprocess
import json
import sys
import shutil
from collections import defaultdict
from datetime import datetime

from config import VOLATILITY_PATH, OUTPUT_DIR, ORPHAN_WHITELIST

PSTREE_JSON = OUTPUT_DIR / "pstree.json"
PSSCAN_JSON = OUTPUT_DIR / "psscan.json"
RAW_NODES_DIR = OUTPUT_DIR / "raw_nodes"
MD_OUTPUT = OUTPUT_DIR / "Process_Map.md"


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------


def clean_old_workspace():
    print("[+] Đang dọn dẹp workspace cũ...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for f in [PSTREE_JSON, PSSCAN_JSON, MD_OUTPUT]:
        if f.exists():
            f.unlink()

    if RAW_NODES_DIR.exists():
        shutil.rmtree(RAW_NODES_DIR)
    RAW_NODES_DIR.mkdir(parents=True, exist_ok=True)

    print("[+] Workspace sạch!")


# ---------------------------------------------------------------------------
# Volatility
# ---------------------------------------------------------------------------


def _run_vol(image_path, plugin, out_path):
    print(f"[+] Đang chạy {plugin}...")
    with open(out_path, "w", encoding="utf-8") as out:
        subprocess.run(
            ["python", str(VOLATILITY_PATH), "-f", image_path, "-r", "json", plugin],
            stdout=out,
        )


def run_volatility(image_path):
    _run_vol(image_path, "windows.pstree", PSTREE_JSON)
    _run_vol(image_path, "windows.psscan", PSSCAN_JSON)


# ---------------------------------------------------------------------------
# Flatten pstree
# ---------------------------------------------------------------------------


def flatten_pstree(nodes, result=None):
    if result is None:
        result = {}
    for node in nodes:
        pid = str(node.get("PID", "N/A"))
        children = node.get("__children", [])
        clean = {k: v for k, v in node.items() if k != "__children"}
        result[pid] = clean
        if children:
            flatten_pstree(children, result)
    return result


# ---------------------------------------------------------------------------
# Duplicate-name index (cùng tên, khác path)
# ---------------------------------------------------------------------------


def build_duplicate_index(flat_processes):
    name_groups = defaultdict(list)
    for pid, rec in flat_processes.items():
        name = str(rec.get("ImageFileName", "")).lower()
        path = str(rec.get("Path") or "").lower().strip()
        name_groups[name].append((pid, path))

    flagged = set()
    for name, members in name_groups.items():
        paths = {p for _, p in members if p}
        if len(paths) > 1:
            for pid, _ in members:
                flagged.add(pid)

    return flagged


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def format_time(t_str):
    if not t_str or t_str == "N/A":
        return "N/A"
    try:
        dt = datetime.strptime(str(t_str)[:19], "%Y-%m-%dT%H:%M:%S")
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return str(t_str)


# ---------------------------------------------------------------------------
# Build tree
# ---------------------------------------------------------------------------


def build_process_tree(flat_pstree, psscan_pids, duplicate_flagged):
    processes = dict(flat_pstree)

    # Thêm tiến trình tàng hình từ psscan
    for pid in psscan_pids:
        if pid not in processes:
            processes[pid] = {"PID": pid, "ImageFileName": "???", "_hidden": True}

    children_map = defaultdict(list)
    for pid, rec in processes.items():
        ppid = str(rec.get("PPID", "N/A"))
        children_map[ppid].append(pid)

    roots = [
        pid
        for pid, rec in processes.items()
        if str(rec.get("PPID", "N/A")) not in processes
    ]
    roots.sort(key=lambda x: int(x) if x.isdigit() else 0)

    pstree_pids = set(flat_pstree.keys())

    def render_tree(node_pid, prefix="", is_last=True):
        rec = processes[node_pid]
        ppid = str(rec.get("PPID", "N/A"))
        name = str(rec.get("ImageFileName", "Unknown"))
        node_path = str(rec.get("Path") or "").lower().strip()
        ctime = format_time(rec.get("CreateTime", "N/A"))

        flags = []

        # Luật 1: Tàng hình
        if node_pid not in pstree_pids:
            flags.append("🔴")

        # Luật 2: Mồ côi — lọc qua whitelist tên + path
        is_orphan = ppid not in processes and node_pid != "4" and ppid != "0"
        if is_orphan:
            valid_paths = ORPHAN_WHITELIST.get(name.lower(), set())
            if node_path not in valid_paths:
                flags.append(f"🟠 `[Cha: {ppid}]`")

        # Luật 3: Trùng tên, khác path
        if node_pid in duplicate_flagged:
            flags.append("🟡")

        status = (" " + " ".join(flags)) if flags else ""

        # Ghi raw node
        raw_file = f"{node_pid}.json"
        detail = dict(rec)
        detail["_flags"] = flags
        with open(RAW_NODES_DIR / raw_file, "w", encoding="utf-8") as f:
            json.dump(detail, f, indent=4, ensure_ascii=False)

        connector = "└── " if is_last else "├── "
        line = (
            f"{prefix}{connector}**{name}** (PID: {node_pid}){status}"
            f" — *{ctime}* | [Details](./raw_nodes/{raw_file})\n"
        )

        children = sorted(
            children_map.get(node_pid, []),
            key=lambda x: int(x) if x.isdigit() else 0,
        )
        for i, child_pid in enumerate(children):
            ext = "    " if is_last else "│   "
            line += render_tree(child_pid, prefix + ext, i == len(children) - 1)

        return line

    tree_md = ""
    for i, root_pid in enumerate(roots):
        tree_md += render_tree(root_pid, is_last=(i == len(roots) - 1))

    return tree_md


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def build_cross_view_map():
    print("[+] Đang phân tích phả hệ và vẽ cây...")

    try:
        with open(PSTREE_JSON, "r", encoding="utf-8") as f:
            pstree_data = json.load(f)
        with open(PSSCAN_JSON, "r", encoding="utf-8") as f:
            psscan_data = json.load(f)
    except FileNotFoundError as e:
        print(f"[-] Lỗi: {e}")
        return

    flat_pstree = flatten_pstree(pstree_data)
    psscan_pids = {str(rec.get("PID")) for rec in psscan_data}
    duplicate_flagged = build_duplicate_index(flat_pstree)

    md = "# PROCESS TREE VIEW\n\n"
    md += "> **Tips:** `Ctrl` + Click `[Chi tiết]` để xem data thô.\n\n"
    md += "> **Cờ:** 🔴 Tàng hình | 🟠 Cha không tồn tại | 🟡 Trùng tên–khác path\n\n"
    md += build_process_tree(flat_pstree, psscan_pids, duplicate_flagged)

    with open(MD_OUTPUT, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"\n[✓] Hoàn thành!")
    print(f"    Báo cáo : {MD_OUTPUT}")
    print(f"    Chi tiết: {RAW_NODES_DIR}/")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Cách dùng: python src/map_builder.py <đường_dẫn_file_ram>")
        sys.exit(1)

    ram_file = sys.argv[1]
    clean_old_workspace()
    run_volatility(ram_file)
    build_cross_view_map()
