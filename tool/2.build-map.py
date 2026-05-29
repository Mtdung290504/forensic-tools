import subprocess
import json
import sys
import shutil
from collections import defaultdict
from datetime import datetime

from config import VOLATILITY_PATH, OUTPUT_DIR, ORPHAN_WHITELIST

PSTREE_JSON = OUTPUT_DIR / "pstree.json"
PSSCAN_JSON = OUTPUT_DIR / "psscan.json"
MALFIND_JSON = OUTPUT_DIR / "malfind.json"
RAW_NODES_DIR = OUTPUT_DIR / "raw_nodes"
MD_OUTPUT = OUTPUT_DIR / "Process_Map.md"


def clean_old_workspace():
    print("[+] Đang dọn dẹp workspace cũ...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for f in [PSTREE_JSON, PSSCAN_JSON, MALFIND_JSON, MD_OUTPUT]:
        if f.exists():
            f.unlink()

    if RAW_NODES_DIR.exists():
        shutil.rmtree(RAW_NODES_DIR)
    RAW_NODES_DIR.mkdir(parents=True, exist_ok=True)
    print("[+] Workspace sạch!")


def _run_vol(image_path, plugin, out_path, extra_args=None):
    cmd = ["python", str(VOLATILITY_PATH), "-f", image_path, "-r", "json", plugin]
    if extra_args:
        cmd.extend(extra_args)

    with open(out_path, "w", encoding="utf-8") as out:
        subprocess.run(cmd, stdout=out)


def load_vol_json(filepath):
    """Trích xuất JSON an toàn, phớt lờ mọi Warning rác từ Volatility 3"""
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


def get_best_path(rec):
    raw_path = str(rec.get("Path") or "").lower().strip()
    audit_path = str(rec.get("Audit") or "").lower().strip()

    best_path = raw_path if raw_path and raw_path != "null" else audit_path

    if best_path.startswith("\\device\\harddiskvolume"):
        parts = best_path.split("\\", 3)
        if len(parts) >= 4:
            return "c:\\" + parts[3]
    return best_path


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
    malfind_data = load_vol_json(MALFIND_JSON)

    for entry in malfind_data:
        pid = str(entry.get("PID", "N/A"))
        evidence = {
            "StartVPN": entry.get("Start VPN"),
            "Protection": entry.get("Protection"),
            "Hexdump": entry.get("Hexdump", ""),
        }
        malfind_map[pid].append(evidence)
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
    psscan_dict = {str(rec.get("PID")): rec for rec in psscan_data}

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

        is_suspect = False

        if pid not in pstree_pids and not extime:
            is_suspect = True

        is_orphan = ppid not in processes and pid != "4" and ppid != "0"
        if is_orphan:
            if name in ORPHAN_WHITELIST:
                valid_paths, target_session = ORPHAN_WHITELIST[name]
                if best_path not in valid_paths or (
                    target_session is not None and session_id != target_session
                ):
                    is_suspect = True
            else:
                is_suspect = True

        if pid in duplicate_flagged:
            is_suspect = True

        if is_suspect:
            suspects.add(pid)

    return list(suspects)


def build_process_tree(pstree_data, psscan_data):
    flat_pstree = flatten_pstree(pstree_data)
    psscan_dict = {str(rec.get("PID")): rec for rec in psscan_data}
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
        session_id = rec.get("SessionId")
        ctime = format_time(rec.get("CreateTime", "N/A"))
        extime = rec.get("ExitTime")
        best_path = get_best_path(rec)

        md_flags = []
        detail_flags = []

        if node_pid not in pstree_pids:
            if extime:
                md_flags.append("⚪")
                detail_flags.append("⚪ `[Đã Exit]`")
            else:
                md_flags.append("🔴")
                detail_flags.append("🔴 `[Tàng hình]`")

        is_orphan = ppid not in processes and node_pid != "4" and ppid != "0"
        if is_orphan:
            if name.lower() in ORPHAN_WHITELIST:
                valid_paths, target_session = ORPHAN_WHITELIST[name.lower()]
                if best_path not in valid_paths or (
                    target_session is not None and session_id != target_session
                ):
                    md_flags.append("🟠")
                    detail_flags.append(f"🟠 `[Mồ côi dị thường - Cha: {ppid}]`")
            else:
                md_flags.append("🟠")
                detail_flags.append(f"🟠 `[Mồ côi - Cha: {ppid}]`")

        if node_pid in duplicate_flagged:
            md_flags.append("🟡")
            detail_flags.append("🟡 `[Trùng tên]`")

        if node_pid in malfind_map:
            md_flags.append("🟣")
            detail_flags.append("🟣 `[Vùng nhớ RWX]`")

        status = (" " + "".join(md_flags)) if md_flags else ""

        raw_file = f"pid_{node_pid}.json"
        detail = dict(rec)
        detail["_flags"] = detail_flags
        detail["_best_extracted_path"] = best_path
        detail["MemoryAnomalies"] = malfind_map.get(node_pid, [])

        if md_flags:
            flagged_pids[node_pid] = detail_flags

        with open(RAW_NODES_DIR / raw_file, "w", encoding="utf-8") as f:
            json.dump(detail, f, indent=4, ensure_ascii=False)

        connector = "└── " if is_last else "├── "
        line = f"{prefix}{connector}**{name}** (PID: {node_pid}){status} — *{ctime}* | [Chi tiết](./raw_nodes/{raw_file})\n"

        children = sorted(
            children_map.get(node_pid, []), key=lambda x: int(x) if x.isdigit() else 0
        )
        for i, child_pid in enumerate(children):
            ext = "    " if is_last else "│   "
            line += render_tree(child_pid, prefix + ext, i == len(children) - 1)

        return line

    tree_md = ""
    for i, root_pid in enumerate(roots):
        tree_md += render_tree(root_pid, is_last=(i == len(roots) - 1))

    return tree_md, flagged_pids


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
        print("\n[!] Chế độ FULL SCAN: Đang quét malfind TOÀN BỘ RAM (Sẽ rất lâu)...")
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
                f"[!] Bắn malfind vào {len(suspect_pids)} mục tiêu khả nghi (PID: {', '.join(suspect_pids)})..."
            )
            # Nối mảng tham số để truyền chuẩn cú pháp cho subprocess
            malfind_args = ["--pid"] + suspect_pids
            _run_vol(
                image_path,
                "windows.malware.malfind",
                MALFIND_JSON,
                extra_args=malfind_args,
            )

    print("\n[+] Đang tổng hợp phả hệ và vẽ cây...")
    md = "# PROCESS TREE VIEW\n\n"
    md += "> **Tips:** `Ctrl` + Click `[Chi tiết]` để xem data thô.\n\n"
    md += "> **Cờ:** 🔴 Tàng hình | ⚪ Đã Exit | 🟠 Mồ côi | 🟡 Trùng tên | 🟣 RWX\n\n"

    tree_md, flagged_pids = build_process_tree(pstree_data, psscan_data)
    md += tree_md

    with open(OUTPUT_DIR / "flagged_pids.json", "w", encoding="utf-8") as f:
        json.dump(flagged_pids, f, indent=2, ensure_ascii=False)

    with open(MD_OUTPUT, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"\n[✓] HOÀN THÀNH!")
    print(f"    Báo cáo : {MD_OUTPUT}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Cách dùng: python src/map_builder.py <đường_dẫn_file_ram> [-full]")
        sys.exit(1)

    ram_file = sys.argv[1]
    is_full = "-full" in sys.argv

    run_pipeline(ram_file, is_full)
