import subprocess
import json
import re
import sys
from config import OUTPUT_DIR, VOLATILITY_PATH, Path

OUTPUT_FILE = OUTPUT_DIR / "windows_info_summary.json"


def get_dump_path():
    if len(sys.argv) != 2:
        print("Usage:")
        print("  py window-info.py <ram_dump_path>")
        sys.exit(1)

    ram_path = Path(sys.argv[1])

    if not ram_path.exists():
        print(f"[-] File not found: {ram_path}")
        sys.exit(1)

    return ram_path


def get_windows_info(ram_dump_path: Path):
    cmd = [
        "python",
        VOLATILITY_PATH,
        "-f",
        str(ram_dump_path),
        "windows.info",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    print(result.stdout)

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    return result.stdout


def parse_windows_info(raw_output: str):
    parsed = {}

    for line in raw_output.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("-"):
            continue

        parts = re.split(r"\s{2,}|\t+", line)

        if len(parts) >= 2:
            key = parts[0].strip()
            value = " ".join(parts[1:]).strip()
            parsed[key] = value

    return parsed


def normalize(parsed: dict):
    buildlab = parsed.get("NTBuildLab", "")

    major = parsed.get("NtMajorVersion")
    minor = parsed.get("NtMinorVersion")

    version_map = {
        ("6", "1"): "Windows 7",
        ("6", "2"): "Windows 8",
        ("6", "3"): "Windows 8.1",
        ("10", "0"): "Windows 10/11",
    }

    os_name = version_map.get((major, minor), "Unknown Windows")

    useful = {}
    useful["architecture"] = "64-bit" if parsed.get("Is64Bit") == "True" else "32-bit"
    useful["os"] = {
        "name": os_name,
        "service_pack": (
            f"SP{parsed.get('CSDVersion')}" if parsed.get("CSDVersion") else ""
        ),
        "build_lab": buildlab,
    }
    useful["system_time_utc"] = parsed.get("SystemTime", "Unknown")
    useful["system_root"] = parsed.get("NtSystemRoot", "Unknown")
    useful["processors"] = parsed.get("KeNumberProcessors", "Unknown")
    useful["kernel"] = {
        "base_address": parsed.get("Kernel Base"),
        "symbol_file": parsed.get("Symbols"),
    }

    return useful


def build_context(useful: dict):
    os_info = useful.get("os", {})

    os_name = os_info.get("name", "Unknown OS")
    service_pack = os_info.get("service_pack", "")
    architecture = useful.get("architecture", "Unknown")
    system_time = useful.get("system_time_utc", "Unknown")

    summary = (
        f"RAM dump identified as "
        f"{os_name} "
        f"{service_pack} "
        f"{architecture}. "
        f"System time: "
        f"{system_time}."
    )

    return {
        "summary": " ".join(summary.split()),
        "analysis_notes": [
            "OS version used as baseline for plugin compatibility.",
            "System time used as investigation timeline reference.",
            "System root used to validate suspicious paths.",
            "Architecture used for process and DLL interpretation.",
        ],
    }


def main(ram_dump=None):
    ram_dump = get_dump_path()
    OUTPUT_DIR.mkdir(exist_ok=True)

    raw_output = get_windows_info(ram_dump)
    parsed_raw = parse_windows_info(raw_output)
    useful = normalize(parsed_raw)
    forensic_context = build_context(useful)

    result = {
        "evidence_file": str(ram_dump.resolve()),
        "parsed": useful,
        "forensic_context": forensic_context,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"[+] Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
