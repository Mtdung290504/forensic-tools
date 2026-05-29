from pathlib import Path

VOLATILITY_PATH = Path("/forensic/volatility3-stable/vol.py")
OUTPUT_DIR = Path("output")

# Tri thức bộ nhớ: Tiến trình hệ thống được phép mồ côi kèm Session ID bắt buộc
# Cấu trúc: "tên_tiến_trình": ( {tập_hợp_đường_dẫn_hợp_lệ}, session_id_hợp_lệ )
# Nếu session_id_hợp_lệ là None nghĩa là tiến trình đó chấp nhận mọi Session
ORPHAN_WHITELIST = {
    "csrss.exe": ({"c:\\windows\\system32\\csrss.exe"}, None),
    "wininit.exe": ({"c:\\windows\\system32\\wininit.exe"}, 0),
    "winlogon.exe": ({"c:\\windows\\system32\\winlogon.exe"}, None),
    "explorer.exe": ({"c:\\windows\\explorer.exe"}, None),
    "lsass.exe": ({"c:\\windows\\system32\\lsass.exe"}, 0),
    "lsm.exe": ({"c:\\windows\\system32\\lsm.exe"}, 0),
    "smss.exe": ({"c:\\windows\\system32\\smss.exe"}, 0),
}
