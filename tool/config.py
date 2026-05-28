from pathlib import Path

VOLATILITY_PATH = Path("/forensic/volatility3-stable/vol.py")
OUTPUT_DIR = Path("output")

# Tiến trình hệ thống được phép mồ côi (smss.exe tự hủy sau khi sinh)
# Key: tên (lower), Value: set path hợp lệ (lower)
ORPHAN_WHITELIST = {
    "csrss.exe": {"c:\\windows\\system32\\csrss.exe"},
    "winlogon.exe": {"c:\\windows\\system32\\winlogon.exe"},
    "wininit.exe": {"c:\\windows\\system32\\wininit.exe"},
    "explorer.exe": {"c:\\windows\\explorer.exe"},
    "lsass.exe": {"c:\\windows\\system32\\lsass.exe"},
    "lsm.exe": {"c:\\windows\\system32\\lsm.exe"},
    "smss.exe": {"c:\\windows\\system32\\smss.exe"},
}
