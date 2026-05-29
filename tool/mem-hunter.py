import subprocess
import re
import sys
from pathlib import Path

VOLATILITY_PATH = "volatility3-stable/vol.py"  # Cấu hình lại nếu cần


def create_tmp_yara(pattern, is_regex=False):
    yara_path = Path("tmp_hunt.yar")
    search_str = f"/{pattern}/" if is_regex else f'"{pattern}"'
    rule_content = f"""
rule dynamic_hunt {{
    strings:
        $str = {search_str} ascii nocase
        $wide = {search_str} wide nocase
    condition:
        $str or $wide
}}"""
    yara_path.write_text(rule_content, encoding="utf-8")
    return yara_path


def parse_hex_bytes(raw_output):
    """
    Bóc tách trực tiếp từ cột mã Hex thô của Volatility.
    Giải quyết triệt để lỗi mất dấu chấm của Wide-String bằng kỹ thuật loại bỏ Null-Byte.
    """
    matches = []
    current_bytes = bytearray()

    # Regex bắt chính xác tối đa 16 cặp mã Hex ở đầu mỗi dòng dữ liệu
    hex_row_pattern = re.compile(r"^((?:[0-9a-fA-F]{2}\s+){1,16})")

    for line in raw_output.splitlines():
        line_str = line.strip()
        if not line_str:
            continue

        # Nếu gặp phân đoạn địa chỉ mới (Offset) thì đóng gói cụm cũ
        if line_str.startswith("0x"):
            if current_bytes:
                matches.append(current_bytes)
                current_bytes = bytearray()
            continue

        # Khớp dòng và nhặt các cặp mã Hex đưa vào mảng byte
        match = hex_row_pattern.match(line_str)
        if match:
            hex_part = match.group(1)
            for hex_val in hex_part.split():
                current_bytes.append(int(hex_val, 16))

    if current_bytes:
        matches.append(current_bytes)

    clean_strings = set()
    for b_array in matches:
        # LỌC TỐI THƯỢNG: Loại bỏ toàn bộ byte 0x00.
        # Chuỗi mã UTF-16 (Wide) sẽ tự động co về chuỗi kí tự thuần túy mà không mất dấu chấm cấu trúc.
        clean_bytes = bytearray([b for b in b_array if b != 0x00])

        try:
            decoded = clean_bytes.decode("latin-1").strip()

            # Khử rác Stdout hệ thống bám đuôi
            for garbage in ["finished", "progress", "shed"]:
                if decoded.endswith(garbage):
                    decoded = decoded[: -len(garbage)]

            if decoded:
                clean_strings.add(decoded)
        except Exception:
            continue

    return list(clean_strings)


def main():
    if len(sys.argv) < 4:
        print(
            "Cách dùng: python tool/mem-hunter.py <file_ram> <pid> <từ_khóa_hoặc_regex> [-regex]"
        )
        sys.exit(1)

    ram_path = sys.argv[1]
    pid = sys.argv[2]
    pattern = sys.argv[3]
    is_regex = "-regex" in sys.argv

    yara_file = create_tmp_yara(pattern, is_regex)
    cmd = [
        "python",
        VOLATILITY_PATH,
        "-f",
        ram_path,
        "windows.vadyarascan",
        "--pid",
        pid,
        "--yara-file",
        str(yara_file),
    ]

    print(f"[+] Đang quét không gian bộ nhớ ảo PID {pid}...")
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

    if yara_file.exists():
        yara_file.unlink()

    url_list = parse_hex_bytes(result.stdout)

    print("\n" + "=" * 50)
    print(f"Results:")
    print("=" * 50)
    if url_list:
        for url in url_list:
            print(f"=> {url}")
    else:
        print("[!] Không tìm thấy chuỗi phù hợp.")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
