# Forensic Memory Analysis Tool

Công cụ Memory Forensics tự động dựa trên Volatility 3, hỗ trợ dồn dữ liệu và trực quan hóa thành giao diện Web Dashboard tương tác.

Công cụ tuân thủ nguyên tắc: **Không tự ý lọc bỏ dữ liệu, chỉ phân tích đối chiếu và gắn cờ cảnh báo** để điều tra viên tự đánh giá và ưu tiên rà soát.

Cài đặt và chạy xem [tại đây](./how-to-run.md)

---

## Các module và tiêu chí hoạt động của chúng

### 1. Thông tin hệ thống (System Info)

- **Trích xuất OS Metadata**: Đọc thông tin hệ điều hành từ `windows.info`.
- **Xác định kiến trúc & Build Lab**: Nhận diện Windows bản 32/64-bit, Build version để làm căn cứ cho độ tương thích của các plugin khác.
- **Mốc thời gian tham chiếu**: Trích xuất System Time (UTC) làm căn cứ thời gian thực thi của các tiến trình và kết nối.

### 2. Bản đồ tiến trình (Process Map)

- **Xây dựng cây tiến trình**: Tái dựng sơ đồ phân cấp Cha - Con dựa trên `windows.pstree` và `windows.psscan`. Tự động xác định tài khoản và SID chạy tiến trình
- **Cờ cảnh báo tiến trình**:
  - `🔴 Tàng hình`: Tiến trình xuất hiện trong `psscan` nhưng bị ẩn khỏi `pstree`.
  - `🟠 Mồ côi`: Tiến trình có PPID của cha không tồn tại (ngoại trừ System/Idle).
  - `🟡 Trùng tên khác path`: Tiến trình trùng tên nhưng chạy ở đường dẫn khác nhau.
  - `🔵 Path đáng ngờ`: Chạy từ thư mục nhạy cảm (Temp, AppData, Downloads, Desktop...).
  - `🟣 Memory Injection (Malfind)`: Quét `windows.malware.malfind` trên các tiến trình có cờ bất thường để tìm vùng nhớ RWX ẩn danh chứa PE Header (MZ). Có option full để quét tất cả nhưng mặc định tắt vì chậm.
  - `⚪ Đã kết thúc`: Dấu vết tiến trình đã tắt vẫn còn nằm lại trong `psscan`.

### 3. Bản đồ kết nối mạng (Network Map)

- **Tổng hợp & Lọc trùng**: Tổng hợp dữ liệu kết nối mạng từ `windows.netscan` và loại bỏ trùng lặp.
- **Định vị địa lý IP**: Gọi API để tra cứu ASN, Quốc gia, Tổ chức/ISP của IP Public (sử dụng cache cục bộ `ip_cache.json` để tăng tốc độ và tránh rate-limit).
- **Đánh giá mức độ ưu tiên kiểm tra**:
  - `High (Đỏ)`:
    - Kết nối được thực hiện bởi tiến trình đã bị Module 2 đánh cờ bất thường (flagged_process).
    - Kết nối đến một địa chỉ IP Public thông qua cổng lạ (cổng đích nằm ngoài danh sách cổng phổ biến).
  - `Low (Xám)`:
    - Kết nối đi tới địa chỉ loopback/localhost/IP nội bộ
    - Sử dụng cổng local thuộc nhóm cổng nhiễu hệ thống
    - Sử dụng giao thức IPv6 đi qua cổng dịch vụ khám phá mạng cục bộ
  - `Medium (Vàng)`:
    - Kết nối đến địa chỉ IP Public thông qua các cổng phổ biến thông thường.
    - Socket đang ở trạng thái đóng dở dang (FIN_WAIT2, TIME_WAIT, CLOSE_WAIT) hoặc trạng thái đang khởi tạo kết nối (SYN_SENT).
    - Kết nối đã đóng hoàn toàn (CLOSED) nhưng có đích đến là IP Public
    - Hoặc tất cả các kết nối thông thường khác không thỏa mãn bất kỳ điều kiện lọc nào của mức `High` và `Low`.

### 4. Danh sách DLL (DLL List)

- **Gom nhóm theo Tiến trình**: Nạp danh sách DLL từ `windows.dlllist` và gom nhóm hiển thị dưới dạng collapsible theo từng tiến trình chứa để phục vụ phân tích ngữ cảnh.
- **Kế thừa cờ tiến trình**: Tiến trình nạp DLL tự động kế thừa và hiển thị cờ cảnh báo của tiến trình nạp nó (từ Tab Tiến trình) bên cạnh tên của nó.
- **Cờ cảnh báo DLL**:
  - `🔴 Bất thường cấu trúc/định dạng` (Stealth & Format Anomaly):
    - _Tên/Đường dẫn trống (PEB Unlinked)_: DLL nạp trong RAM nhưng có tên/path rỗng (dấu hiệu bypass PEB list).
    - _Đuôi mở rộng lạ_: DLL có đuôi không thuộc định dạng thực thi/thư viện chuẩn.
    - _Tiến trình tàng hình_: PID của tiến trình có nạp DLL nhưng không tìm thấy tiến trình trong kết quả `pstree` và `psscan`
  - `🟠 Bất thường đường dẫn/nạp tệp` (Path & Hijack Anomaly):
    - _DLL Hijacking/Side-loading_: DLL trùng tên hệ thống nạp ngoài System32, hoặc DLL nạp cùng thư mục chạy với file thực thi và trùng tên DLL hệ thống.
    - _Nạp từ thư mục không tin cậy hoặc đáng ngờ_:
      - Quét theo Whitelist: DLL nạp ngoài các phân vùng cài đặt an toàn (C:\Windows, C:\Program Files).
      - Quét theo Blacklist: DLL cố tình nạp vào các thư mục tạm/nhạy cảm (như Temp, AppData, Downloads, Desktop, Recycle Bin...), kể cả khi thư mục đó nằm trong dải phân vùng Windows.
