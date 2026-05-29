# Forensic Memory Analysis Tool

Công cụ phân tích bộ nhớ RAM (Memory Forensics) tự động dựa trên Volatility 3, hỗ trợ dồn dữ liệu và trực quan hóa thành giao diện Web Dashboard tương tác.

Công cụ tuân thủ nguyên tắc forensic cốt lõi: **Không tự ý lọc bỏ dữ liệu (No Filtering), chỉ phân tích đối chiếu và gắn cờ cảnh báo (Flagging Anomalies)** để điều tra viên tự đánh giá và ưu tiên rà soát.

---

## Tiêu chí hoạt động của các Module

### 1. 🖥️ Thông tin hệ thống (System Info)

- **Trích xuất OS Metadata**: Đọc thông tin hệ điều hành từ `windows.info`.
- **Xác định kiến trúc & Build Lab**: Nhận diện Windows bản 32/64-bit, Build version để làm căn cứ cho độ tương thích của các plugin khác.
- **Mốc thời gian tham chiếu**: Trích xuất System Time (UTC) làm căn cứ thời gian thực thi của các tiến trình và kết nối.

### 2. 🌿 Bản đồ tiến trình (Process Map)

- **Xây dựng cây tiến trình**: Tái dựng sơ đồ phân cấp Cha - Con dựa trên `windows.pstree` và `windows.psscan`.
- **Cờ cảnh báo tiến trình**:
  - `🔴 Tàng hình (Hidden)`: Tiến trình xuất hiện trong `psscan` nhưng bị ẩn khỏi danh sách `pslist/pstree`.
  - `⚪ Đã kết thúc (Exit)`: Dấu vết tiến trình đã tắt vẫn còn nằm lại trong `psscan`.
  - `🟠 Mồ côi (Orphaned)`: Tiến trình có PPID của cha không tồn tại (ngoại trừ System/Idle).
  - `🟡 Trùng tên (Duplicate)`: Tiến trình trùng tên hệ thống nhưng chạy ở đường dẫn không hợp lệ.
  - `🔵 Path đáng ngờ (Suspicious Path)`: Chạy từ thư mục nhạy cảm (Temp, AppData, Downloads, Desktop...).
  - `🟣 Memory Injection (Malfind)`: Quét targeted `windows.malware.malfind` trên các tiến trình có cờ bất thường để tìm vùng nhớ RWX ẩn danh chứa PE Header (MZ).

### 3. 🌐 Bản đồ kết nối mạng (Network Map)

- **Tổng hợp & Lọc trùng**: Tổng hợp dữ liệu kết nối mạng từ `windows.netscan` và loại bỏ trùng lặp.
- **Định vị địa lý IP**: Gọi API để tra cứu ASN, Quốc gia, Tổ chức/ISP của IP Public (sử dụng cache cục bộ `ip_cache.json` để tăng tốc độ và tránh rate-limit).
- **Đánh giá mức độ ưu tiên kết nối**:
  - `High (Đỏ)`: Kết nối thuộc về tiến trình đã bị gắn cờ cảnh báo ở Tab 2, hoặc kết nối tới IP Public qua cổng ngoại vi lạ.
  - `Medium (Vàng)`: Kết nối tới IP Public thông thường, hoặc kết nối đang ở trạng thái đóng dở dang (`TIME_WAIT`, `FIN_WAIT`...).
  - `Low (Xám)`: Kết nối nội bộ localhost, cổng nội bộ của hệ thống hoặc lưu lượng multicast (mDNS/SSDP).

### 4. 📚 Danh sách DLL (DLL List)

- **Gom nhóm theo Tiến trình**: Nạp danh sách DLL từ `windows.dlllist` và gom nhóm hiển thị dưới dạng collapsible theo từng tiến trình chứa để phục vụ phân tích ngữ cảnh.
- **Kế thừa cờ tiến trình**: Tiến trình nạp DLL tự động kế thừa và hiển thị cờ cảnh báo của cha (từ Tab Tiến trình) bên cạnh tên của nó.
- **Cờ cảnh báo DLL** (Tối đa hiển thị 2 cờ để tránh rối giao diện):
  - `🔴 Bất thường cấu trúc/định dạng` (Stealth & Format Anomaly):
    - _Tên/Đường dẫn trống (PEB Unlinked)_: DLL nạp trong RAM nhưng có tên/path rỗng (dấu hiệu bypass PEB list).
    - _Đuôi mở rộng lạ (Ngụy trang)_: DLL có đuôi không thuộc định dạng thực thi/thư viện chuẩn (như `.png`, `.jpg`, `.dat`, `.tmp`, `.bin`).
  - `🟠 Bất thường đường dẫn/nạp tệp` (Path & Hijack Anomaly):
    - _DLL giả mạo hệ thống (Hijacking/Side-loading)_: DLL trùng tên hệ thống nạp ngoài System32, hoặc DLL nạp cùng thư mục chạy với file thực thi và trùng tên DLL hệ thống.
    - _Đường dẫn đáng ngờ (Suspicious Path)_: Nạp từ các thư mục Temp, AppData, Downloads...
    - _Thư mục nạp lạ (Untrusted Path)_: Nạp ngoài các thư mục an toàn cài đặt chương trình.
