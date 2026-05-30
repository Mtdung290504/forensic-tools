Tải volatility3-stable về project folder [Hướng dẫn tại đây](https://docs.google.com/document/d/1My8uhDeQiXw6SR7Rwg36-jot1TbevjUSz65N3FwK1aE/edit?tab=t.pgr6nzxlbqax)

Các lệnh trong note-commands và config.py chạy trên thư mục `C:\Forensic` theo full cây thư mục dưới đây, đề xuất sử dụng cùng cấu trúc để ít phải chỉnh sửa gì:

```
C:\Forensic
├── output
├── ram_dump
├── tool
└── volatility3-stable
```

Đề xuất tải RAM dump xuống thư mục `ram_dump` cho tiện vì đã có gitignore

Sửa biến VOLATILITY_PATH trong `tools\config.py` tùy vào cấu trúc thư mục máy dùng (Nếu cây thư mục đã như trên thì không cần)

Chạy:

```bash
python .\tool\forensic_analyzer.py <path_to_memory_dump>
# e.g.
python .\tool\forensic_analyzer.py .\ram_dump\MemoryDump.mem
```

Note một số lệnh khác [tại đây](./note-commands.md)
