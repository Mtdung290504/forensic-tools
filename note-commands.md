Lấy hash

```bash
Get-FileHash .\ram_dump\MemoryDump.mem -Algorithm MD5
```

Search regex trong mem của process nào đó

```bash
python .\tool\mem-hunter.py <path_to_memory_dump> <PID> <regex_theo_yêu_cầu_hỏi_AI_bằng_prompt.txt> -regex
# e.g. Lấy http(s)://77.91.124.20/<text>.php
python .\tool\mem-hunter.py .\ram_dump\MemoryDump.mem 5896 'https?:\/\/77\.91\.124\.20\/[a-zA-Z0-9\.\/*~-]+\.php' -regex
```
