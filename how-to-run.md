Download volatility3-stable in project folder [Guide](https://docs.google.com/document/d/1My8uhDeQiXw6SR7Rwg36-jot1TbevjUSz65N3FwK1aE/edit?tab=t.pgr6nzxlbqax)

The directory tree that the commands in the notes run on and that config.python uses:

```
C:\Forensic
├── output
├── ram_dump
├── tool
└── volatility3-stable
```

It is recommended to load the RAM dump into the `ram_dump` directory since .gitignore already has it

Update VOLATILITY_PATH in tools\config.py depending on the directory structure you are using

Run:

```bash
python .\tool\forensic_analyzer.py <path_to_memory_dump>
# e.g.
python .\tool\forensic_analyzer.py .\ram_dump\MemoryDump.mem
```
