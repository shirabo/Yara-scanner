# 🔍 Simple YARA Rule Scanner

A lightweight Python tool to scan files or folders using YARA rules.

## Features
- Scans files or directories
- Highlights matched rules
- Supports standard YARA syntax

## Requirements
- Python 3.7+
- yara-python (`pip install yara-python`)

## Usage

```bash
python yara_scanner.py -r sample_rules/example.yar -t suspicious_folder/
```

## Example YARA Rule

```yara
rule SilentBanker : Trojan
{
    meta:
        description = "Detects SilentBanker Trojan"
    strings:
        $a = "BankingMalware"
    condition:
        $a
}
```

## License
MIT
