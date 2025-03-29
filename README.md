# Simple YARA Rule Scanner

A lightweight Python tool that scans files and folders using YARA rules to detect malware or suspicious patterns.



## Features
- Scan individual files or entire directories
- Uses `.yar` YARA rule files
- Displays matched rule names in the terminal
- Easy to run with just one command

---

## Getting Started

### Requirements
- Python 3.7+
- YARA Python bindings

Install dependencies using pip:

```bash
pip install yara-python

Usage:
python yara_scanner.py -r sample_rules/example.yar -t <path_to_file_or_folder>

Arguments:
-r / --rules: Path to your YARA rule file (e.g., sample_rules/example.yar)
-t / --target: Path to the file or folder you want to scan

Example:
python yara_scanner.py -r sample_rules/example.yar -t ./suspicious_folder/

If a file matches a YARA rule, the scanner will display:
[+] Match in ./suspicious_folder/sample.exe:
    - Rule: SilentBanker

If no match is found:
[-] No matches found in target_file.exe

Example Rule:
rule SilentBanker : Trojan
{
    meta:
        description = "Detects SilentBanker Trojan"
    strings:
        $a = "BankingMalware"
    condition:
        $a
}

Project Structure:
yara-scanner/
├── yara_scanner.py
├── sample_rules/
│   └── example.yar
└── README.md



