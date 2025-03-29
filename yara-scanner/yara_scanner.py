import yara
import os
import argparse

def compile_rules(rules_path):
    try:
        rules = yara.compile(filepath=rules_path)
        return rules
    except yara.SyntaxError as e:
        print(f"Error compiling rules: {e}")
        return None

def scan_path(rules, target_path):
    if os.path.isfile(target_path):
        match_file(rules, target_path)
    else:
        for root, _, files in os.walk(target_path):
            for file in files:
                match_file(rules, os.path.join(root, file))

def match_file(rules, file_path):
    try:
        matches = rules.match(filepath=file_path)
        if matches:
            print(f"[+] Match in {file_path}:")
            for match in matches:
                print(f"    - Rule: {match.rule}")
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Simple YARA Rule Scanner")
    parser.add_argument("-r", "--rules", required=True, help="Path to YARA rule file")
    parser.add_argument("-t", "--target", required=True, help="File or directory to scan")
    args = parser.parse_args()

    rules = compile_rules(args.rules)
    if rules:
        scan_path(rules, args.target)

if __name__ == "__main__":
    main()
