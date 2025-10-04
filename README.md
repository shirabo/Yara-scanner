import yara
import os
import argparse
import sys

def compile_rules(rule_path):
    """
    Compiles the YARA rule file. This step prepares the rules for scanning,
    including any imported modules like 'pe'.
    """
    if not os.path.exists(rule_path):
        print(f"!!! FATAL ERROR: Rules file not found at '{rule_path}'")
        return None
        
    try:
        # yara.compile automatically handles modules imported in the .yar file
        rules = yara.compile(filepath=rule_path)
        print(f"[i] Rules file '{rule_path}' compiled successfully.")
        return rules
    except yara.Error as e:
        print(f"!!! FATAL ERROR: Failed to compile YARA rules from '{rule_path}'.")
        print(f"!!! Details: {e}")
        return None

def scan_file(rules, filepath):
    """
    Performs the scan on a single file and prints the results.
    """
    if not os.path.isfile(filepath):
        return

    is_match_found = False

    try:
        # Execute the scan
        matches = rules.match(filepath=filepath)
        
        if matches:
            is_match_found = True
            print(f"\n[+] Match found in {filepath}:")
            for match in matches:
                # Print the name of the rule that matched
                print(f"    - Rule: {match.rule}")
        
    except yara.Error as e:
        # Catches errors like permission denied or corrupted file format
        print(f"[!] Warning: Could not scan file {filepath}. YARA Error: {e}")
    except Exception as e:
        print(f"[!] Warning: An unexpected error occurred while scanning {filepath}. Error: {e}")
    
    # Print the "No matches found" message only if no match was reported and no fatal error occurred
    if not is_match_found:
        print(f"[-] No matches found in {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="A lightweight Python tool that scans files and folders using YARA rules."
    )
    # Required argument for the rules file
    parser.add_argument(
        '-r', '--rules', 
        required=True, 
        help='Path to your YARA rule file (e.g., sample_rules/example.yar)'
    )
    # Required argument for the target file or directory
    parser.add_argument(
        '-t', '--target', 
        required=True, 
        help='Path to the file or folder you want to scan'
    )
    
    args = parser.parse_args()

    # 1. Compile the rules
    compiled_rules = compile_rules(args.rules)
    if not compiled_rules:
        # Exit if compilation fails
        sys.exit(1) 

    target_path = args.target

    # 2. Scanning logic
    if os.path.isfile(target_path):
        # Scan a single file
        scan_file(compiled_rules, target_path)

    elif os.path.isdir(target_path):
        # Scan a directory (recursively)
        print(f"\n[i] Starting recursive scan of directory: {target_path}")
        
        # os.walk efficiently traverses all files and subdirectories
        for root, _, files in os.walk(target_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                scan_file(compiled_rules, file_path)
        
    else:
        print(f"[!] Error: Target path '{target_path}' is not a valid file or directory.")


if __name__ == "__main__":
    main()
