import os
import re
import argparse
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

SECRET_PATTERNS = {
    "AWS Access Key": r"\b(A[SK]IA[0-9A-Z]{16})\b",
    "Stripe API Key": r"\b((?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,})\b",
    "Google API Key": r"\b(AIza[0-9A-Za-z\-_\s]{35})\b",
    "JSON Web Token (JWT)": r"\b(eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)\b",
    "Asymmetric Private Key": r"-----BEGIN ((?:EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY-----",
    "Generic Credentials/Password Assignment": r"(?i)\b(?:password|passwd|secret|api_key|token)\s*=\s*['\"]([^'\"]{4,})['\"]"
}

COMPILED_PATTERNS = {name: re.compile(pattern) for name, pattern in SECRET_PATTERNS.items()}

def scan_file(file_path):
    """Scans a single file for secret patterns line by line."""
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, start=1):
                for secret_type, regex in COMPILED_PATTERNS.items():
                    matches = regex.findall(line)
                    for match in matches:
                        matched_str = match if isinstance(match, str) else match[0]
                        findings.append({
                            "filename": file_path,
                            "line_number": line_num,
                            "type": secret_type,
                            "match": matched_str.strip()
                        })
    except Exception as e:
        logging.error(f"Could not read file {file_path}: {e}")
    return findings

def scan_directory(directory_path, exclusions=None):
    """Recursively crawls a folder structure to locate text files to scan."""
    if exclusions is None:
        exclusions = {'.git', 'node_modules', 'venv', '__pycache__', '.env'}
        
    all_findings = []
    logging.info(f"Starting crawl on root workspace directory: {directory_path}")
    
    for root, dirs, files in os.walk(directory_path):
        dirs[:] = [d for d in dirs if d not in exclusions and not d.startswith('.')]
        
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(('.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz', '.exe')):
                continue
            all_findings.extend(scan_file(file_path))
            
    return all_findings

def main():
    parser = argparse.ArgumentParser(
        description="A Python-based CLI Secret Scanner to find hardcoded tokens, keys, and passwords."
    )
    parser.add_argument(
        "target", 
        help="Target folder path or individual file string to analyze."
    )
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true", 
        help="Enable diagnostic debugging logs."
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    if not os.path.exists(args.target):
        logging.error(f"The targeted input location could not be located: {args.target}")
        sys.exit(1)
        
    findings = []
    if os.path.isdir(args.target):
        findings = scan_directory(args.target)
    elif os.path.isfile(args.target):
        findings = scan_file(args.target)
        
    print("\n" + "="*80)
    print(f"SCAN REPORT SUMMARY: Detected {len(findings)} potential secret leak(s)")
    print("="*80)
    
    if findings:
        for f in findings:
            print(f"[!] FILE: {f['filename']} | LINE: {f['line_number']} | TYPE: {f['type']}")
            print(f"    MATCHED DATA: {f['match']}\n")
        sys.exit(1) 
    else:
        logging.info("Zero high-entropy signature or credential matches discovered.")
        sys.exit(0)

if __name__ == "__main__":
    main()