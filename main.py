import argparse
import os
import re
import math
import logging
import sys
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define regular expressions for common password and API key patterns
PASSWORD_REGEX = r"(password|pwd|secret|key)\s*[:=]\s*[\"']?([a-zA-Z0-9!@#$%^&*()_+=-]+)[\"']?"
API_KEY_REGEX = r"(api_key|apikey|auth_token|token)\s*[:=]\s*[\"']?([a-zA-Z0-9_-]+)[\"']?"

def calculate_entropy(data):
    """
    Calculates the Shannon entropy of a given string.  Used for heuristic password/key detection.
    High entropy strings are more likely to be random keys.
    """
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log2(p_x)
    return entropy

def scan_file(filepath):
    """
    Scans a single file for hardcoded passwords and API keys.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
        return

    # Search for password patterns
    password_matches = re.finditer(PASSWORD_REGEX, content, re.IGNORECASE)
    for match in password_matches:
        key_name = match.group(1)
        value = match.group(2)
        entropy = calculate_entropy(value)
        logging.warning(f"Possible hardcoded password found in {filepath}: Key Name: {key_name}, Value: {value}, Entropy: {entropy}")
        if entropy > 4:
            logging.warning(f"High entropy detected for password in {filepath}. May be a false positive, review carefully.")

    # Search for API key patterns
    api_key_matches = re.finditer(API_KEY_REGEX, content, re.IGNORECASE)
    for match in api_key_matches:
        key_name = match.group(1)
        value = match.group(2)
        entropy = calculate_entropy(value)
        logging.warning(f"Possible hardcoded API key found in {filepath}: Key Name: {key_name}, Value: {value}, Entropy: {entropy}")
        if entropy > 4:
            logging.warning(f"High entropy detected for API Key in {filepath}. May be a false positive, review carefully.")

def scan_directory(directory):
    """
    Recursively scans a directory for files and then scans each file.
    """
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            scan_file(filepath)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans code for hardcoded passwords and API keys.")
    parser.add_argument("path", help="Path to the file or directory to scan.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-e", "--entropy_threshold", type=float, default=4.0, help="Entropy threshold for flagging potential secrets.  Defaults to 4.0.")
    parser.add_argument("-l", "--log_file", type=str, help="Path to log file. If not provided, logs to stdout")
    return parser


def main():
    """
    Main function to execute the code intelligence tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging
    if args.log_file:
        logging.basicConfig(filename=args.log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)


    path = args.path

    # Input validation: Check if the path exists
    if not os.path.exists(path):
        logging.error(f"Error: Path '{path}' does not exist.")
        sys.exit(1)

    # Determine if it's a file or a directory
    if os.path.isfile(path):
        scan_file(path)
    elif os.path.isdir(path):
        scan_directory(path)
    else:
        logging.error(f"Error: '{path}' is neither a file nor a directory.")
        sys.exit(1)
    
    logging.info("Scanning complete.")

if __name__ == "__main__":
    main()