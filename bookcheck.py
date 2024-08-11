import argparse
import hashlib
import os
import requests
import csv
import shutil

# VirusTotal API key
API_KEY = ''
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/files'
HASH_CSV = 'scanned_hashes.csv'
SUPPORTED_FORMATS = ['.epub', '.mobi', '.pdf']

# Example books directory path (can be updated by the user)
books_directory = r''

# Function to update the VirusTotal API key and save it for future use
def update_api_key(api_key, verbose=True):
    global API_KEY
    API_KEY = api_key
    save_configuration()
    if verbose:
        print_decorative_message("API key updated successfully.")

# Function to update the directory path and save it for future use
def update_directory(directory, verbose=True):
    global books_directory
    books_directory = directory
    save_configuration()
    if verbose:
        print_decorative_message("Directory updated successfully.")

# Function to save the configuration to a file
def save_configuration():
    config_data = {
        'API_KEY': API_KEY,
        'books_directory': books_directory
    }
    with open('config.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        for key, value in config_data.items():
            writer.writerow([key, value])

# Function to load configuration from a file
def load_configuration():
    global API_KEY, books_directory
    if os.path.exists('config.csv'):
        with open('config.csv', mode='r', newline='') as file:
            reader = csv.reader(file)
            config = {rows[0]: rows[1] for rows in reader}
            API_KEY = config.get('API_KEY', '')
            books_directory = config.get('books_directory', '')

# Function to calculate file hash
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to check the file hash with VirusTotal
def check_virus_total(file_hash):
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(f"{VIRUSTOTAL_URL}/{file_hash}", headers=headers)
    if response.status_code == 200:
        result = response.json()
        return result['data']['attributes']['last_analysis_stats']
    else:
        return None

# Function to ensure CSV exists and create it if not
def ensure_csv_exists():
    if not os.path.exists(HASH_CSV):
        with open(HASH_CSV, mode='w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(['hash', 'status'])  # Write header

# Function to read scanned hashes from CSV
def load_scanned_hashes():
    scanned_hashes = {}
    if os.path.exists(HASH_CSV):
        with open(HASH_CSV, mode='r', newline='') as csv_file:
            csv_reader = csv.reader(csv_file)
            next(csv_reader, None)  # Skip header
            for row in csv_reader:
                if len(row) == 2:
                    file_hash, status = row
                    scanned_hashes[file_hash] = status
    return scanned_hashes

# Function to update CSV with new hashes
def update_csv_with_hash(file_hash, status):
    with open(HASH_CSV, mode='a', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow([file_hash, status])

# Function to print a decorative message
def print_decorative_message(message, verbose=True):
    if verbose:
        columns = shutil.get_terminal_size().columns
        border = "+" + "-" * (columns - 2) + "+"
        print(border)
        print(f"| {message.ljust(columns - 4)} |")
        print(border)
    else:
        print(f"[!] {message}")

# Function to print ASCII art for the start event
def print_start_ascii_art():
    print("""
__________               __   _________ .__                   __    
\______   \ ____   ____ |  | _\_   ___ \|  |__   ____   ____ |  | __
 |    |  _//  _ \ /  _ \|  |/ /    \  \/|  |  \_/ __ \_/ ___\|  |/ /
 |    |   (  <_> |  <_> )    <\     \___|   Y  \  ___/\  \___|    < 
 |______  /\____/ \____/|__|_ \\______  /___|  /\___  >\___  >__|_ \     
        \/                   \/       \/     \/     \/     \/     \/
        """)

# Function to scan all files in a directory
def scan_directory(directory_path, verbose=True):
    ensure_csv_exists()
    scanned_hashes = load_scanned_hashes()

    for root, dirs, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            
            # Check if the file is in a supported eBook format
            if not any(file_name.lower().endswith(ext) for ext in SUPPORTED_FORMATS):
                continue

            if verbose:
                print_decorative_message(f"Scanning file: {file_name}", verbose)

            # Calculate file hash
            file_hash = calculate_file_hash(file_path)
            if verbose:
                print_decorative_message(f"File hash: {file_hash}", verbose)

            # Check if the file has been scanned before
            if file_hash in scanned_hashes:
                if scanned_hashes[file_hash] == 'malicious':
                    print_decorative_message(f"Previously scanned file {file_name} is malicious! Removing.", verbose)
                    os.remove(file_path)
                else:
                    if verbose:
                        print_decorative_message(f"File already scanned and marked as {scanned_hashes[file_hash]}: {file_name}", verbose)
                continue

            # Check the file with VirusTotal
            scan_result = check_virus_total(file_hash)
            if scan_result:
                if scan_result['malicious'] > 0:
                    if verbose:
                        print_decorative_message(f"File is malicious! Removing.", verbose)
                    else:
                        print(f"[!] File {file_name} is malicious! Removing.")
                    os.remove(file_path)
                    update_csv_with_hash(file_hash, 'malicious')
                else:
                    if verbose:
                        print_decorative_message("File is clean.", verbose)
                    update_csv_with_hash(file_hash, 'clean')
            else:
                if verbose:
                    print_decorative_message(f"Failed to scan the file {file_name}. It will not be removed.", verbose)
                else:
                    print(f"[!] Failed to scan the file {file_name}. It will not be removed.")
                update_csv_with_hash(file_hash, 'failed')

    if not verbose:
        print(f"[!] Scan completed.")

# Main function
def main():
    global API_KEY, books_directory  # Declare global variables

    load_configuration()  # Load existing configuration

    parser = argparse.ArgumentParser(description='Bookscan CLI to update API key and scan directories.')
    parser.add_argument('--api-key', type=str, help='VirusTotal API key')
    parser.add_argument('--directory', type=str, help='Directory to scan')
    parser.add_argument('--verbose', action='store_true', help='Display detailed output')

    args = parser.parse_args()

    print_start_ascii_art()

    # Update API key using provided argument or prompt the user
    if args.api_key:
        update_api_key(args.api_key, args.verbose)
    elif not API_KEY:
        API_KEY = input("Enter your VirusTotal API key: ")
        update_api_key(API_KEY, args.verbose)
    else:
        print_decorative_message(f"Using existing API key.", args.verbose)

    # Update directory using provided argument or prompt the user
    if args.directory:
        update_directory(args.directory, args.verbose)
    elif not books_directory:
        books_directory = input("Enter the directory to scan: ")
        update_directory(books_directory, args.verbose)
    else:
        print_decorative_message(f"Using existing directory.", args.verbose)

    # Display set values
    print_decorative_message(f"API key set: {API_KEY}", args.verbose)
    print_decorative_message(f"Directory set: {books_directory}", args.verbose)

    # Run the scan
    scan_directory(books_directory if not args.directory else args.directory, args.verbose)

if __name__ == "__main__":
    main()
