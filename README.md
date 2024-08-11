```
+---------------------------------------------------------------------+
__________               __   _________ .__                   __    
\______   \ ____   ____ |  | _\_   ___ \|  |__   ____   ____ |  | __
 |    |  _//  _ \ /  _ \|  |/ /    \  \/|  |  \_/ __ \_/ ___\|  |/ /
 |    |   (  <_> |  <_> )    <\     \___|   Y  \  ___/\  \___|    < 
 |______  /\____/ \____/|__|_ \______  /___|  /\___  >\___  >__|_ \     
        \/                   \/       \/     \/     \/     \/     \/
+---------------------------------------------------------------------+
```

Bookcheck is a Python utility that integrates with the VirusTotal API to scan directories of books for potential malware. This tool helps ensure that downloaded books are safe by verifying them against VirusTotal’s database.

## Features

- **VirusTotal Integration**: Automatically scans books using the VirusTotal API.
- **Configurable API Key**: Easily update or store your VirusTotal API key.
- **Directory Management**: Specify the directory to be scanned or store it for future scans.
- **Automated Scanning**: Automatically runs the scanning process after updating configurations.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/bytedawn/bookcheck
   ```

2. Navigate to the project directory:

   ```bash
   cd bookcheck
   ```

3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To run the `bookcheck.py` script:

```bash
python3 bookcheck.py --api-key YOUR_API_KEY --directory /path/to/your/books
```

### Options

- `--api-key`: Your VirusTotal API key.
- `--directory`: The directory containing the books to scan.
- `--verbose`: Verbose output.

## Example Output

```powershell
PS C:\Users\xxxx\Documents\pydev\bookcheck\bookcheck\bookcheck> python3 bookcheck.py

__________               __   _________ .__                   __
\______   \ ____   ____ |  | _\_   ___ \|  |__   ____   ____ |  | __
 |    |  _//  _ \ /  _ \|  |/ /    \  \/|  |  \_/ __ \_/ ___\|  |/ /
 |    |   (  <_> |  <_> )    <\     \___|   Y  \  ___/\  \___|    <
 |______  /\____/ \____/|__|_ \______  /___|  /\___  >\___  >__|_ \
        \/                   \/       \/     \/     \/     \/     \/

Enter your VirusTotal API key: 24dxxxxxxxxxxxxxxxxxxxx
Enter the directory to scan: C:/Tools/m 
[!] API key set: 24dxxxxxxxxxxxxxxxxxxxxxxxxx
[!] Directory set: C:/Tools/m
[!] Previously scanned file test1.pdf is malicious! Removing.
[!] Previously scanned file test10.pdf is malicious! Removing.
[!] Previously scanned file test11.pdf is malicious! Removing.
[!] Previously scanned file test1bis.pdf is malicious! Removing.
[!] Previously scanned file test2.pdf is malicious! Removing.
[!] Previously scanned file test3.pdf is malicious! Removing.
[!] Previously scanned file test4.pdf is malicious! Removing.
[!] Previously scanned file test5.pdf is malicious! Removing.
[!] Previously scanned file test8.pdf is malicious! Removing.
[!] Scan completed.
```

## License

This project is licensed under the MIT License.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for their API and services.
