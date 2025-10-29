# subscope

**Subscope** is a command-line Python tool for discovering subdomains using certificate transparency logs (crt.sh) and validating their resolved IP addresses against a user-defined IP scope. Designed for pentesters and security researchers.

---

## Key features

* Queries crt.sh (`https://crt.sh/?q=%25.{domain}&output=json`) and extracts `name_value` entries.
* Optional: find sub-subdomains for discovered entries.
* Resolve domains to IP(s) and check whether IPs fall inside a provided scope (single IPs, CIDR, or hyphenated IP ranges supported).
* Writes results to files and prints a summary to the console.

---

## Requirements

* Python 3.9+ (recommended)
* See `requirements.txt` for exact dependency versions.

---

## Installation

### Clone the repository

```bash
git clone https://github.com/111laaaddaaa/subscope.git
cd subscope
```

Or download and extract the ZIP archive, then `cd` into the extracted folder.

### Create and activate a virtual environment (recommended)

On Linux / macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

On Windows (PowerShell):

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Make the script executable (Linux/macOS)

```bash
chmod +x subscope.py
```

---

## Usage

### Input files

* `domains.txt` — one target domain per line (empty lines and surrounding whitespace are ignored). Example:

  ```
  example.com
  testsite.net
  company.org
  ```
* `scope.txt` (optional) — one entry per line describing allowed IPs for validation. Supported formats:

  * Single IP: `198.51.100.4`
  * CIDR: `198.51.100.0/24`
  * Hyphenated range: `172.16.0.1-172.16.0.255`

### Quick start

Run enumerator interactively:

```bash
python subscope.py -d domains.txt
```

Non-interactive mode (no prompts):

```bash
python subscope.py -d domains.txt --non-interactive --validate --scope scope.txt
```

### Typical CLI options

* `-d, --domains` — path to `domains.txt` (required)
* `--non-interactive` — do not prompt the user; use defaults and flags
* `--validate` — resolve discovered hostnames to IPs and validate against scope
* `--scope` — path to a scope file (required when `--validate` is used)
* `--recursive` — perform recursive enumeration for sub-subdomains
* `-o, --output` — path to output file (default: `results_subdomains.txt`)
* `-v, --verbose` — increase logging verbosity
* `-h, --help` — show help and exit

(Use `python subscope.py --help` to list the exact, current options.)

---

## Output

* `results_subdomains.txt` — newline-separated unique subdomains discovered by the tool (normalized and deduplicated).
* Console summary.

---


## Contributing

Contributions, bug reports, and feature requests are welcome.
