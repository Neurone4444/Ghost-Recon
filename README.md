# Ghost-Recon

Ghost Recon is an OSINT intelligence framework focused on public exposure analysis and defensive reconnaissance.

The framework collects and correlates publicly available information to evaluate exposure surface, breach signals, and security posture indicators. It is designed for defensive analysis only.

Educational and authorized use only.

---

## Requirements

- Python 3.9 or higher
- Internet connection for public OSINT sources

---

## Features

Domain Intelligence
- DNS resolution
- SSL/TLS certificate inspection
- HTTP security header analysis
- Technology fingerprinting
- Subdomain enumeration (public sources only)
- Shodan InternetDB integration
- URLScan visibility analysis
- WHOIS (RDAP) lookup
- Public port exposure visibility

Email Intelligence
- Email format validation
- MX record verification
- Disposable email detection
- Public breach database check (XposedOrNot)
- Exposure scoring and risk classification

Username Hunter
- Multi-platform username search (50+ platforms)
- Response verification engine to reduce false positives
- Exposure scoring

Phone Intelligence
- Public breach confirmation (optional API integration)
- Exposure signal analysis

Presence Signal Engine
- Public web mention detection
- Cross-platform exposure indicators
- Confidence-based signal classification

Security Utilities
- Password and hash check (HIBP k-anonymity)
- PII redaction mode
- Encrypted report export (AES-256-GCM)
- Session persistence

Full Recon Mode
- Combined domain, IP, and email analysis workflow

---

## Installation

Clone the repository:

git clone https://github.com/YOUR_USERNAME/Ghost-Recon.git

Move into the directory:

cd Ghost-Recon

Install required dependency:

python -m pip install cryptography

If a requirements.txt file is present:

python -m pip install -r requirements.txt

---

## Usage

Run the framework:

python ghostrecon.py

Decrypt encrypted report:

python ghostrecon.py --decrypt filename.ghost your_password

---

## Output

Reports can be exported in:
- JSON
- HTML
- Encrypted format (.ghost) using AES-256-GCM

---

## Legal Notice

Ghost Recon is intended for defensive security analysis, research, and educational purposes.

Use only on domains, accounts, identities, and assets you are legally authorized to analyze.

The author assumes no responsibility for misuse or unauthorized activity.
