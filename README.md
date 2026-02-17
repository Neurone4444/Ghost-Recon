Ghost-Recon

Ghost Recon is an OSINT intelligence framework focused on public exposure analysis, breach signal correlation, and defensive reconnaissance.

The framework collects and correlates publicly available information to evaluate:

Exposure surface

Breach indicators

Incident signals

Security posture

Risk scoring drivers

Designed strictly for defensive and authorized use.

Core Capabilities
Domain Intelligence

DNS resolution and record analysis

SSL/TLS certificate inspection

HTTP security header evaluation

Technology fingerprinting

Subdomain enumeration (public sources only)

URLScan visibility analysis

WHOIS / RDAP unified lookup

Public port exposure visibility

Domain risk scoring engine

Email Intelligence

Format validation

MX record verification

Disposable email detection

Public breach database check (XposedOrNot)

Exposure scoring and classification

Leak Intelligence Engine

Noise-aware leak signal analysis:

Paste and code repository monitoring

Exposure signal weighting

Strict target validation (email & domain only)

Risk confidence scoring

Proof-ready verification links

Incident Intelligence (Pivot Engine)

OSINT pivoting for:

Ransomware mentions

Data breach references

Leak site indexing

Infostealer exposure

Credential theft indicators

Cybersecurity media coverage

Ransomware tracker correlation

Includes:

Smart dork refinement

Self-site noise exclusion

Multi-language pivoting

Focused breach-relevance queries

Username Hunter

50+ platform checks

Response verification logic

False positive reduction

Exposure scoring

Phone Intelligence

Public breach signal detection

Exposure scoring

Optional API integration

Security Utilities

Password & hash check (HIBP k-anonymity)

PII redaction mode

AES-256-GCM encrypted reports

Session persistence

Safe / Aggressive mode separation

Modes
Safe Mode

Low-noise, compliance-focused reconnaissance.

Aggressive Mode

Extended OSINT pivots and deeper exposure correlation
(Still based only on public and legally accessible sources)

Installation

Clone the repository:

git clone https://github.com/YOUR_USERNAME/Ghost-Recon.git
cd Ghost-Recon


Install dependencies:

python -m pip install -r requirements.txt


If needed:

python -m pip install cryptography

Usage

Run the framework:

python ghostrecon.py


Decrypt encrypted report:

python ghostrecon.py --decrypt filename.ghost your_password

Output

Reports can be exported in:

JSON

HTML

Encrypted format (.ghost) using AES-256-GCM

Legal Notice

Ghost Recon is intended for defensive security analysis, research, and educational purposes.

Use only on domains, accounts, identities, and assets you are legally authorized to analyze.

The author assumes no responsibility for misuse or unauthorized activity.
