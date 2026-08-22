# 🔒 SecuriScan

## Automated Vulnerability Assessment & Remediation Management Platform


### 🎯 Project Overview
SecuriScan is a full-stack research prototype for automated web vulnerability
assessment and explainable remediation prioritization. It helps analysts run a
bounded nine-module assessment, preserve evidence, apply business and threat
context, and review the most urgent findings first.

### 🛠️ Tech Stack
- Frontend: React 19, TypeScript, Tailwind CSS
- Backend: Next.js 16 (App Router)
- Database: MongoDB Atlas
- Scanners: Python 3.x
- Deployment: Node.js hosting with a Python runtime for scans

### 🚀 Quick Start

#### Prerequisites
Make sure you have the following installed:
- Node.js 18+
- Python 3.9+
- MongoDB Atlas account (free tier)
- Git

#### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Zuana15/securiscan.git
   cd securiscan
   ```

2. Install frontend dependencies:
   ```bash
   npm install
   ```

3. Create the project Python environment and install the scanner dependencies:
   ```bash
   python -m venv .venv
   # Windows PowerShell
   .\.venv\Scripts\python -m pip install -r scanners/requirements.txt
   # macOS/Linux
   ./.venv/bin/python -m pip install -r scanners/requirements.txt
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env.local
   ```
   Then update the file with your MongoDB connection string. The dashboard uses
   the project virtual environment by default; set `SECURISCAN_PYTHON` only to
   override that location.

   Set a long random `NEXTAUTH_SECRET`. To create the first local demo account,
   also set `SECURISCAN_ALLOW_REGISTRATION=true`, run the app, and use **Create
   account**. The first account receives an owner label and later local accounts
   receive an analyst label, ready for the future RBAC milestone. Every signed-in
   account currently has the same assessment features and can access only its own
   stored results. Registration is disabled by default and must stay disabled in
   deployed environments until an administrator provisioning flow is added.

5. Run the development server:
   ```bash
   npm run dev
   ```

6. Open your browser at:
   ```text
   http://localhost:3000
   ```

The first dashboard lets you select scanner modules, confirm you are authorized
to assess the target, and review the combined findings. It accepts public HTTP(S)
targets only and blocks private or local-network addresses.

Each authenticated account can run assessments and sees only its own saved scans,
recent history, severity counts, finding trends, and risk-priority analytics. The
dashboard performs a server-side session check before a scan or stored-data request
is accepted.

### Risk-scoring MVP

Every new scan is prioritized by a deterministic, explainable `risk-v1` model. The
model combines the scanner severity/CVSS-like baseline with asset criticality,
exposure, analyst-supplied threat context, business impact, scanner-derived
exploitability, and compensating controls. Scores range from 0 to 100 and map to
low, medium, high, or critical remediation priority.

The scan form captures the business context, every finding shows its factor-by-factor
score breakdown, and MongoDB stores both the selected context and calculated risk
summary. The history and analytics views show highest/average score and priority
counts. Version 1 does not call an AI service or a live threat-intelligence feed;
the threat-context value is supplied by the analyst.

The repository also contains a repeatable prototype benchmark with 12 calibration
and 12 separate validation scenarios. It compares pairwise remediation ranking
accuracy against a CVSS-only baseline and evaluates five weight candidates without
using the validation cases for candidate selection. On this internal dataset,
Risk v1 scores 96.97% versus 56.06% for CVSS-only ranking: a 40.91 percentage-point
gain and 72.98% relative improvement. These developer-authored labels demonstrate
the mechanism, but they are not independent research proof; a blinded expert-labelled
WebGoat/DVWA-derived dataset is still required before making the formal 30% claim.

### PDF assessment reports

Every saved assessment can be exported as a professional A4 PDF from the results
screen or Scan History. Reports include the target and completion time, severity
summary, module coverage, prioritized findings, evidence, OWASP/CWE labels,
recommended actions, Risk v1 context, and an interpretation/authorization note.
The download route performs the same server-side session and ownership checks as
scan history, so an authenticated user can export only their own stored reports.

Run the risk-model tests with:

```bash
npm test
```

Run the benchmark report with:

```bash
npm run risk:benchmark
```

The scanner-detection evaluator and labelled local-demo ground truth are in
`benchmarks/detection/`. The recorded integration result completed all nine modules
and detected 34/34 developer-labelled positive cases. This is regression evidence,
not independent WebGoat/DVWA validation; use the included blinded-evaluation
template before making the formal >85% research claim.

### Release verification

Run the complete release-candidate verification suite with:

```bash
npm run verify
```

The command runs the automated risk-model tests, ESLint, a production Next.js
build, and the repeatable risk benchmark. A release demonstration should also
verify the following authenticated workflow:

1. Create an account and sign in.
2. Run all nine modules against the authorized local demonstration target.
3. Confirm that all nine module cards show **Completed**.
4. Confirm that the scan is saved and appears in **Scan History**.
5. Confirm that **Analytics** includes the scan and risk-priority totals.
6. Open a finding and verify its seven-factor risk explanation.
7. Download the saved PDF report from the results screen and Scan History.

The scan API launches Python as a child process. Next.js may therefore emit a
non-fatal file-tracing warning while producing a successful build. SecuriScan
must be deployed on a Node.js host that also provides Python and the scanner
dependencies; it is not compatible with a static-only deployment.

If your network blocks the DNS SRV lookup used by an Atlas `mongodb+srv` URI, add
`MONGODB_DNS_SERVERS=1.1.1.1,8.8.8.8` to `.env.local`. Also add your current IP
address in Atlas **Network Access** before connecting.

### Local demonstration target

For presentations, run the intentionally vulnerable local target:

```bash
.\.venv\Scripts\python scanners/demo_target.py
```

Start the dashboard with `SECURISCAN_ALLOW_PRIVATE_TARGETS=true` for that local
session only, then scan `http://127.0.0.1:8080` with every module selected.
Never enable this setting in a deployed environment.

### 📁 Project Structure
```text
securiscan/
├── app/                 # Next.js pages, components, styles, and API routes
├── src/
│   ├── lib/             # Auth, persistence, scan types, scoring, and benchmark
│   └── models/          # MongoDB user and scan-record schemas
├── scanners/             # Python vulnerability scanning modules
│   ├── common.py           # Shared result schema and helpers
│   ├── run_scan.py         # Run all scanners from one command
│   ├── port_scanner.py     # TCP port & service detection
│   ├── sql_injection.py    # Error-based SQL injection
│   ├── xss_scanner.py      # Reflected XSS detection
│   ├── ssl_checker.py      # SSL/TLS certificate analysis
│   ├── headers_scanner.py  # Security headers audit
│   ├── tech_fingerprint.py # Technology stack fingerprinting
│   ├── sensitive_files.py  # Exposed files & backups
│   ├── csrf_scanner.py     # Missing CSRF token checks
│   └── http_misconfig.py   # HTTP methods, cookies, CORS
├── benchmarks/          # Benchmark design and evidence-boundary documentation
├── scripts/             # Executable risk-model evaluation
├── public/              # Static assets
└── reports/             # Local generated reports
```

### 🔍 Vulnerability Scanners (Python)

Run a single module:

```bash
cd scanners
python headers_scanner.py https://your-target.com
python sql_injection.py https://your-target.com
python xss_scanner.py https://your-target.com
```

Run all scanners and save a combined JSON report:

```bash
cd scanners
python run_scan.py https://your-target.com --output ../reports/scan-report.json
```

| Scanner | Module | Category |
|---------|--------|----------|
| Port scan | `port_scanner.py` | Network reconnaissance |
| SQL injection | `sql_injection.py` | OWASP Injection |
| XSS | `xss_scanner.py` | OWASP Injection |
| SSL/TLS | `ssl_checker.py` | Cryptographic failures |
| Security headers | `headers_scanner.py` | Security misconfiguration |
| Tech fingerprint | `tech_fingerprint.py` | Information disclosure |
| Sensitive files | `sensitive_files.py` | Broken access control |
| CSRF | `csrf_scanner.py` | Broken access control |
| HTTP misconfig | `http_misconfig.py` | Security misconfiguration |

**Important:** Only scan systems you own or have explicit written authorization to test.

### 📋 Planned Features
- Independent expert-labelled risk benchmark and external validation
- Automated threat-intelligence enrichment
- RBAC administration and production account provisioning
- Remediation workflow and ticketing
