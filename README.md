# 🔒 SecuriScan

## Automated Vulnerability Assessment & Remediation Management Platform


### 🎯 Project Overview
SecuriScan is an enterprise-grade, automated vulnerability management platform designed to help organizations continuously discover, prioritize, and remediate security weaknesses in their web applications before malicious attackers can exploit them.

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
recent history, severity counts, and finding trends. The dashboard performs a
server-side session check before a scan or stored-data request is accepted.

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
├── src/
│   ├── app/              # Next.js App Router pages and API routes
│   ├── components/       # Reusable React components
│   ├── lib/              # Utility functions and database connection
│   └── types/            # TypeScript type definitions
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
├── public/               # Static assets
└── reports/              # Generated PDF reports
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
- Risk-based prioritization dashboard
- RBAC administration and production account provisioning
- Remediation workflow and ticketing
- Professional PDF report generation
