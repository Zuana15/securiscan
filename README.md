# 🔒 SecuriScan

## Automated Vulnerability Assessment & Remediation Management Platform


### 🎯 Project Overview
SecuriScan is an enterprise-grade, automated vulnerability management platform designed to help organizations continuously discover, prioritize, and remediate security weaknesses in their web applications before malicious attackers can exploit them.

### 🛠️ Tech Stack
- Frontend: React 18, TypeScript, Tailwind CSS
- Backend: Next.js 14 (App Router)
- Database: MongoDB Atlas
- Scanners: Python 3.x
- Deployment: Vercel

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

3. Install Python dependencies:
   ```bash
   pip install -r scanners/requirements.txt
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env.local
   ```
   Then update the file with your MongoDB connection string. The dashboard uses
   the project virtual environment by default; set `SECURISCAN_PYTHON` only to
   override that location.

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
- User authentication and RBAC
- Remediation workflow and ticketing
- Professional PDF report generation
