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
   pip install requests beautifulsoup4 scapy ssl-checker
   ```

4. Set up environment variables:
   ```bash
   cp .env.example .env.local
   ```
   Then update the file with your MongoDB connection string.

5. Run the development server:
   ```bash
   npm run dev
   ```

6. Open your browser at:
   ```text
   http://localhost:3000
   ```

### 📁 Project Structure
```text
securiscan/
├── src/
│   ├── app/              # Next.js App Router pages and API routes
│   ├── components/       # Reusable React components
│   ├── lib/              # Utility functions and database connection
│   └── types/            # TypeScript type definitions
├── scanners/             # Python vulnerability scanning modules
│   ├── port_scanner.py
│   ├── sql_injection.py
│   ├── xss_scanner.py
│   └── ssl_checker.py
├── public/               # Static assets
└── reports/              # Generated PDF reports
```

### 📋 Planned Features
- Port scanning with service detection
- SQL Injection detection
- Cross-Site Scripting (XSS) detection
- SSL/TLS certificate analysis
- Security header auditing
- Technology stack fingerprinting
- Risk-based prioritization dashboard
- User authentication and RBAC
- Remediation workflow and ticketing
- Professional PDF report generation