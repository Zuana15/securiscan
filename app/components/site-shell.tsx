"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut } from "next-auth/react";
import { createContext, useContext, useState } from "react";

interface ThemeContextValue {
  darkTheme: boolean;
}

const ThemeContext = createContext<ThemeContextValue>({ darkTheme: false });

const navigation = [
  { href: "/", label: "Home" },
  { href: "/scans", label: "Scans" },
  { href: "/history", label: "Scan history" },
  { href: "/analytics", label: "Analytics" },
];

interface SiteUser {
  id: string;
  name: string | null;
  email: string | null;
  role: "owner" | "analyst" | "viewer";
}

interface SiteShellProps {
  children: React.ReactNode;
  initialUser: SiteUser | null;
}

export function useSiteTheme() {
  return useContext(ThemeContext);
}

function BrandIcon() {
  return (
    <span className="site-brand-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" role="presentation">
        <path d="M12 2.8 20 6v5.4c0 5.1-3.2 8.6-8 10.6-4.8-2-8-5.5-8-10.6V6l8-3.2Z" />
        <path d="m8.7 12.2 2.1 2.1 4.7-5" />
      </svg>
    </span>
  );
}

export default function SiteShell({ children, initialUser }: SiteShellProps) {
  const pathname = usePathname();
  const [darkTheme, setDarkTheme] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  async function endSession() {
    await signOut({ redirect: false });
    window.location.assign("/");
  }

  const userLabel = initialUser?.name ?? initialUser?.email ?? "Account";
  const userInitial = userLabel.charAt(0).toUpperCase();

  return (
    <ThemeContext.Provider value={{ darkTheme }}>
      <div className={`site-shell ${darkTheme ? "site-theme-dark" : "site-theme-light"}`}>
        <header className="site-header">
          <div className="site-header-inner">
            <Link className="site-brand" href="/" onClick={() => setMobileMenuOpen(false)}>
              <BrandIcon />
              <span>
                <strong>SecuriScan</strong>
                <small>Web security, made clear</small>
              </span>
            </Link>

            <button
              className="mobile-menu-button"
              type="button"
              aria-label={mobileMenuOpen ? "Close navigation" : "Open navigation"}
              aria-expanded={mobileMenuOpen}
              onClick={() => setMobileMenuOpen((current) => !current)}
            >
              <span />
              <span />
              <span />
            </button>

            <nav className={`site-navigation ${mobileMenuOpen ? "site-navigation-open" : ""}`} aria-label="Primary navigation">
              {navigation.map((item) => {
                const active = pathname === item.href;
                return (
                  <Link
                    className={active ? "site-nav-active" : ""}
                    href={item.href}
                    key={item.href}
                    aria-current={active ? "page" : undefined}
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    {item.label}
                  </Link>
                );
              })}
              <div className="mobile-auth-actions">
                {initialUser ? (
                  <>
                    <span className="mobile-account-label"><i>{userInitial}</i>{userLabel}</span>
                    <button type="button" onClick={() => void endSession()}>Sign out</button>
                  </>
                ) : (
                  <>
                    <Link className="mobile-sign-in" href="/scans?auth=sign-in#account-title" onClick={() => setMobileMenuOpen(false)}>Sign in</Link>
                    <Link className="mobile-create-account" href="/scans?auth=sign-up#account-title" onClick={() => setMobileMenuOpen(false)}>Create account</Link>
                  </>
                )}
              </div>
            </nav>

            <div className="site-header-actions">
              <button
                className="site-theme-toggle"
                type="button"
                onClick={() => setDarkTheme((current) => !current)}
                aria-label={darkTheme ? "Switch to light theme" : "Switch to dark theme"}
              >
                {darkTheme ? (
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <circle cx="12" cy="12" r="4" />
                    <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M20 15.2A8.5 8.5 0 0 1 8.8 4a8.5 8.5 0 1 0 11.2 11.2Z" />
                  </svg>
                )}
              </button>
              {initialUser ? (
                <>
                  <div className="site-account-summary" title={initialUser.email ?? userLabel}>
                    <span>{userInitial}</span>
                    <div><strong>{userLabel}</strong><small>{initialUser.role}</small></div>
                  </div>
                  <button className="site-sign-out" type="button" onClick={() => void endSession()}>Sign out</button>
                </>
              ) : (
                <>
                  <Link className="site-sign-in" href="/scans?auth=sign-in#account-title">Sign in</Link>
                  <Link className="site-header-cta" href="/scans?auth=sign-up#account-title">Create account</Link>
                </>
              )}
            </div>
          </div>
        </header>

        <div className="site-content">{children}</div>

        <footer className="site-footer">
          <div className="site-footer-grid">
            <div className="site-footer-brand">
              <Link className="site-brand" href="/">
                <BrandIcon />
                <span><strong>SecuriScan</strong><small>Authorized vulnerability assessment</small></span>
              </Link>
              <p>Focused web-security scanning, account-isolated evidence, and remediation guidance in one clear workspace.</p>
              <div className="footer-socials" aria-label="Social links">
                <a href="https://github.com/Zuana15/securiscan" target="_blank" rel="noreferrer">GitHub</a>
                <Link href="/#contact">Contact</Link>
              </div>
            </div>

            <div>
              <h2>Product</h2>
              <Link href="/scans">New scan</Link>
              <Link href="/history">Scan history</Link>
              <Link href="/analytics">Analytics</Link>
            </div>
            <div>
              <h2>Platform</h2>
              <Link href="/#capabilities">Capabilities</Link>
              <Link href="/#workflow">How it works</Link>
              <Link href="/#security">Security model</Link>
            </div>
            <div>
              <h2>Resources</h2>
              <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noreferrer">OWASP Top 10</a>
              <a href="https://github.com/Zuana15/securiscan" target="_blank" rel="noreferrer">Source repository</a>
              <Link href="/#contact">Support</Link>
            </div>
          </div>
          <div className="site-footer-bottom">
            <span>© 2026 SecuriScan. Built for authorized security assessment.</span>
            <span>Privacy-first · No AI scoring · Rule-based findings</span>
          </div>
        </footer>
      </div>
    </ThemeContext.Provider>
  );
}
