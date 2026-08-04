"use client";

import Link from "next/link";
import { FormEvent, useEffect, useRef, useState } from "react";

import { SCANNERS } from "@/src/lib/scan-types";

const capabilities = [
  {
    number: "01",
    title: "Nine focused scanners",
    copy: "Cover headers, TLS, technology fingerprints, sensitive files, HTTP configuration, ports, SQL injection, reflected XSS, and CSRF controls.",
  },
  {
    number: "02",
    title: "Evidence you can act on",
    copy: "Every finding is returned with severity, location, technical evidence, OWASP and CWE context, plus a clear recommended action.",
  },
  {
    number: "03",
    title: "Private scan history",
    copy: "MongoDB-backed records are isolated by account, giving every user a private assessment trail and useful trend analytics.",
  },
  {
    number: "04",
    title: "Rule-based transparency",
    copy: "Detection and remediation guidance comes from auditable scanner rules—no hidden AI scoring and no unexplained recommendations.",
  },
  {
    number: "05",
    title: "Authorization first",
    copy: "Targets require an explicit ownership or written-authorization confirmation before active assessment modules can run.",
  },
  {
    number: "06",
    title: "Clear risk overview",
    copy: "Severity summaries, module coverage, findings history, and trends turn raw scanner output into a practical security picture.",
  },
];

const workflow = [
  { step: "01", title: "Choose your target", copy: "Enter an authorized HTTP or HTTPS target and select the assessment modules that match your scope." },
  { step: "02", title: "Run the assessment", copy: "The Next.js API securely launches the Python scanner runner and collects normalized JSON findings." },
  { step: "03", title: "Prioritize remediation", copy: "Review evidence, OWASP and CWE mappings, severity, and concrete remediation steps in one dashboard." },
];

function ArrowIcon() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true">
      <path d="M4 10h12M11 5l5 5-5 5" />
    </svg>
  );
}

export default function LandingPage() {
  const pageRef = useRef<HTMLElement>(null);
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    const root = pageRef.current;
    if (!root) return;

    const elements = Array.from(root.querySelectorAll<HTMLElement>("[data-reveal]"));
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            (entry.target as HTMLElement).dataset.revealed = "true";
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.14, rootMargin: "0px 0px -8%" },
    );

    elements.forEach((element) => observer.observe(element));
    return () => observer.disconnect();
  }, []);

  function submitContact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitted(true);
    event.currentTarget.reset();
  }

  return (
    <main className="landing-page" ref={pageRef}>
      <section className="landing-hero" aria-labelledby="landing-title">
        <div className="landing-hero-copy">
          <div className="landing-kicker"><i /> Security assessment, without the noise</div>
          <h1 id="landing-title">See your web risk.<br /><span>Know what to fix next.</span></h1>
          <p>
            SecuriScan brings nine focused vulnerability checks, evidence-backed findings, and clear remediation guidance into one private security workspace.
          </p>
          <div className="landing-hero-actions">
            <Link className="landing-primary-button" href="/scans">Start an assessment <ArrowIcon /></Link>
            <a className="landing-secondary-button" href="#capabilities">Explore capabilities</a>
          </div>
          <div className="landing-trust-row">
            <span><strong>09</strong> scanning modules</span>
            <span><strong>OWASP</strong> mapped context</span>
            <span><strong>100%</strong> authorized workflow</span>
          </div>
        </div>

        <div className="landing-product-visual" aria-label="SecuriScan assessment preview">
          <div className="visual-orbit visual-orbit-one" />
          <div className="visual-orbit visual-orbit-two" />
          <div className="scan-window">
            <div className="scan-window-bar">
              <div><i /><i /><i /></div>
              <span>assessment.sec</span>
              <em>Live</em>
            </div>
            <div className="scan-window-body">
              <div className="visual-target-row">
                <span>Target</span>
                <strong>https://app.example.com</strong>
                <i />
              </div>
              <div className="visual-progress-heading"><span>Assessment progress</span><strong>9 / 9</strong></div>
              <div className="visual-progress"><i /></div>
              <div className="visual-severity-grid">
                <div className="visual-critical"><span>Critical</span><strong>3</strong></div>
                <div className="visual-high"><span>High</span><strong>5</strong></div>
                <div className="visual-medium"><span>Medium</span><strong>12</strong></div>
              </div>
              <div className="visual-findings">
                <div><span className="visual-finding-icon">!</span><p><strong>Exposed environment file</strong><small>Sensitive files · CWE-538</small></p><em>Critical</em></div>
                <div><span className="visual-finding-icon">↗</span><p><strong>Reflected Cross-Site Scripting</strong><small>Reflected XSS · CWE-79</small></p><em>High</em></div>
                <div><span className="visual-finding-icon">✓</span><p><strong>All modules completed</strong><small>Evidence stored securely</small></p><em className="visual-complete">Ready</em></div>
              </div>
            </div>
          </div>
          <div className="visual-float-card visual-float-left"><i /><span><strong>Scanner ready</strong><small>Python runner connected</small></span></div>
          <div className="visual-float-card visual-float-right"><strong>37</strong><span>findings organized</span></div>
        </div>
      </section>

      <section className="module-marquee" aria-label="Available assessment modules">
        <div>
          {[...SCANNERS, ...SCANNERS].map((scanner, index) => (
            <span key={`${scanner.id}-${index}`}><i />{scanner.name}</span>
          ))}
        </div>
      </section>

      <section className="landing-section capabilities-section" id="capabilities">
        <div className="landing-section-heading" data-reveal>
          <p>Everything in one workspace</p>
          <h2>From target URL to actionable finding.</h2>
          <span>Built to make security assessment understandable, repeatable, and useful for the people responsible for fixing it.</span>
        </div>
        <div className="capability-grid">
          {capabilities.map((capability, index) => (
            <article data-reveal data-delay={String((index % 3) + 1)} key={capability.number}>
              <div className="capability-number">{capability.number}</div>
              <h3>{capability.title}</h3>
              <p>{capability.copy}</p>
              <span className="capability-line" />
            </article>
          ))}
        </div>
      </section>

      <section className="landing-showcase" id="security">
        <div className="showcase-copy" data-reveal>
          <p>Built for clarity</p>
          <h2>Security evidence your team can actually use.</h2>
          <span>SecuriScan keeps the technical depth while organizing each result into a consistent, readable record.</span>
          <ul>
            <li><i>01</i><span><strong>Normalize every finding</strong><small>One structure for severity, evidence, location, context, and remedy.</small></span></li>
            <li><i>02</i><span><strong>Map security standards</strong><small>OWASP and CWE labels connect scanner output to recognized categories.</small></span></li>
            <li><i>03</i><span><strong>Protect account data</strong><small>Authentication and owner-scoped MongoDB queries isolate saved assessments.</small></span></li>
          </ul>
          <Link href="/scans">Open the scanner <ArrowIcon /></Link>
        </div>

        <div className="showcase-panel" data-reveal data-delay="2">
          <div className="showcase-panel-heading">
            <div><span>Assessment complete</span><strong>Findings overview</strong></div>
            <em>37 findings</em>
          </div>
          <div className="showcase-score-row">
            <div><strong>3</strong><span>Critical</span></div>
            <div><strong>5</strong><span>High</span></div>
            <div><strong>12</strong><span>Medium</span></div>
            <div><strong>4</strong><span>Low</span></div>
          </div>
          <div className="showcase-module-list">
            <div><span><i />Security headers</span><strong>7 findings</strong><em>Complete</em></div>
            <div><span><i />Sensitive files</span><strong>8 findings</strong><em>Complete</em></div>
            <div><span><i />HTTP configuration</span><strong>8 findings</strong><em>Complete</em></div>
            <div><span><i />Reflected XSS</span><strong>1 finding</strong><em>Complete</em></div>
          </div>
        </div>
      </section>

      <section className="landing-section workflow-section" id="workflow">
        <div className="landing-section-heading" data-reveal>
          <p>A simple, accountable workflow</p>
          <h2>Assess. Understand. Improve.</h2>
        </div>
        <div className="workflow-grid">
          {workflow.map((item, index) => (
            <article data-reveal data-delay={String(index + 1)} key={item.step}>
              <div><span>{item.step}</span><i /></div>
              <h3>{item.title}</h3>
              <p>{item.copy}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="landing-cta" data-reveal>
        <div>
          <p>Ready when you are</p>
          <h2>Turn your next scan into a clear remediation plan.</h2>
        </div>
        <Link href="/scans">Run your first scan <ArrowIcon /></Link>
      </section>

      <section className="contact-section" id="contact">
        <div className="contact-copy" data-reveal>
          <p>Contact us</p>
          <h2>Questions, feedback, or a project collaboration?</h2>
          <span>Tell us what you are working on. We would be happy to discuss the scanner, research collaboration, or deployment requirements.</span>
          <div className="contact-details">
            <div><i>01</i><span><strong>Project discussions</strong><small>Architecture, deployment, and custom scanner modules</small></span></div>
            <div><i>02</i><span><strong>Research collaboration</strong><small>Detection accuracy and risk-prioritization evaluation</small></span></div>
            <div><i>03</i><span><strong>Response time</strong><small>Usually within one to two business days</small></span></div>
          </div>
        </div>

        <form className="contact-form" onSubmit={submitContact} data-reveal data-delay="2">
          <div className="contact-form-row">
            <label>Full name<input name="name" type="text" placeholder="Your name" required /></label>
            <label>Email address<input name="email" type="email" placeholder="you@example.com" required /></label>
          </div>
          <label>Topic<select name="topic" defaultValue="General question"><option>General question</option><option>Scanner deployment</option><option>Research collaboration</option><option>Feature request</option></select></label>
          <label>Message<textarea name="message" rows={5} placeholder="Tell us how we can help…" required /></label>
          <button type="submit">Send message <ArrowIcon /></button>
          {submitted && <p className="contact-success" role="status">Thank you—your message form is ready. Connect an email service before production delivery.</p>}
        </form>
      </section>
    </main>
  );
}
