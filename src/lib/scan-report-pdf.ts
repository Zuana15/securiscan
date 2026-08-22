import {
  PDFDocument,
  StandardFonts,
  rgb,
  type PDFFont,
  type PDFPage,
} from "pdf-lib";

import { SCANNERS, type ScanReport, type Severity } from "@/src/lib/scan-types";

const PAGE_WIDTH = 595.28;
const PAGE_HEIGHT = 841.89;
const PAGE_MARGIN = 46;
const CONTENT_WIDTH = PAGE_WIDTH - PAGE_MARGIN * 2;
const CONTENT_BOTTOM = 52;

const palette = {
  ink: rgb(0.09, 0.17, 0.14),
  muted: rgb(0.35, 0.43, 0.39),
  line: rgb(0.84, 0.89, 0.86),
  paper: rgb(0.98, 0.99, 0.985),
  green: rgb(0.03, 0.43, 0.31),
  greenSoft: rgb(0.90, 0.96, 0.93),
  white: rgb(1, 1, 1),
  critical: rgb(0.69, 0.10, 0.08),
  criticalSoft: rgb(0.98, 0.90, 0.89),
  high: rgb(0.74, 0.31, 0.04),
  highSoft: rgb(1, 0.93, 0.87),
  medium: rgb(0.65, 0.45, 0.00),
  mediumSoft: rgb(1, 0.96, 0.83),
  low: rgb(0.09, 0.32, 0.67),
  lowSoft: rgb(0.90, 0.94, 1),
  info: rgb(0.03, 0.43, 0.31),
  infoSoft: rgb(0.91, 0.96, 0.93),
};

const severityOrder: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function cleanText(value: unknown) {
  return String(value ?? "")
    .normalize("NFKD")
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/\u2022/g, "-")
    .replace(/[^\x20-\x7E\n]/g, "")
    .replace(/[ \t]+/g, " ")
    .trim();
}

function truncate(value: unknown, length: number) {
  const text = cleanText(value);
  return text.length > length ? `${text.slice(0, length - 3)}...` : text;
}

function splitLongWord(word: string, font: PDFFont, size: number, maxWidth: number) {
  const chunks: string[] = [];
  let chunk = "";
  for (const character of word) {
    if (font.widthOfTextAtSize(chunk + character, size) <= maxWidth) {
      chunk += character;
    } else {
      if (chunk) chunks.push(chunk);
      chunk = character;
    }
  }
  if (chunk) chunks.push(chunk);
  return chunks;
}

function wrapText(text: unknown, font: PDFFont, size: number, maxWidth: number) {
  const lines: string[] = [];
  const paragraphs = cleanText(text).split("\n");

  for (const paragraph of paragraphs) {
    const rawWords = paragraph.split(" ").filter(Boolean);
    const words = rawWords.flatMap((word) =>
      font.widthOfTextAtSize(word, size) > maxWidth
        ? splitLongWord(word, font, size, maxWidth)
        : [word],
    );
    let line = "";
    for (const word of words) {
      const nextLine = line ? `${line} ${word}` : word;
      if (font.widthOfTextAtSize(nextLine, size) <= maxWidth) {
        line = nextLine;
      } else {
        if (line) lines.push(line);
        line = word;
      }
    }
    if (line) lines.push(line);
    if (!paragraph && lines.length) lines.push("");
  }

  return lines.length ? lines : [""];
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? cleanText(value)
    : new Intl.DateTimeFormat("en-GB", {
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
        timeZone: "UTC",
      }).format(date) + " UTC";
}

function moduleName(scanType: string) {
  const aliases: Record<string, string> = {
    security_headers: "headers",
    ssl_tls: "ssl",
    tech_fingerprint: "tech",
    sensitive_files: "files",
    http_misconfiguration: "misconfig",
    port_scan: "port",
    sql_injection: "sql",
  };
  const scannerId = aliases[scanType] ?? scanType;
  return SCANNERS.find((scanner) => scanner.id === scannerId)?.name ?? cleanText(scanType);
}

function severityColors(severity: Severity) {
  return {
    strong: palette[severity],
    soft: palette[`${severity}Soft` as keyof typeof palette],
  };
}

export interface ScanPdfOptions {
  reportId: string;
  generatedAt?: Date;
}

export async function generateScanReportPdf(report: ScanReport, options: ScanPdfOptions) {
  const pdf = await PDFDocument.create();
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const mono = await pdf.embedFont(StandardFonts.Courier);
  const generatedAt = options.generatedAt ?? new Date();
  const pages: PDFPage[] = [];
  let page!: PDFPage;
  let y = 0;

  pdf.setTitle(`SecuriScan assessment - ${cleanText(report.target)}`);
  pdf.setSubject("Authorized web application security assessment report");
  pdf.setAuthor("SecuriScan");
  pdf.setCreator("SecuriScan PDF reporting");
  pdf.setProducer("SecuriScan");
  pdf.setCreationDate(generatedAt);

  function addPage(section = "SECURITY ASSESSMENT") {
    page = pdf.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
    pages.push(page);
    page.drawRectangle({ x: 0, y: 0, width: PAGE_WIDTH, height: PAGE_HEIGHT, color: palette.white });
    page.drawRectangle({
      x: PAGE_MARGIN - 8,
      y: PAGE_HEIGHT - 56,
      width: 32,
      height: 32,
      color: palette.green,
    });
    page.drawText("S", {
      x: PAGE_MARGIN + 3,
      y: PAGE_HEIGHT - 48,
      size: 14,
      font: bold,
      color: palette.white,
    });
    page.drawText("SECURISCAN", {
      x: PAGE_MARGIN + 34,
      y: PAGE_HEIGHT - 45,
      size: 12,
      font: bold,
      color: palette.ink,
    });
    page.drawText(section, {
      x: PAGE_WIDTH - PAGE_MARGIN - bold.widthOfTextAtSize(section, 7.5),
      y: PAGE_HEIGHT - 44,
      size: 7.5,
      font: bold,
      color: palette.green,
    });
    page.drawLine({
      start: { x: PAGE_MARGIN, y: PAGE_HEIGHT - 67 },
      end: { x: PAGE_WIDTH - PAGE_MARGIN, y: PAGE_HEIGHT - 67 },
      thickness: 0.8,
      color: palette.line,
    });
    y = PAGE_HEIGHT - 92;
    return page;
  }

  function ensureSpace(height: number, section?: string) {
    if (y - height < CONTENT_BOTTOM) addPage(section);
  }

  function drawLines(
    text: unknown,
    {
      x = PAGE_MARGIN,
      width = CONTENT_WIDTH,
      size = 9.5,
      lineHeight = size * 1.35,
      font = regular,
      color = palette.ink,
      section,
    }: {
      x?: number;
      width?: number;
      size?: number;
      lineHeight?: number;
      font?: PDFFont;
      color?: ReturnType<typeof rgb>;
      section?: string;
    } = {},
  ) {
    const lines = wrapText(text, font, size, width);
    for (const line of lines) {
      ensureSpace(lineHeight, section);
      page.drawText(line, { x, y, size, font, color });
      y -= lineHeight;
    }
    return lines.length * lineHeight;
  }

  function sectionTitle(label: string, title: string) {
    ensureSpace(48);
    page.drawText(cleanText(label).toUpperCase(), {
      x: PAGE_MARGIN,
      y,
      size: 7.5,
      font: bold,
      color: palette.green,
    });
    y -= 19;
    drawLines(title, { size: 17, lineHeight: 21, font: bold, color: palette.ink });
    y -= 9;
  }

  function drawKeyValue(label: string, value: unknown, x: number, width: number) {
    page.drawText(cleanText(label).toUpperCase(), {
      x,
      y,
      size: 6.5,
      font: bold,
      color: palette.green,
    });
    const valueLines = wrapText(value, regular, 8.5, width);
    valueLines.slice(0, 2).forEach((line, index) => {
      page.drawText(line, {
        x,
        y: y - 14 - index * 11,
        size: 8.5,
        font: regular,
        color: palette.ink,
      });
    });
  }

  addPage("ASSESSMENT REPORT");
  page.drawText("AUTHORIZED WEB SECURITY ASSESSMENT", {
    x: PAGE_MARGIN,
    y,
    size: 8,
    font: bold,
    color: palette.green,
  });
  y -= 31;
  drawLines("Vulnerability Assessment Report", {
    size: 27,
    lineHeight: 31,
    font: bold,
    color: palette.ink,
  });
  y -= 5;
  drawLines(report.target, { size: 12, lineHeight: 16, color: palette.muted });
  y -= 19;

  page.drawRectangle({
    x: PAGE_MARGIN,
    y: y - 66,
    width: CONTENT_WIDTH,
    height: 66,
    color: palette.paper,
    borderColor: palette.line,
    borderWidth: 0.7,
  });
  const detailsY = y - 17;
  const savedY = y;
  y = detailsY;
  drawKeyValue("Assessment completed", formatDate(report.timestamp), PAGE_MARGIN + 15, 145);
  drawKeyValue("Report ID", options.reportId, PAGE_MARGIN + 180, 150);
  drawKeyValue("Status", cleanText(report.status).toUpperCase(), PAGE_MARGIN + 360, 125);
  y = savedY - 91;

  page.drawText("FINDINGS BY SEVERITY", {
    x: PAGE_MARGIN,
    y,
    size: 7.5,
    font: bold,
    color: palette.green,
  });
  y -= 17;
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  const gap = 7;
  const cardWidth = (CONTENT_WIDTH - gap * 4) / 5;
  severities.forEach((severity, index) => {
    const x = PAGE_MARGIN + index * (cardWidth + gap);
    const colors = severityColors(severity);
    page.drawRectangle({
      x,
      y: y - 59,
      width: cardWidth,
      height: 59,
      color: colors.soft,
    });
    page.drawText(severity.toUpperCase(), {
      x: x + 11,
      y: y - 17,
      size: 6.5,
      font: bold,
      color: colors.strong,
    });
    page.drawText(String(report.summary[severity]), {
      x: x + 11,
      y: y - 43,
      size: 20,
      font: bold,
      color: colors.strong,
    });
  });
  y -= 86;

  sectionTitle("Executive summary", "Assessment snapshot");
  const completedModules = Object.values(report.scans).filter((scan) => scan.status === "completed").length;
  const failedModules = Object.values(report.scans).length - completedModules;
  drawLines(
    `SecuriScan completed an authorized assessment of ${report.target}. The selected modules produced ${report.summary.total_findings} findings. ${completedModules} modules completed successfully${failedModules ? ` and ${failedModules} could not complete` : ""}. Findings are ordered using the deterministic Risk v1 model when scoring data is available.`,
    { size: 9.5, lineHeight: 14, color: palette.muted },
  );
  y -= 15;

  if (report.riskSummary) {
    page.drawRectangle({
      x: PAGE_MARGIN,
      y: y - 64,
      width: CONTENT_WIDTH,
      height: 64,
      color: palette.greenSoft,
    });
    const metrics = [
      ["Highest risk", `${report.riskSummary.highestScore}/100`],
      ["Average risk", `${report.riskSummary.averageScore}/100`],
      ["Critical priority", report.riskSummary.priorities.critical],
      ["High priority", report.riskSummary.priorities.high],
    ];
    metrics.forEach(([label, value], index) => {
      const x = PAGE_MARGIN + 15 + index * 122;
      page.drawText(cleanText(label).toUpperCase(), { x, y: y - 18, size: 6.2, font: bold, color: palette.green });
      page.drawText(cleanText(value), { x, y: y - 45, size: 17, font: bold, color: palette.ink });
    });
    y -= 85;
  }

  sectionTitle("Coverage", "Scanner module status");
  const scans = Object.values(report.scans);
  for (let index = 0; index < scans.length; index += 3) {
    ensureSpace(47);
    const row = scans.slice(index, index + 3);
    row.forEach((scan, column) => {
      const x = PAGE_MARGIN + column * 169;
      const completed = scan.status === "completed";
      page.drawRectangle({
        x,
        y: y - 37,
        width: 158,
        height: 37,
        color: completed ? palette.greenSoft : palette.criticalSoft,
      });
      page.drawText(truncate(moduleName(scan.scan_type), 26), { x: x + 9, y: y - 14, size: 7.5, font: bold, color: palette.ink });
      page.drawText(
        completed
          ? `${scan.summary.total_findings} finding${scan.summary.total_findings === 1 ? "" : "s"} | completed`
          : "could not complete",
        { x: x + 9, y: y - 27, size: 6.4, font: regular, color: completed ? palette.green : palette.critical },
      );
    });
    y -= 45;
  }

  const sortedFindings = [...report.findings].sort((left, right) => {
    const riskDifference = (right.risk?.score ?? -1) - (left.risk?.score ?? -1);
    return riskDifference || severityOrder[left.severity] - severityOrder[right.severity];
  });

  addPage("PRIORITIZED FINDINGS");
  sectionTitle("Detailed results", `${sortedFindings.length} prioritized findings`);
  drawLines(
    "Review higher risk scores first. Scanner severity describes the technical observation; Risk v1 also considers the analyst-supplied business and threat context.",
    { size: 8.5, lineHeight: 12, color: palette.muted },
  );
  y -= 12;

  sortedFindings.forEach((finding, index) => {
    const colors = severityColors(finding.severity);
    const titleLines = wrapText(`${index + 1}. ${finding.title}`, bold, 11, 380);
    const descriptionLines = wrapText(truncate(finding.description, 900), regular, 8.6, CONTENT_WIDTH - 28);
    const metadata = [
      finding.owasp || finding.cwe ? `Classification: ${[finding.owasp, finding.cwe].filter(Boolean).join(" | ")}` : "",
      finding.location ? `Location: ${truncate(finding.location, 500)}` : "",
      finding.evidence ? `Evidence: ${truncate(finding.evidence, 900)}` : "",
      finding.recommendation ? `Recommended action: ${truncate(finding.recommendation, 900)}` : "",
    ].filter(Boolean);
    const metadataLines = metadata.flatMap((entry) => wrapText(entry, regular, 7.8, CONTENT_WIDTH - 28));
    const cardHeight = Math.min(
      610,
      35 + titleLines.length * 14 + descriptionLines.length * 11.5 + metadataLines.length * 10.5 + 18,
    );
    ensureSpace(cardHeight + 12, "PRIORITIZED FINDINGS");
    const cardTop = y;
    page.drawRectangle({
      x: PAGE_MARGIN,
      y: cardTop - cardHeight,
      width: CONTENT_WIDTH,
      height: cardHeight,
      color: palette.paper,
      borderColor: palette.line,
      borderWidth: 0.65,
    });
    page.drawRectangle({ x: PAGE_MARGIN, y: cardTop - cardHeight, width: 4, height: cardHeight, color: colors.strong });
    const badge = finding.risk ? `RISK ${finding.risk.score}` : finding.severity.toUpperCase();
    page.drawRectangle({
      x: PAGE_WIDTH - PAGE_MARGIN - 73,
      y: cardTop - 27,
      width: 59,
      height: 17,
      color: colors.soft,
    });
    page.drawText(badge, {
      x: PAGE_WIDTH - PAGE_MARGIN - 66,
      y: cardTop - 21.5,
      size: 6.8,
      font: bold,
      color: colors.strong,
    });
    y = cardTop - 18;
    titleLines.forEach((line) => {
      page.drawText(line, { x: PAGE_MARGIN + 14, y, size: 11, font: bold, color: palette.ink });
      y -= 14;
    });
    page.drawText(`${moduleName(finding.scan_type ?? "assessment")} | ${finding.severity.toUpperCase()}`, {
      x: PAGE_MARGIN + 14,
      y,
      size: 6.8,
      font: bold,
      color: colors.strong,
    });
    y -= 16;
    descriptionLines.forEach((line) => {
      page.drawText(line, { x: PAGE_MARGIN + 14, y, size: 8.6, font: regular, color: palette.muted });
      y -= 11.5;
    });
    y -= 3;
    metadataLines.forEach((line) => {
      page.drawText(line, { x: PAGE_MARGIN + 14, y, size: 7.8, font: regular, color: palette.ink });
      y -= 10.5;
    });
    y = cardTop - cardHeight - 12;
  });

  addPage("CONTEXT AND METHODOLOGY");
  sectionTitle("Risk context", "Analyst-supplied assessment context");
  if (report.riskContext) {
    const contextRows = [
      ["Asset criticality", report.riskContext.assetCriticality],
      ["Exposure", report.riskContext.exposure],
      ["Threat context", report.riskContext.threatIntel],
      ["Business impact", report.riskContext.businessImpact],
      ["Compensating controls", report.riskContext.compensatingControls],
    ];
    contextRows.forEach(([label, value]) => {
      ensureSpace(35);
      page.drawLine({ start: { x: PAGE_MARGIN, y: y - 24 }, end: { x: PAGE_WIDTH - PAGE_MARGIN, y: y - 24 }, thickness: 0.5, color: palette.line });
      page.drawText(label, { x: PAGE_MARGIN, y: y - 11, size: 8.5, font: bold, color: palette.ink });
      page.drawText(cleanText(value).toUpperCase(), { x: PAGE_WIDTH - PAGE_MARGIN - 120, y: y - 11, size: 7.5, font: bold, color: palette.green });
      y -= 32;
    });
  } else {
    drawLines("No analyst-supplied business context was stored for this assessment.", { color: palette.muted });
  }
  y -= 18;

  sectionTitle("Methodology", "How to interpret this report");
  const methodology = [
    ["Deterministic detection", "Findings and remedies are produced by rules inside the nine scanner modules. No external generative-AI service is used to create findings or recommendations."],
    ["Risk v1", "The explainable scoring model combines technical severity, asset criticality, exposure, threat context, business impact, exploitability, and compensating controls. Scores support prioritization and do not replace professional judgment."],
    ["Coverage boundary", "A completed module means its configured checks ran against the target. A failed module is reported as could not complete and should be rerun after resolving reachability, TLS, firewall, or authorization constraints."],
    ["Authorization", "This report is intended only for systems owned by the user or covered by explicit written authorization. Results should be validated before remediation or disclosure."],
  ];
  methodology.forEach(([heading, body]) => {
    ensureSpace(62);
    page.drawText(heading.toUpperCase(), { x: PAGE_MARGIN, y, size: 7, font: bold, color: palette.green });
    y -= 15;
    drawLines(body, { size: 8.7, lineHeight: 12.5, color: palette.muted });
    y -= 11;
  });

  y -= 7;
  ensureSpace(82);
  page.drawRectangle({
    x: PAGE_MARGIN,
    y: y - 68,
    width: CONTENT_WIDTH,
    height: 68,
    color: palette.greenSoft,
  });
  page.drawText("NEXT ACTION", { x: PAGE_MARGIN + 15, y: y - 20, size: 7, font: bold, color: palette.green });
  const actionLines = wrapText(
    "Validate high-priority findings, assign an owner and deadline, apply the recommended control, then rerun SecuriScan to confirm remediation.",
    bold,
    9.5,
    CONTENT_WIDTH - 30,
  );
  actionLines.forEach((line, index) => {
    page.drawText(line, { x: PAGE_MARGIN + 15, y: y - 39 - index * 13, size: 9.5, font: bold, color: palette.ink });
  });

  pages.forEach((currentPage, index) => {
    const footerY = 27;
    currentPage.drawLine({
      start: { x: PAGE_MARGIN, y: footerY + 15 },
      end: { x: PAGE_WIDTH - PAGE_MARGIN, y: footerY + 15 },
      thickness: 0.55,
      color: palette.line,
    });
    const footerText = `Generated ${formatDate(generatedAt.toISOString())} | Report ${cleanText(options.reportId)}`;
    currentPage.drawText(footerText, { x: PAGE_MARGIN, y: footerY, size: 6.3, font: mono, color: palette.muted });
    const pageNumber = `${index + 1} / ${pages.length}`;
    currentPage.drawText(pageNumber, {
      x: PAGE_WIDTH - PAGE_MARGIN - mono.widthOfTextAtSize(pageNumber, 6.3),
      y: footerY,
      size: 6.3,
      font: mono,
      color: palette.muted,
    });
  });

  return pdf.save();
}
