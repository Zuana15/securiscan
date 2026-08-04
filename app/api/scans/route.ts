import { spawn } from "node:child_process";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";

import { authOptions } from "@/src/lib/auth-options";
import { persistScanReport } from "@/src/lib/scan-repository";
import { SCANNER_IDS, type ScanReport, type ScannerId } from "@/src/lib/scan-types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 90;

const SCAN_TIMEOUT_MS = 85_000;
const MAX_TARGET_LENGTH = 2_048;
const MAX_PROCESS_OUTPUT = 512_000;

class RequestError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

function normalizeTarget(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new RequestError("Enter a target URL to scan.", 400);
  }

  const candidate = value.trim();
  if (candidate.length > MAX_TARGET_LENGTH) {
    throw new RequestError("The target URL is too long.", 400);
  }

  let target: URL;
  try {
    target = new URL(
      candidate.startsWith("http://") || candidate.startsWith("https://")
        ? candidate
        : `https://${candidate}`,
    );
  } catch {
    throw new RequestError("Enter a valid HTTP or HTTPS URL.", 400);
  }

  if (
    !["http:", "https:"].includes(target.protocol) ||
    !target.hostname ||
    target.username ||
    target.password
  ) {
    throw new RequestError("Use a public HTTP or HTTPS URL without credentials.", 400);
  }

  target.hash = "";
  return target.toString();
}

function isBlockedAddress(address: string): boolean {
  const version = isIP(address);

  if (version === 4) {
    const [first, second, third] = address.split(".").map(Number);
    return (
      first === 0 ||
      first === 10 ||
      first === 127 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && (second === 0 || second === 168 || second === 2)) ||
      (first === 198 && (second === 18 || second === 19 || second === 51)) ||
      (first === 203 && second === 0 && third === 113) ||
      first >= 224
    );
  }

  if (version === 6) {
    const normalized = address.toLowerCase();
    return (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      normalized.startsWith("fe8") ||
      normalized.startsWith("fe9") ||
      normalized.startsWith("fea") ||
      normalized.startsWith("feb") ||
      normalized.startsWith("::ffff:") ||
      normalized.startsWith("2001:db8")
    );
  }

  return true;
}

async function ensurePublicTarget(target: string): Promise<void> {
  const { hostname } = new URL(target);
  const addresses = isIP(hostname)
    ? [{ address: hostname }]
    : await lookup(hostname, { all: true, verbatim: true });

  if (!addresses.length || addresses.some(({ address }) => isBlockedAddress(address))) {
    throw new RequestError(
      "Only targets that resolve exclusively to public internet addresses can be scanned.",
      400,
    );
  }
}

function canScanPrivateDevelopmentTargets(): boolean {
  return (
    process.env.NODE_ENV === "development" &&
    process.env.SECURISCAN_ALLOW_PRIVATE_TARGETS === "true"
  );
}

function parseScanners(value: unknown): ScannerId[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new RequestError("Choose at least one scanner.", 400);
  }

  const selected = [...new Set(value)];
  if (
    selected.length > SCANNER_IDS.length ||
    selected.some((item) => typeof item !== "string" || !SCANNER_IDS.includes(item as ScannerId))
  ) {
    throw new RequestError("The selected scanners are not valid.", 400);
  }

  return selected as ScannerId[];
}

function extractReport(output: string): ScanReport {
  const marker = "--- RESULTS (JSON) ---";
  const start = output.lastIndexOf(marker);
  if (start === -1) {
    throw new Error("The scanner completed without producing a readable report.");
  }

  return JSON.parse(output.slice(start + marker.length).trim()) as ScanReport;
}

function runScan(target: string, scanners: ScannerId[]): Promise<ScanReport> {
  const python =
    process.env.SECURISCAN_PYTHON?.trim() ||
    (process.platform === "win32"
      ? "..\\.venv\\Scripts\\python.exe"
      : "../.venv/bin/python");
  const scannerDirectory = "scanners";
  const script = "run_scan.py";

  return new Promise((resolve, reject) => {
    const scannerProcess = spawn(python, [script, target, "--scanners", ...scanners], {
      cwd: scannerDirectory,
      env: {
        ...process.env,
        PYTHONIOENCODING: "utf-8",
        SECURISCAN_REQUIRE_PUBLIC_TARGETS: "1",
      },
      shell: false,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    let settled = false;

    const finish = (callback: () => void) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        callback();
      }
    };

    const timeout = setTimeout(() => {
      scannerProcess.kill();
      finish(() => reject(new Error("The scan exceeded the 85-second safety limit.")));
    }, SCAN_TIMEOUT_MS);

    scannerProcess.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
      if (stdout.length > MAX_PROCESS_OUTPUT) {
        scannerProcess.kill();
        finish(() => reject(new Error("The scanner produced too much output.")));
      }
    });

    scannerProcess.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
      if (stderr.length > MAX_PROCESS_OUTPUT) {
        scannerProcess.kill();
        finish(() => reject(new Error("The scanner produced too much diagnostic output.")));
      }
    });

    scannerProcess.once("error", (error: NodeJS.ErrnoException) => {
      finish(() => {
        if (error.code === "ENOENT") {
          reject(
            new Error(
              "The Python scanner environment was not found. Create the project virtual environment or set SECURISCAN_PYTHON.",
            ),
          );
          return;
        }
        reject(error);
      });
    });

    scannerProcess.once("close", (code) => {
      finish(() => {
        if (code !== 0) {
          reject(
            new Error(stderr.trim() || "The scanner process stopped before the assessment completed."),
          );
          return;
        }

        try {
          resolve(extractReport(stdout));
        } catch (error) {
          reject(error);
        }
      });
    });
  });
}

export async function POST(request: Request) {
  try {
    const session = await getServerSession(authOptions);
    const ownerId = session?.user?.id;
    if (!ownerId) {
      return NextResponse.json({ error: "Sign in before running an assessment." }, { status: 401 });
    }

    const body: unknown = await request.json();
    if (!body || typeof body !== "object") {
      throw new RequestError("Send a valid scan request.", 400);
    }

    const { target, scanners, authorized } = body as Record<string, unknown>;
    if (authorized !== true) {
      throw new RequestError(
        "Confirm that you own the target or have written authorization before scanning.",
        403,
      );
    }

    const normalizedTarget = normalizeTarget(target);
    const selectedScanners = parseScanners(scanners);
    if (!canScanPrivateDevelopmentTargets()) {
      await ensurePublicTarget(normalizedTarget);
    }
    const report = await runScan(normalizedTarget, selectedScanners);

    const persistence = await persistScanReport(report, selectedScanners, ownerId);

    return NextResponse.json({ ...report, persistence });
  } catch (error) {
    if (error instanceof RequestError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }

    console.error("Scan request failed", error);
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "The scan could not be completed. Please try again.",
      },
      { status: 500 },
    );
  }
}
