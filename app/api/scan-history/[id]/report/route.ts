import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";

import { authOptions } from "@/src/lib/auth-options";
import { isMongoConfigured } from "@/src/lib/mongodb";
import { generateScanReportPdf } from "@/src/lib/scan-report-pdf";
import { getScanReport } from "@/src/lib/scan-repository";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function reportFilename(target: string, reportId: string) {
  let targetName = "assessment";
  try {
    targetName = new URL(target).hostname || targetName;
  } catch {
    targetName = target;
  }

  const safeTarget = targetName
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || "assessment";
  return `securiscan-${safeTarget}-${reportId.slice(-6)}.pdf`;
}

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const session = await getServerSession(authOptions);
  const ownerId = session?.user?.id;
  if (!ownerId) {
    return NextResponse.json({ error: "Sign in to download this report." }, { status: 401 });
  }

  if (!isMongoConfigured()) {
    return NextResponse.json(
      { error: "PDF reporting requires the configured scan-history database." },
      { status: 503 },
    );
  }

  const { id } = await context.params;
  try {
    const report = await getScanReport(ownerId, id);
    if (!report) {
      return NextResponse.json({ error: "The saved assessment was not found." }, { status: 404 });
    }

    const pdfBytes = await generateScanReportPdf(report, { reportId: id });
    const body = pdfBytes.buffer.slice(
      pdfBytes.byteOffset,
      pdfBytes.byteOffset + pdfBytes.byteLength,
    ) as ArrayBuffer;

    return new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="${reportFilename(report.target, id)}"`,
        "Cache-Control": "private, no-store, max-age=0",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch (error) {
    console.error("Unable to generate the PDF assessment report", error);
    return NextResponse.json(
      { error: "The PDF report could not be generated. Try again." },
      { status: 500 },
    );
  }
}
