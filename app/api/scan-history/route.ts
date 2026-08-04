import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";

import { authOptions } from "@/src/lib/auth-options";
import { isMongoConfigured } from "@/src/lib/mongodb";
import { listScanHistory } from "@/src/lib/scan-repository";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const session = await getServerSession(authOptions);
  const ownerId = session?.user?.id;
  if (!ownerId) {
    return NextResponse.json(
      { available: false, message: "Sign in to view your scan history.", items: [] },
      { status: 401 },
    );
  }

  if (!isMongoConfigured()) {
    return NextResponse.json({
      available: false,
      message: "Set MONGODB_URI in .env.local to save and view scan history.",
      items: [],
    });
  }

  try {
    return NextResponse.json({ available: true, items: await listScanHistory(ownerId) });
  } catch (error) {
    console.error("Unable to load scan history", error);
    return NextResponse.json(
      { available: false, message: "Scan history is temporarily unavailable.", items: [] },
      { status: 503 },
    );
  }
}
