import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";

import { authOptions } from "@/src/lib/auth-options";
import { isMongoConfigured } from "@/src/lib/mongodb";
import { getScanAnalytics } from "@/src/lib/scan-repository";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const session = await getServerSession(authOptions);
  const ownerId = session?.user?.id;
  if (!ownerId) {
    return NextResponse.json(
      { available: false, message: "Sign in to view your scan analytics." },
      { status: 401 },
    );
  }

  if (!isMongoConfigured()) {
    return NextResponse.json({
      available: false,
      message: "Set MONGODB_URI in .env.local to enable scan analytics.",
    });
  }

  try {
    return NextResponse.json({ available: true, analytics: await getScanAnalytics(ownerId) });
  } catch (error) {
    console.error("Unable to load scan analytics", error);
    return NextResponse.json(
      { available: false, message: "Scan analytics are temporarily unavailable." },
      { status: 503 },
    );
  }
}
