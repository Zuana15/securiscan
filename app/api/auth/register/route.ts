import { NextResponse } from "next/server";

import dbConnect, { isMongoConfigured } from "@/src/lib/mongodb";
import { hashPassword } from "@/src/lib/passwords";
import { canRegisterLocally, validateRegistration } from "@/src/lib/registration";
import User from "@/src/models/user";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  if (!canRegisterLocally()) {
    return NextResponse.json(
      { error: "Account registration is disabled. Ask an administrator to create your account." },
      { status: 403 },
    );
  }

  if (!isMongoConfigured()) {
    return NextResponse.json(
      { error: "Account registration needs MONGODB_URI in .env.local." },
      { status: 503 },
    );
  }

  let input;
  try {
    input = validateRegistration(await request.json());
  } catch {
    input = null;
  }

  if (!input) {
    return NextResponse.json(
      {
        error:
          "Use a name, a valid email address, and an 8-character password containing a letter and a number.",
      },
      { status: 400 },
    );
  }

  try {
    await dbConnect();
    const accountCount = await User.countDocuments();
    const user = await User.create({
      name: input.name,
      email: input.email,
      passwordHash: await hashPassword(input.password),
      role: accountCount === 0 ? "owner" : "analyst",
    });

    return NextResponse.json(
      { ok: true, email: user.email, message: "Account created. You can now sign in." },
      { status: 201 },
    );
  } catch (error) {
    if (typeof error === "object" && error && "code" in error && error.code === 11000) {
      return NextResponse.json(
        { error: "An account with that email address already exists." },
        { status: 409 },
      );
    }

    console.error("Account registration failed", error);

    if (
      error instanceof Error &&
      (error.name === "MongooseServerSelectionError" ||
        error.message.includes("Could not connect to any servers"))
    ) {
      return NextResponse.json(
        {
          error:
            "MongoDB Atlas is unreachable. Check the cluster status and add this PC's current public IP in Atlas Network Access, then try again.",
        },
        { status: 503 },
      );
    }

    return NextResponse.json({ error: "The account could not be created. Try again." }, { status: 503 });
  }
}
