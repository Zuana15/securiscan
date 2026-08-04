import type { Metadata } from "next";
import { headers } from "next/headers";
import { getCurrentUser } from "@/src/lib/current-user";
import "./globals.css";

import SiteShell from "./components/site-shell";

const siteMetadata = {
  title: "SecuriScan | Vulnerability assessments",
  description: "Authorized web application vulnerability assessments and findings.",
};

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host");
  const protocol = requestHeaders.get("x-forwarded-proto") ?? "https";
  const safeHost = host && /^[a-z0-9.-]+(?::\d+)?$/i.test(host) ? host : undefined;

  return {
    ...siteMetadata,
    metadataBase: safeHost ? new URL(`${protocol}://${safeHost}`) : undefined,
    openGraph: {
      ...siteMetadata,
      type: "website",
      images: "/og.png",
    },
    twitter: {
      card: "summary_large_image",
      title: siteMetadata.title,
      description: siteMetadata.description,
      images: "/og.png",
    },
  };
}

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const user = await getCurrentUser();

  return (
    <html lang="en">
      <body><SiteShell initialUser={user}>{children}</SiteShell></body>
    </html>
  );
}
