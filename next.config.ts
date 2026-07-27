import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  outputFileTracingIncludes: {
    "/api/scans": ["./scanners/**/*"],
  },
};

export default nextConfig;
