import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  outputFileTracingIncludes: {
    "/api/scans": ["./scanners/*.py", "./scanners/requirements.txt"],
  },
};

export default nextConfig;
