import { spawnSync } from "node:child_process";

const python = process.env.SECURISCAN_PYTHON?.trim() || (
  process.platform === "win32" ? ".venv\\Scripts\\python.exe" : ".venv/bin/python"
);
const result = spawnSync(
  python,
  ["-m", "unittest", "discover", "-s", "scanners", "-p", "test_*.py"],
  { stdio: "inherit", windowsHide: true },
);

if (result.error) {
  console.error(`Unable to run scanner-rule tests with ${python}: ${result.error.message}`);
  process.exitCode = 1;
} else {
  process.exitCode = result.status ?? 1;
}
