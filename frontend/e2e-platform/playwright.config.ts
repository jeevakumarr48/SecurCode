import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Browser end-to-end test of the multi-tenant platform against the real
 * FastAPI backend, the real background worker and a throwaway SQLite DB.
 */
const python = process.env.E2E_PYTHON ?? (process.platform === "win32" ? "python" : "python3");
const dataDir = process.env.E2E_DATA_DIR ?? join(tmpdir(), `securcode-e2e-${process.pid}`);
const chrome = ["/usr/bin/google-chrome", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"].find((p) => existsSync(p));
const backendEnv = {
  SECURCODE_ENV: "development",
  SECURCODE_DATABASE_PATH: join(dataDir, "legacy.db"),
  SECURCODE_DATABASE_URL: `sqlite:///${join(dataDir, "platform.db").replaceAll("\\", "/")}`,
  SECURCODE_ENCRYPTION_KEY: "JnuHkB6hUWJXcSrDHfRLS3TQsGyuPl1NErjsSxD7Npo=",
  SECURCODE_DISABLE_WATCHER: "true",
  SECURCODE_PUBLIC_APP_URL: "http://127.0.0.1:5173",
};

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts/,
  workers: 1,
  timeout: 180_000,
  expect: { timeout: 30_000 },
  reporter: [["list"], ["json", { outputFile: "../test-results/platform-e2e.json" }]],
  use: {
    baseURL: "http://127.0.0.1:5173",
    browserName: "chromium",
    launchOptions: chrome ? { executablePath: chrome } : {},
    headless: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      // Migrate, then run the worker and API side by side.
      command: `${python} -c "import os;os.makedirs(r'${dataDir}',exist_ok=True)" && ${python} -m app.v1.cli migrate && (${python} -m app.v1.worker & ${python} -m uvicorn app.main:app --host 127.0.0.1 --port 8000)`,
      cwd: "../../backend",
      url: "http://127.0.0.1:8000/api/v1/health/ready",
      env: backendEnv,
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: "npx vite --host 127.0.0.1 --port 5173 --strictPort",
      cwd: "..",
      url: "http://127.0.0.1:5173",
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
});
