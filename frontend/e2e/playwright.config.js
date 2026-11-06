import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";

const chromePath = process.platform === "win32"
  ? [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  ].find((candidate) => existsSync(candidate))
  : undefined;

export default defineConfig({
  testDir: ".",
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: "list",
  use: {
    browserName: "chromium",
    launchOptions: chromePath ? { executablePath: chromePath } : {},
    headless: true,
    trace: "off",
    video: "off",
    screenshot: "off",
  },
});
