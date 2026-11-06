import { randomBytes, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

const FRONTEND_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ROOT_DIR = path.resolve(FRONTEND_DIR, "..");
const BACKEND_DIR = path.join(ROOT_DIR, "backend");
const PYTHON = process.platform === "win32"
  ? path.join(BACKEND_DIR, ".venv", "Scripts", "python.exe")
  : path.join(BACKEND_DIR, ".venv", "bin", "python");
const VITE = path.join(FRONTEND_DIR, "node_modules", "vite", "bin", "vite.js");
const DEMO_PROJECT_PATH = "backend/app/api/docs/security-demo";

let apiProcess;
let frontendProcess;
let tempDirectory;
let apiUrl;
let frontendUrl;
let username;
let password;

function availablePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function startProcess(command, args, options) {
  return spawn(command, args, {
    ...options,
    stdio: "ignore",
    windowsHide: true,
  });
}

async function waitFor(url, child) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error("An E2E service exited before becoming ready.");
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // The service may still be starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("An E2E service did not become ready in time.");
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  const stopped = await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(() => resolve(false), 5000)),
  ]);
  if (stopped === false) throw new Error("An isolated E2E service did not stop; its temporary database was preserved.");
}

async function removeTemporaryData(directory) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      await rm(directory, { recursive: true, force: true });
      return;
    } catch (error) {
      if (!["EBUSY", "EPERM"].includes(error.code) || attempt === 7) throw error;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}

test.beforeAll(async () => {
  const apiPort = await availablePort();
  let frontendPort = await availablePort();
  while (frontendPort === apiPort) frontendPort = await availablePort();
  tempDirectory = await mkdtemp(path.join(os.tmpdir(), "securcode-e2e-"));
  apiUrl = `http://127.0.0.1:${apiPort}`;
  frontendUrl = `http://127.0.0.1:${frontendPort}`;

  const bootstrapToken = randomBytes(48).toString("base64url");
  username = `e2e-${randomUUID()}`;
  password = randomBytes(32).toString("base64url");

  apiProcess = startProcess(PYTHON, [
    "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(apiPort),
  ], {
    cwd: BACKEND_DIR,
    env: {
      ...process.env,
      SECURCODE_ENV: "development",
      SECURCODE_DEMO_MODE: "false",
      SECURCODE_ALLOWED_ORIGINS: frontendUrl,
      SECURCODE_DATABASE_PATH: path.join(tempDirectory, "e2e.sqlite"),
      SECURCODE_BOOTSTRAP_TOKEN: bootstrapToken,
    },
  });

  frontendProcess = startProcess(process.execPath, [
    VITE, "--host", "127.0.0.1", "--port", String(frontendPort), "--strictPort",
  ], {
    cwd: FRONTEND_DIR,
    env: {
      ...process.env,
      VITE_API_BASE_URL: apiUrl,
    },
  });

  await waitFor(`${apiUrl}/status`, apiProcess);
  await waitFor(frontendUrl, frontendProcess);

  const bootstrap = await fetch(`${apiUrl}/auth/bootstrap`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      password,
      bootstrap_token: bootstrapToken,
    }),
  });
  if (bootstrap.status !== 201) {
    throw new Error(`Isolated E2E administrator setup failed with HTTP ${bootstrap.status}.`);
  }
  const bootstrapSession = await bootstrap.json();
  const assignee = await fetch(`${apiUrl}/auth/users`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${bootstrapSession.access_token}`,
    },
    body: JSON.stringify({
      username: "admin",
      password: randomBytes(32).toString("base64url"),
      role: "developer",
    }),
  });
  if (assignee.status !== 201) {
    throw new Error(`Isolated E2E assignee setup failed with HTTP ${assignee.status}.`);
  }
});

test.afterAll(async () => {
  await stopProcess(frontendProcess);
  await stopProcess(apiProcess);
  if (tempDirectory) await removeTemporaryData(tempDirectory);
  password = undefined;
  username = undefined;
});

test("administrator login, project registration, scan, findings, and report export", async ({ page }) => {
  await page.goto(frontendUrl);
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForTimeout(1000);
  const authAlert = page.getByRole("alert");
  if (await authAlert.isVisible().catch(() => false)) {
    throw new Error(`Browser login was rejected: ${(await authAlert.innerText()).slice(0, 200)}`);
  }
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
  await expect(page.getByText(new RegExp(username))).toBeVisible();

  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await navigation.getByRole("button", { name: "Projects" }).click();
  const projectName = `E2E project ${randomUUID()}`;
  const repositoryUrl = "https://github.com/example/securcode-e2e";
  await expect(page.getByRole("note")).toHaveText(
    "Repository URLs are metadata only; remote repositories are not fetched or scanned.",
  );
  await page.getByLabel("Project name").fill(projectName);
  await page.getByLabel("Workspace path").fill(DEMO_PROJECT_PATH);
  await page.getByLabel("Repository URL").fill(repositoryUrl);
  await page.getByRole("button", { name: "Register project" }).click();

  const projectRow = page.getByRole("row", { name: new RegExp(projectName) });
  await expect(projectRow).toBeVisible();
  await projectRow.getByRole("button", { name: "Details" }).click();
  await expect(page.getByText(repositoryUrl)).toBeVisible();
  await projectRow.getByRole("button", { name: "Scan" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Project scan completed:" })).toBeVisible();

  await navigation.getByRole("button", { name: "Vulnerabilities" }).click();
  const findingRow = page.locator("main tbody tr").first();
  await expect(findingRow).toBeVisible();
  await findingRow.getByRole("button", { name: "Evidence and history" }).click();
  await page.getByLabel("Assignee").fill("unknown-assignee");
  await page.getByRole("button", { name: "Save assignment" }).click();
  await expect(page.getByRole("alert")).toHaveText(
    "Assignee must be an active SecurCode username.",
  );
  await expect(page.locator(".detail-panel")).toContainText("Unassigned");
  await page.getByLabel("Assignee").fill("admin");
  let assignmentRequests = 0;
  await page.route(/\/findings\/\d+\/\d+\/assignee$/, async (route) => {
    assignmentRequests += 1;
    await new Promise((resolve) => setTimeout(resolve, 250));
    await route.continue();
  });
  const assignmentButton = page.getByRole("button", { name: "Save assignment" });
  await assignmentButton.click();
  await expect(page.getByRole("button", { name: "Saving assignment…" })).toBeDisabled();
  await expect(page.getByRole("status").filter({ hasText: "Finding assigned to admin." })).toBeVisible();
  expect(assignmentRequests).toBe(1);
  await expect(page.locator(".detail-panel dl")).toContainText("admin");
  await expect(findingRow).toContainText("admin");

  await navigation.getByRole("button", { name: "Reports" }).click();
  await expect(page.getByText("Finding export")).toBeVisible();
  const reportResponsePromise = page.waitForResponse((response) =>
    response.url().endsWith("/reports/findings.csv"),
  );
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download findings CSV" }).click();
  const download = await downloadPromise;
  const reportResponse = await reportResponsePromise;
  expect(reportResponse.status()).toBe(200);
  expect(reportResponse.headers()["content-type"]).toContain("text/csv");
  expect(download.suggestedFilename()).toBe("securcode-findings.csv");
  expect(await download.failure()).toBeNull();
  expect(await readFile(await download.path(), "utf8")).toContain(
    "severity,status,rule_id,language",
  );

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in to SecurCode" })).toBeVisible();
});
