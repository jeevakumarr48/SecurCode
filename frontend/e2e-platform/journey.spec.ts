import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const PASSWORD = "Correct-Horse-Battery-42";
const FIXTURES = resolve(import.meta.dirname, "../../scanner-fixtures/projects");
const SHOTS = resolve(import.meta.dirname, "../../docs/screenshots");
const work = join(tmpdir(), `securcode-e2e-zips-${process.pid}`);
const python = process.env.E2E_PYTHON ?? (process.platform === "win32" ? "python" : "python3");

function zipFixture(name: string): string {
  mkdirSync(work, { recursive: true });
  const target = join(work, `${name}.zip`);
  execFileSync(python, ["-c", [
    "import sys, zipfile, pathlib",
    "root = pathlib.Path(sys.argv[1]); out = zipfile.ZipFile(sys.argv[2], 'w', zipfile.ZIP_DEFLATED)",
    "[out.write(p, 'repo/' + p.relative_to(root).as_posix()) for p in sorted(root.rglob('*')) if p.is_file()]",
    "out.close()"].join("\n"), join(FIXTURES, name), target]);
  return target;
}

async function register(page: Page, email: string, name: string) {
  await page.goto("/register");
  await page.getByLabel("Name").fill(name);
  await page.getByLabel("Work email").fill(email);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create account" }).click();
}

async function shot(page: Page, name: string) {
  mkdirSync(SHOTS, { recursive: true });
  await page.waitForLoadState("networkidle");
  await page.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: false });
}

async function waitForScan(page: Page, status: RegExp) {
  await expect(page.getByText(status).first()).toBeVisible({ timeout: 90_000 });
}

test("register → org → invite → project → scan → triage → remediate → rescan → verify → export, with tenant isolation", async ({ browser }) => {
  const stamp = Date.now();
  const ownerEmail = `owner${stamp}@example.com`;
  const devEmail = `dev${stamp}@example.com`;
  const owner = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();

  await owner.goto("/");
  await expect(owner.getByRole("heading", { level: 1 })).toContainText("Find, prioritise and verify");
  await shot(owner, "01-landing");

  // Register and create an organization.
  await register(owner, ownerEmail, "Avery Owner");
  await expect(owner.getByRole("heading", { name: "Set up your organization" })).toBeVisible();
  await owner.getByLabel("Organization name").fill("Northwind Security");
  await owner.getByRole("button", { name: "Create organization" }).click();

  // Create a project (inline form opens via ?new=1 from onboarding).
  await expect(owner.getByRole("heading", { name: "New project" })).toBeVisible();
  await owner.getByLabel("Name", { exact: true }).fill("Payments API");
  await owner.getByRole("button", { name: "Create project" }).click();
  await expect(owner.getByRole("heading", { name: "Payments API" })).toBeVisible();
  const orgId = owner.url().split("/orgs/")[1].split("/")[0];

  // Invite a developer (no SMTP configured → single-use link shown once).
  await owner.goto(`/orgs/${orgId}/team`);
  await owner.getByLabel("Invite by email").fill(devEmail);
  await owner.getByLabel("Role").selectOption("developer");
  await owner.getByRole("button", { name: "Send invitation" }).click();
  const linkText = await owner.locator("code", { hasText: "/invitations/accept?token=" }).innerText();
  const inviteUrl = new URL(linkText.trim());

  // Upload the vulnerable archive and run the scan through the background worker.
  await owner.goto(`/orgs/${orgId}/projects`);
  await owner.getByRole("link", { name: "Payments API" }).click();
  await owner.getByLabel("Source archive").setInputFiles(zipFixture("demo-vulnerable-app"));
  await owner.getByRole("button", { name: "Start scan" }).click();
  await waitForScan(owner, /^completed$/);
  await expect(owner.getByText("Findings in this scan (9)")).toBeVisible();
  await shot(owner, "03-scan-results");

  // The developer accepts the invitation in a separate browser session.
  const dev = await (await browser.newContext({ viewport: { width: 1280, height: 860 } })).newPage();
  await dev.goto(inviteUrl.pathname + inviteUrl.search);
  await expect(dev.getByText(/invited to join/)).toBeVisible();
  await dev.getByRole("link", { name: /Create an account for/ }).click();
  await dev.getByLabel("Name").fill("Devon Developer");
  await dev.getByLabel("Password").fill(PASSWORD);
  await dev.getByRole("button", { name: "Create account" }).click();
  await dev.getByRole("button", { name: "Accept and join" }).click();
  await expect(dev.getByRole("heading", { name: "Security overview" })).toBeVisible();

  // Owner triages and assigns the SQL injection finding to the developer.
  await owner.goto(`/orgs/${orgId}/findings`);
  await expect(owner.getByRole("link", { name: "Tainted SQL execution" })).toBeVisible();
  await shot(owner, "04-vulnerabilities");
  await owner.getByRole("link", { name: "Tainted SQL execution" }).click();
  await owner.getByLabel("Assignee").selectOption({ label: `${devEmail} (developer)` });
  await expect(owner.getByText("Saved.")).toBeVisible();
  await owner.getByRole("button", { name: "Triaged" }).click();
  await expect(owner.getByText("triaged", { exact: true }).first()).toBeVisible();
  await shot(owner, "05-finding-detail");
  const findingUrl = owner.url();

  // Developer sees it under "My remediation" and moves it through remediation.
  await dev.goto(`/orgs/${orgId}/remediation`);
  await dev.getByRole("link", { name: "Tainted SQL execution" }).click();
  await expect(dev.getByRole("button", { name: "Accepted risk" })).toHaveCount(0);
  await dev.getByRole("button", { name: "In progress" }).click();
  await expect(dev.getByRole("button", { name: "Fixed" })).toBeVisible();
  await dev.getByLabel("Add a comment").fill("Switched to parameterised queries in PR #42.");
  await dev.getByRole("button", { name: "Comment" }).click();
  await dev.getByRole("button", { name: "Fixed" }).click();
  await expect(dev.getByText("fixed", { exact: true }).first()).toBeVisible();

  // Rescan with the fixed code: the fix is verified only by the rescan.
  await owner.goto(`/orgs/${orgId}/projects`);
  await owner.getByRole("link", { name: "Payments API" }).click();
  await owner.getByLabel("Source archive").setInputFiles(zipFixture("demo-vulnerable-app-fixed"));
  await owner.getByRole("button", { name: "Start scan" }).click();
  await waitForScan(owner, /^completed$/);
  await expect(owner.getByText("Verified fixed", { exact: true })).toBeVisible();
  const rescanUrl = owner.url();
  await owner.goto(findingUrl);
  await expect(owner.getByText("resolved", { exact: true }).first()).toBeVisible();
  await expect(owner.getByText(/Verified fixed by/)).toBeVisible();

  // Compare the two scans.
  await owner.goto(rescanUrl);
  await owner.getByLabel("Scan", { exact: true }).selectOption({ index: 1 });
  await owner.getByRole("button", { name: "Compare" }).click();
  await expect(owner.getByText(/Equivalent scans/)).toBeVisible();
  await expect(owner.getByRole("heading", { name: "Resolved (7)" })).toBeVisible();
  await shot(owner, "06-scan-comparison");

  // Export a CSV report.
  await owner.goto(`/orgs/${orgId}/findings`);
  const [download] = await Promise.all([owner.waitForEvent("download"), owner.getByRole("button", { name: "Export CSV" }).click()]);
  expect(download.suggestedFilename()).toMatch(/securcode-findings-.*\.csv/);

  await owner.goto(`/orgs/${orgId}/dashboard`);
  await expect(owner.getByText("Project posture")).toBeVisible();
  await shot(owner, "02-dashboard");

  // Tenant isolation: an unrelated user cannot see or fetch Northwind's data.
  const outsider = await (await browser.newContext()).newPage();
  await register(outsider, `outsider${stamp}@example.com`, "Olive Outsider");
  await outsider.getByLabel("Organization name").fill("Other Corp");
  await outsider.getByRole("button", { name: "Create organization" }).click();
  await expect(outsider.getByRole("heading", { name: "New project" })).toBeVisible();
  await outsider.goto(`/orgs/${orgId}/findings`);
  await expect(outsider.getByRole("heading", { name: "Organization not found" })).toBeVisible();
  const status = await outsider.evaluate(async (id) => (await fetch(`/api/v1/organizations/${id}/findings`, { credentials: "include" })).status, orgId);
  expect(status).toBe(404);
});
