import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("CSP script hash in vercel.json and nginx.conf matches the inline theme script", () => {
  // Exact-match the single inline <script> block (no attributes) to hash its body.
  const html = read("../index.html");
  const start = html.indexOf("<script>") + "<script>".length;
  const script = html.slice(start, html.indexOf("</script>", start));
  const hash = `sha256-${createHash("sha256").update(script).digest("base64")}`;
  assert.ok(read("../vercel.json").includes(`'${hash}'`), "vercel.json CSP must contain the current inline-script hash");
  assert.ok(read("../deploy/nginx.conf").includes(`'${hash}'`), "nginx.conf CSP must contain the current inline-script hash");
});

test("CSP never allows unsafe-inline scripts", () => {
  for (const file of ["../vercel.json", "../deploy/nginx.conf"]) {
    assert.doesNotMatch(read(file), /script-src[^;]*'unsafe-inline'/);
  }
});
