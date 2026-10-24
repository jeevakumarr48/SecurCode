import assert from "node:assert/strict";
import test from "node:test";

import { refreshHistoryAfterFailedScan } from "../src/scanHistoryRefresh.js";

test("failed scan refreshes history and reports success", async () => {
  const states = [];
  let updatedHistory;

  const refreshed = await refreshHistoryAfterFailedScan({
    loadHistory: async () => ({ scans: [{ id: 7, status: "failed" }] }),
    onHistory: (history) => { updatedHistory = history; },
    onState: (state) => states.push(state),
  });

  assert.equal(refreshed, true);
  assert.deepEqual(states, ["refreshing", "refreshed"]);
  assert.deepEqual(updatedHistory, { scans: [{ id: 7, status: "failed" }] });
});

test("history refresh failure preserves stale state without throwing", async () => {
  const ui = {
    scanMessage: "The security scan failed.",
    historyState: "idle",
  };

  const refreshed = await refreshHistoryAfterFailedScan({
    loadHistory: async () => { throw new Error("history unavailable"); },
    onHistory: () => assert.fail("History must not update after a failed request"),
    onState: (state) => { ui.historyState = state; },
  });

  assert.equal(refreshed, false);
  assert.equal(ui.scanMessage, "The security scan failed.");
  assert.equal(ui.historyState, "stale");
});
