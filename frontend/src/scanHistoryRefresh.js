export async function refreshHistoryAfterFailedScan({
  loadHistory,
  onHistory,
  onState,
}) {
  onState("refreshing");
  try {
    const history = await loadHistory();
    onHistory(history);
    onState("refreshed");
    return true;
  } catch {
    onState("stale");
    return false;
  }
}
