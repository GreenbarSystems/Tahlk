// Bounded-concurrency async map.
//
// Runs `fn` over `items` with at most `limit` in flight at once, preserving
// input order in the results. Used by the record-integrity sweeps
// (historyChain.js / auditLog.js), which otherwise `await` one Tauri IPC call
// per encounter strictly sequentially — turning a whole-database check into N
// serial round-trips (audit perf finding #12). A bounded pool keeps the total
// in-flight work sane (we are not trying to open thousands of connections at
// once) while collapsing wall-clock from sum-of-latencies to
// ceil(N/limit)*latency.
export async function mapLimit(items, limit, fn) {
  const list = Array.isArray(items) ? items : [...items];
  const results = new Array(list.length);
  let next = 0;

  async function worker() {
    while (next < list.length) {
      const idx = next++;
      results[idx] = await fn(list[idx], idx);
    }
  }

  const workers = Math.max(1, Math.min(limit, list.length));
  await Promise.all(Array.from({ length: workers }, worker));
  return results;
}
