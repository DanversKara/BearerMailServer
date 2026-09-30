// Failed-login throttle for the IMAP port, which is reachable from the internet.
// After MAX failures from one address inside the window, that address is refused for BLOCK_MS.
// Set IMAP_MAX_AUTH_FAILURES=0 to turn it off.
const MAX = Number(process.env.IMAP_MAX_AUTH_FAILURES ?? 10);
const WINDOW_MS = Number(process.env.IMAP_AUTH_WINDOW_SECONDS ?? 600) * 1000;
const BLOCK_MS = Number(process.env.IMAP_AUTH_BLOCK_SECONDS ?? 900) * 1000;
const MAX_TRACKED = 20000;

const state = new Map(); // address -> { fails: [timestamps], blockedUntil }

function entry(addr) {
  let e = state.get(addr);
  if (!e) { e = { fails: [], blockedUntil: 0 }; state.set(addr, e); }
  return e;
}

function isBlocked(addr, now = Date.now()) {
  if (!MAX) return false;
  const e = state.get(addr);
  return !!e && e.blockedUntil > now;
}

function recordFailure(addr, now = Date.now()) {
  if (!MAX) return false;
  if (state.size > MAX_TRACKED) prune(now);
  const e = entry(addr);
  e.fails = e.fails.filter((t) => now - t < WINDOW_MS);
  e.fails.push(now);
  if (e.fails.length >= MAX) { e.blockedUntil = now + BLOCK_MS; e.fails = []; return true; }
  return false;
}

function recordSuccess(addr) { state.delete(addr); }

function prune(now = Date.now()) {
  for (const [k, e] of state) {
    if (e.blockedUntil <= now && e.fails.every((t) => now - t >= WINDOW_MS)) state.delete(k);
  }
}

setInterval(() => prune(), 60 * 1000).unref();

module.exports = { isBlocked, recordFailure, recordSuccess, _state: state };
