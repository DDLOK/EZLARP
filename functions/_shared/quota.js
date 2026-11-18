// Free scans for visitors who aren't logged in, counted per (salted, hashed) IP in KV.
import { sha256hex, ipKey } from './util.js';

async function keyFor(env, ip) {
  return 'q:' + await sha256hex((env.IP_SALT || env.SESSION_SECRET || 'ezlarp') + '|' + ipKey(ip));
}

export async function readQuota(env, cfg, ip) {
  const now = Math.floor(Date.now() / 1000);
  const raw = await env.EZLARP_KV.get(await keyFor(env, ip));
  let q = null;
  try { q = raw ? JSON.parse(raw) : null; } catch (e) { q = null; }
  if (!q || q.reset <= now) q = { n: 0, reset: now + cfg.windowSeconds };
  return { used: q.n, left: Math.max(0, cfg.limit - q.n), reset: q.reset };
}

// returns { ok, left, reset }
export async function useScan(env, cfg, ip) {
  const now = Math.floor(Date.now() / 1000);
  const key = await keyFor(env, ip);
  const raw = await env.EZLARP_KV.get(key);
  let q = null;
  try { q = raw ? JSON.parse(raw) : null; } catch (e) { q = null; }
  if (!q || q.reset <= now) q = { n: 0, reset: now + cfg.windowSeconds };
  if (q.n >= cfg.limit) return { ok: false, left: 0, reset: q.reset };
  q.n++;
  // KV needs an expiry at least 60 s away
  await env.EZLARP_KV.put(key, JSON.stringify(q), { expiration: Math.max(q.reset, now + 61) });
  return { ok: true, left: Math.max(0, cfg.limit - q.n), reset: q.reset };
}
