// POST /api/scan/consume: called before every scan. Logged-in users are unlimited;
// everyone else gets ANON_SCAN_LIMIT scans per ANON_WINDOW_HOURS.
// Also sets a short-lived ticket cookie that /api/fetch (link downloads) checks.
import { json, config, currentUser, seal, setCookie, TICKET_COOKIE } from '../../_shared/util.js';
import { useScan } from '../../_shared/quota.js';

async function ticket(env) {
  if (!env.SESSION_SECRET) return [];
  const t = await seal(env.SESSION_SECRET, { t: 1, exp: Math.floor(Date.now() / 1000) + 900 });
  return [['set-cookie', setCookie(TICKET_COOKIE, t, 900)]];
}

export async function onRequestPost({ request, env, data }) {
  const cfg = config(env);
  const user = await currentUser(request, env);
  if (user || !cfg.enforce) return json({ ok: true, left: null, limit: null }, 200, Object.fromEntries(await ticket(env)));
  const r = await useScan(env, cfg, data.ip);
  if (!r.ok) {
    return json({ ok: false, reason: 'limit', left: 0, limit: cfg.limit, reset: r.reset,
      error: `You've used your ${cfg.limit} free scans. Log in with Discord to keep scanning.` }, 429);
  }
  return json({ ok: true, left: r.left, limit: cfg.limit, reset: r.reset }, 200, Object.fromEntries(await ticket(env)));
}
