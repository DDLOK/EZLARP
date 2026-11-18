// GET /api/me: who is logged in, and how many free scans are left
import { json, config, currentUser } from '../_shared/util.js';
import { readQuota } from '../_shared/quota.js';

export async function onRequestGet({ request, env, data }) {
  const cfg = config(env);
  const user = await currentUser(request, env);
  const out = {
    user: user ? { id: user.id, name: user.name, avatar: user.avatar || null } : null,
    login: cfg.loginReady,
    limit: cfg.enforce && !user ? cfg.limit : null,
    left: null,
    reset: null,
    windowHours: cfg.windowHours,
  };
  if (cfg.enforce && !user) {
    const q = await readQuota(env, cfg, data.ip);
    out.left = q.left;
    out.reset = q.reset;
  }
  return json(out);
}
