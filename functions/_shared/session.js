// Start a logged-in session and send the visitor home.
import { seal, setCookie, SESSION_COOKIE } from './util.js';

export function backHome(query, extraHeaders = {}) {
  const h = new Headers({ location: '/?' + query, 'cache-control': 'no-store' });
  for (const [k, v] of Object.entries(extraHeaders)) for (const one of [].concat(v)) h.append(k, one);
  return new Response(null, { status: 302, headers: h });
}

export async function startSession(env, cfg, user, extraCookies = []) {
  const exp = Math.floor(Date.now() / 1000) + cfg.sessionDays * 86400;
  const session = await seal(env.SESSION_SECRET, {
    id: String(user.id),
    name: String(user.name || 'Discord user').slice(0, 64),
    avatar: user.avatar && /^(a_)?[0-9a-f]{32}$/.test(user.avatar) ? user.avatar : null,
    exp,
  });
  return backHome('login=ok' + (user.joined === false ? '&joined=0' : ''), {
    'set-cookie': [setCookie(SESSION_COOKIE, session, cfg.sessionDays * 86400), ...extraCookies],
  });
}
