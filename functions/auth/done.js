// GET /auth/done?token=<JWT from the bot>: check it and start a session.
//
// Contract with the bot (HS256 JWT signed with the shared AUTH_SECRET):
//   { sub: "<discord user id>", name: "<display name>", avatar: "<avatar hash or null>",
//     joined: true|false, aud: "ezlarp", iat: <now>, exp: <now + 120>, jti: "<random id>" }
// The token is single use (its jti is remembered in KV until it expires).
import { config, verifyJwt, seal, setCookie, SESSION_COOKIE } from '../_shared/util.js';

export async function onRequestGet({ request, env }) {
  const cfg = config(env);
  const url = new URL(request.url);
  const back = (q) => new Response(null, { status: 302, headers: { location: '/?' + q, 'cache-control': 'no-store' } });
  if (!cfg.loginReady) return back('login=off');
  if (url.searchParams.get('error')) return back('login=error&why=' + encodeURIComponent(url.searchParams.get('error').slice(0, 80)));
  const v = await verifyJwt(env.AUTH_SECRET, url.searchParams.get('token'), env.AUTH_AUDIENCE || 'ezlarp');
  if (v.error) return back('login=error&why=' + encodeURIComponent(v.error));
  const p = v.payload;
  if (env.EZLARP_KV && p.jti) {
    const k = 'jti:' + String(p.jti).slice(0, 100);
    if (await env.EZLARP_KV.get(k)) return back('login=error&why=' + encodeURIComponent('that login link was already used'));
    await env.EZLARP_KV.put(k, '1', { expirationTtl: 900 });
  }
  const exp = Math.floor(Date.now() / 1000) + cfg.sessionDays * 86400;
  const session = await seal(env.SESSION_SECRET, {
    id: String(p.sub),
    name: String(p.name || 'Discord user').slice(0, 64),
    avatar: p.avatar && /^(a_)?[0-9a-f]{32}$/.test(p.avatar) ? p.avatar : null,
    exp,
  });
  return new Response(null, {
    status: 302,
    headers: {
      location: '/?login=ok' + (p.joined === false ? '&joined=0' : ''),
      'set-cookie': setCookie(SESSION_COOKIE, session, cfg.sessionDays * 86400),
      'cache-control': 'no-store',
    },
  });
}
