// GET /auth/done?token=<JWT from the bot>: check it and start a session. Used when BOT_LOGIN_URL is set.
//
// Contract with the bot (HS256 JWT signed with the shared AUTH_SECRET):
//   { sub: "<discord user id>", name: "<display name>", avatar: "<avatar hash or null>",
//     joined: true|false, aud: "ezlarp", iat: <now>, exp: <now + 120>, jti: "<random id>" }
// The token is single use (its jti is remembered in KV until it expires).
import { config, verifyJwt } from '../_shared/util.js';
import { backHome, startSession } from '../_shared/session.js';

export async function onRequestGet({ request, env }) {
  const cfg = config(env);
  const url = new URL(request.url);
  if (cfg.loginMode !== 'bot') return backHome('login=off');
  if (url.searchParams.get('error')) return backHome('login=error&why=' + encodeURIComponent(url.searchParams.get('error').slice(0, 80)));
  const v = await verifyJwt(env.AUTH_SECRET, url.searchParams.get('token'), env.AUTH_AUDIENCE || 'ezlarp');
  if (v.error) return backHome('login=error&why=' + encodeURIComponent(v.error));
  const p = v.payload;
  if (env.EZLARP_KV && p.jti) {
    const k = 'jti:' + String(p.jti).slice(0, 100);
    if (await env.EZLARP_KV.get(k)) return backHome('login=error&why=' + encodeURIComponent('that login link was already used'));
    await env.EZLARP_KV.put(k, '1', { expirationTtl: 900 });
  }
  return startSession(env, cfg, { id: p.sub, name: p.name, avatar: p.avatar, joined: p.joined });
}
