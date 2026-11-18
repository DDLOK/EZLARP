// GET /auth/login
//  bot mode:     hand over to the Discord bot's login page; it comes back to /auth/done?token=<JWT>.
//  builtin mode: go straight to Discord; it comes back to /auth/callback.
import { config, seal, b64url } from '../_shared/util.js';

export const STATE_COOKIE = 'ezst';

export async function onRequestGet({ request, env }) {
  const cfg = config(env);
  const here = new URL(request.url);
  const origin = env.PUBLIC_ORIGIN || here.origin;
  if (!cfg.loginReady) return Response.redirect(new URL('/?login=off', here).toString(), 302);
  if (cfg.loginMode === 'bot') {
    const target = new URL(env.BOT_LOGIN_URL);
    target.searchParams.set('return', new URL('/auth/done', origin).toString());
    return Response.redirect(target.toString(), 302);
  }
  const state = b64url(crypto.getRandomValues(new Uint8Array(24)));
  const sealed = await seal(env.SESSION_SECRET, { state, exp: Math.floor(Date.now() / 1000) + 600 });
  const target = new URL('https://discord.com/oauth2/authorize');
  target.searchParams.set('client_id', env.DISCORD_CLIENT_ID);
  target.searchParams.set('response_type', 'code');
  target.searchParams.set('scope', 'identify guilds.join');
  target.searchParams.set('redirect_uri', new URL('/auth/callback', origin).toString());
  target.searchParams.set('state', state);
  return new Response(null, {
    status: 302,
    headers: {
      location: target.toString(),
      'set-cookie': `${STATE_COOKIE}=${encodeURIComponent(sealed)}; Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
      'cache-control': 'no-store',
    },
  });
}
