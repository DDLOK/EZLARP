// GET /auth/login: hand over to the Discord bot's login page.
// The bot sends the visitor back to /auth/done?token=<JWT> when they've logged in.
import { config } from '../_shared/util.js';

export async function onRequestGet({ request, env }) {
  const cfg = config(env);
  const here = new URL(request.url);
  if (!cfg.loginReady) return Response.redirect(new URL('/?login=off', here).toString(), 302);
  const target = new URL(env.BOT_LOGIN_URL);
  target.searchParams.set('return', new URL('/auth/done', env.PUBLIC_ORIGIN || here.origin).toString());
  return Response.redirect(target.toString(), 302);
}
