// GET /auth/callback?code=&state= (builtin mode): finish Discord login, add the user to the
// Discord server with the bot's token, start a session.
import { config, unseal, cookies } from '../_shared/util.js';
import { backHome, startSession } from '../_shared/session.js';
import { STATE_COOKIE } from './login.js';

const API = 'https://discord.com/api/v10';
const CLEAR_STATE = `${STATE_COOKIE}=; Path=/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

export async function onRequestGet({ request, env }) {
  const cfg = config(env);
  const url = new URL(request.url);
  const fail = (why) => backHome('login=error&why=' + encodeURIComponent(why), { 'set-cookie': CLEAR_STATE });
  if (cfg.loginMode !== 'builtin') return backHome('login=off');

  const err = url.searchParams.get('error');
  if (err) return fail(err === 'access_denied' ? 'you cancelled on Discord' : err.slice(0, 80));
  const saved = await unseal(env.SESSION_SECRET, cookies(request)[STATE_COOKIE]);
  const state = url.searchParams.get('state'), code = url.searchParams.get('code');
  if (!saved || !state || saved.state !== state) return fail('login timed out, try again');
  if (!code) return fail('Discord sent no code');

  const origin = env.PUBLIC_ORIGIN || url.origin;
  try {
    const tr = await fetch(API + '/oauth2/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: new URL('/auth/callback', origin).toString(),
      }),
    });
    if (!tr.ok) { console.log('discord token exchange', tr.status, await tr.text()); return fail('Discord login failed'); }
    const accessToken = (await tr.json()).access_token;
    if (!accessToken) return fail('Discord login failed');

    const ur = await fetch(API + '/users/@me', { headers: { authorization: 'Bearer ' + accessToken } });
    if (!ur.ok) return fail('could not read your Discord account');
    const u = await ur.json();
    if (!/^\d{5,25}$/.test(String(u.id || ''))) return fail('could not read your Discord account');

    // add to the server; 201 = joined, 204 = already a member
    const body = { access_token: accessToken };
    if (env.DISCORD_ROLE_ID) body.roles = [env.DISCORD_ROLE_ID];
    const jr = await fetch(`${API}/guilds/${env.DISCORD_GUILD_ID}/members/${u.id}`, {
      method: 'PUT',
      headers: { authorization: 'Bot ' + env.DISCORD_BOT_TOKEN, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const joined = jr.status === 201 || jr.status === 204;
    if (!joined) console.log('discord guild join', jr.status, await jr.text());

    return startSession(env, cfg, { id: u.id, name: u.global_name || u.username, avatar: u.avatar, joined }, [CLEAR_STATE]);
  } catch (e) {
    console.log('discord login error', e && e.message);
    return fail('could not reach Discord, try again');
  }
}
