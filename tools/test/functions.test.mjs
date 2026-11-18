// Unit tests for the Pages Functions (login token, sessions, free-scan limit, VPN block).
// Run: node tools/test/functions.test.mjs
import { seal, unseal, verifyJwt, ipKey, b64url, hmac } from '../../functions/_shared/util.js';
import { vpnReason, resetVpnCache } from '../../functions/_shared/vpn.js';
import { onRequest as middleware } from '../../functions/_middleware.js';
import { onRequestGet as me } from '../../functions/api/me.js';
import { onRequestPost as consume } from '../../functions/api/scan/consume.js';
import { onRequestGet as login } from '../../functions/auth/login.js';
import { onRequestGet as done } from '../../functions/auth/done.js';
import { onRequestGet as callback } from '../../functions/auth/callback.js';
import { onRequestPost as logout } from '../../functions/auth/logout.js';
import { onRequestGet as linkFetch } from '../../functions/api/fetch.js';

let pass = 0, fail = 0;
const ok = (c, name, extra) => { if (c) pass++; else { fail++; console.log('FAIL', name, extra !== undefined ? JSON.stringify(extra) : ''); } };

function fakeKV() {
  const m = new Map();
  return {
    m,
    async get(k) { const e = m.get(k); if (!e) return null; if (e.exp && e.exp * 1000 < Date.now()) { m.delete(k); return null; } return e.v; },
    async put(k, v, o = {}) { m.set(k, { v, exp: o.expiration || (o.expirationTtl ? Math.floor(Date.now() / 1000) + o.expirationTtl : 0) }); },
  };
}
const SECRET = 'shared-secret-from-the-bot';
const baseEnv = () => ({ AUTH_SECRET: SECRET, SESSION_SECRET: 'session-secret', BOT_LOGIN_URL: 'https://bot.example.com/login', EZLARP_KV: fakeKV(), VPN_BLOCK: 'on' });
const req = (path, { ip = '203.0.113.7', cookie = '', method = 'GET', asn = 7922 } = {}) => {
  const r = new Request('https://ezlarp.pages.dev' + path, { method, headers: { 'CF-Connecting-IP': ip, cookie } });
  Object.defineProperty(r, 'cf', { value: { asn, asOrganization: 'Test ISP' } });
  return r;
};
async function jwt(payload, secret = SECRET, alg = 'HS256') {
  const enc = o => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const head = enc({ alg, typ: 'JWT' }), body = enc(payload);
  return `${head}.${body}.${b64url(await hmac(secret, head + '.' + body))}`;
}
const now = () => Math.floor(Date.now() / 1000);
const cookieOf = res => (res.headers.get('set-cookie') || '').split(';')[0];
// no network in tests: Tor list empty
globalThis.fetch = async () => new Response('', { status: 200 });

// ---- sealing
{
  const t = await seal('k', { a: 1, exp: now() + 60 });
  ok((await unseal('k', t)).a === 1, 'seal/unseal');
  ok(await unseal('other', t) === null, 'wrong key rejected');
  ok(await unseal('k', await seal('k', { a: 1, exp: now() - 1 })) === null, 'expired seal rejected');
  ok(await unseal('k', t.slice(0, -2) + 'xx') === null, 'tampered seal rejected');
}
// ---- bot JWT
{
  const good = { sub: '123456789012345678', name: 'jeff', aud: 'ezlarp', iat: now(), exp: now() + 120, jti: 'a1' };
  ok(!(await verifyJwt(SECRET, await jwt(good), 'ezlarp')).error, 'valid JWT');
  ok((await verifyJwt(SECRET, await jwt(good, 'nope'), 'ezlarp')).error === 'bad signature', 'bad signature');
  ok((await verifyJwt(SECRET, await jwt({ ...good, exp: now() - 5 }), 'ezlarp')).error === 'token expired', 'expired JWT');
  ok((await verifyJwt(SECRET, await jwt({ ...good, aud: 'x' }), 'ezlarp')).error === 'wrong audience', 'audience');
  ok((await verifyJwt(SECRET, await jwt(good, SECRET, 'none'), 'ezlarp')).error === 'wrong algorithm', 'alg none rejected');
  ok((await verifyJwt(SECRET, await jwt({ ...good, exp: now() + 3600 }), 'ezlarp')).error === 'token lives too long', 'long-lived JWT rejected');
  ok((await verifyJwt(SECRET, await jwt({ ...good, sub: 'abc' }), 'ezlarp')).error === 'no Discord user id', 'bad user id');
}
// ---- IPv6 /64
ok(ipKey('2001:db8:abcd:12:1:2:3:4') === '2001:db8:abcd:12::/64', 'ipv6 /64', ipKey('2001:db8:abcd:12:1:2:3:4'));
ok(ipKey('2001:db8::1') === '2001:db8:0:0::/64', 'ipv6 compressed', ipKey('2001:db8::1'));
ok(ipKey('198.51.100.4') === '198.51.100.4', 'ipv4 unchanged');

// ---- VPN
{
  const env = baseEnv();
  ok(await vpnReason(req('/api/me', { asn: 9009 }), env, '1.2.3.4'), 'M247 blocked');
  ok(await vpnReason(req('/api/me', { asn: 714 }), env, '1.2.3.4') === null, 'Apple / Private Relay allowed');
  ok(await vpnReason(req('/api/me', { asn: 13335 }), env, '1.2.3.4') === null, 'Cloudflare egress allowed');
  ok(await vpnReason(req('/api/me', { asn: 9009 }), { ...env, VPN_BLOCK: 'off' }, '1.2.3.4') === null, 'VPN_BLOCK=off');
  globalThis.fetch = async u => new Response(String(u).includes('torproject') ? '185.220.101.1\n185.220.101.2\n' : '', { status: 200 });
  resetVpnCache();
  const env2 = baseEnv();
  ok(/Tor/.test(await vpnReason(req('/api/me'), env2, '185.220.101.2') || ''), 'Tor exit blocked');
  ok(await vpnReason(req('/api/me'), env2, '203.0.113.9') === null, 'normal IP allowed');
  globalThis.fetch = async () => new Response('', { status: 200 });
  const blocked = await middleware({ request: req('/api/me', { asn: 9009 }), env, data: {}, next: async () => new Response('next') });
  ok(blocked.status === 403 && (await blocked.json()).reason === 'vpn', 'middleware blocks API on VPN');
  const blockedLogin = await middleware({ request: req('/auth/login', { asn: 16276 }), env, data: {}, next: async () => new Response('next') });
  ok(blockedLogin.status === 302 && /login=vpn/.test(blockedLogin.headers.get('location')), 'middleware sends VPN logins back');
  const passed = await middleware({ request: req('/api/me'), env, data: {}, next: async () => new Response('next') });
  ok(await passed.text() === 'next', 'middleware lets normal visitors through');
}

// ---- free scans + login flow
{
  const env = baseEnv();
  const data = { ip: '203.0.113.7' };
  let r = await (await me({ request: req('/api/me'), env, data })).json();
  ok(r.user === null && r.limit === 2 && r.left === 2 && r.login, 'me: anonymous with 2 scans', r);
  const c1 = await consume({ request: req('/api/scan/consume', { method: 'POST' }), env, data });
  const c2 = await consume({ request: req('/api/scan/consume', { method: 'POST' }), env, data });
  const c3 = await consume({ request: req('/api/scan/consume', { method: 'POST' }), env, data });
  ok(c1.status === 200 && (await c1.json()).left === 1, 'scan 1 ok');
  ok(c2.status === 200 && (await c2.json()).left === 0, 'scan 2 ok');
  ok(c3.status === 429 && (await c3.json()).reason === 'limit', 'scan 3 refused');
  ok(/^ezt=/.test(cookieOf(c1)), 'scan ticket cookie set');
  const other = await consume({ request: req('/api/scan/consume', { method: 'POST' }), env, data: { ip: '198.51.100.20' } });
  ok(other.status === 200, 'other IP has its own count');
  // the stored key is a hash, not the IP
  ok([...env.EZLARP_KV.m.keys()].every(k => !k.includes('203.0.113.7')), 'IPs are hashed in KV');

  // link downloads need a ticket
  const noTicket = await linkFetch({ request: req('/api/fetch?url=' + encodeURIComponent('https://example.com/a.jar')), env });
  ok(noTicket.status === 429, 'link download refused without a scan ticket');
  const withTicket = await linkFetch({ request: req('/api/fetch?url=' + encodeURIComponent('https://example.com/a.jar'), { cookie: cookieOf(c1) }), env });
  ok(withTicket.status === 403, 'ticket lets the download through to the host check', withTicket.status);

  // login
  const l = await login({ request: req('/auth/login'), env });
  const loc = new URL(l.headers.get('location'));
  ok(loc.origin === 'https://bot.example.com' && loc.searchParams.get('return') === 'https://ezlarp.pages.dev/auth/done', 'login hands over to the bot', loc.toString());
  const token = await jwt({ sub: '123456789012345678', name: 'jeff', avatar: 'a_0123456789abcdef0123456789abcdef', joined: true, aud: 'ezlarp', iat: now(), exp: now() + 120, jti: 'one-time' });
  const d = await done({ request: req('/auth/done?token=' + token), env });
  ok(d.status === 302 && d.headers.get('location') === '/?login=ok' && /^ezs=/.test(cookieOf(d)), 'login sets a session', d.headers.get('location'));
  const replay = await done({ request: req('/auth/done?token=' + token), env });
  ok(/already%20used/.test(replay.headers.get('location')), 'login token is single use');
  const bad = await done({ request: req('/auth/done?token=' + await jwt({ sub: '1234567', aud: 'ezlarp', iat: now(), exp: now() + 60 }, 'wrong')), env });
  ok(/login=error/.test(bad.headers.get('location')), 'forged token rejected');
  const errBack = await done({ request: req('/auth/done?error=access_denied'), env });
  ok(/login=error&why=access_denied/.test(errBack.headers.get('location')), 'bot error passed back');

  const session = cookieOf(d);
  r = await (await me({ request: req('/api/me', { cookie: session }), env, data })).json();
  ok(r.user && r.user.name === 'jeff' && r.user.avatar && r.limit === null, 'me: logged in', r);
  const lu = await consume({ request: req('/api/scan/consume', { method: 'POST', cookie: session }), env, data });
  ok(lu.status === 200 && (await lu.json()).limit === null, 'logged-in scans are unlimited');
  const out = await logout();
  ok(/^ezs=;/.test(cookieOf(out) + ';') || /Max-Age=0/.test(out.headers.get('set-cookie')), 'logout clears the session');
}

// ---- not set up yet: no limit, no login
{
  const env = { EZLARP_KV: fakeKV() };
  const r = await (await me({ request: req('/api/me'), env, data: { ip: '1.1.1.1' } })).json();
  ok(r.login === false && r.limit === null, 'without secrets: no login, no limit', r);
  for (let i = 0; i < 4; i++) ok((await consume({ request: req('/api/scan/consume', { method: 'POST' }), env, data: { ip: '1.1.1.1' } })).status === 200, 'unlimited until set up');
  const l = await login({ request: req('/auth/login'), env });
  ok(/login=off/.test(l.headers.get('location')), 'login says not set up');
  const env2 = { ...baseEnv(), EZLARP_KV: undefined };
  const r2 = await (await me({ request: req('/api/me'), env: env2, data: { ip: '1.1.1.1' } })).json();
  ok(r2.limit === null && r2.login === true, 'no KV bound: login works, no limit', r2);
}

// ---- built-in Discord login (no bot web server)
{
  const env = { SESSION_SECRET: 'session-secret', DISCORD_CLIENT_ID: '111', DISCORD_CLIENT_SECRET: 'cs', DISCORD_BOT_TOKEN: 'bt',
    DISCORD_GUILD_ID: '999', DISCORD_ROLE_ID: '555', EZLARP_KV: fakeKV() };
  const r = await (await me({ request: req('/api/me'), env, data: { ip: '198.51.100.9' } })).json();
  ok(r.login === true && r.limit === 2, 'builtin: login on, limit on', r);
  const l = await login({ request: req('/auth/login'), env });
  const loc = new URL(l.headers.get('location'));
  ok(loc.origin === 'https://discord.com' && loc.searchParams.get('scope') === 'identify guilds.join'
    && loc.searchParams.get('redirect_uri') === 'https://ezlarp.pages.dev/auth/callback' && loc.searchParams.get('client_id') === '111', 'builtin: login goes to Discord', loc.toString());
  const stateCookie = (l.headers.get('set-cookie') || '').split(';')[0];
  ok(/^ezst=/.test(stateCookie) && /Path=\/auth/.test(l.headers.get('set-cookie')), 'builtin: state cookie set');
  const state = loc.searchParams.get('state');

  const calls = [];
  let joinStatus = 201;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u, o = {}) => {
    u = String(u); calls.push({ u, o });
    if (u.endsWith('/oauth2/token')) return o.body.get('code') === 'good' ? Response.json({ access_token: 'at' }) : new Response('bad', { status: 400 });
    if (u.endsWith('/users/@me')) return Response.json({ id: '123456789012345678', username: 'jeff', global_name: 'Jeff', avatar: 'a_0123456789abcdef0123456789abcdef' });
    if (/\/guilds\/999\/members\//.test(u)) return new Response(joinStatus === 201 ? '{}' : null, { status: joinStatus });
    return new Response('', { status: 200 });
  };
  const c = await callback({ request: req(`/auth/callback?code=good&state=${state}`, { cookie: stateCookie }), env });
  const setc = c.headers.get('set-cookie') || '';
  ok(c.headers.get('location') === '/?login=ok' && /ezs=/.test(setc) && /ezst=;/.test(setc), 'builtin: callback logs in and clears state', [c.headers.get('location'), setc]);
  const join = calls.find(x => /members/.test(x.u));
  ok(join && join.o.method === 'PUT' && join.o.headers.authorization === 'Bot bt' && JSON.parse(join.o.body).roles[0] === '555'
    && JSON.parse(join.o.body).access_token === 'at', 'builtin: adds user to the server with the bot token');
  const sess = decodeURIComponent(setc.match(/ezs=([^;]+)/)[1]);
  const u = await unseal('session-secret', sess);
  ok(u.id === '123456789012345678' && u.name === 'Jeff' && u.avatar === 'a_0123456789abcdef0123456789abcdef', 'builtin: session has the Discord user', u);
  const m = await (await me({ request: req('/api/me', { cookie: 'ezs=' + encodeURIComponent(sess) }), env, data: { ip: '198.51.100.9' } })).json();
  ok(m.user && m.user.name === 'Jeff' && m.limit === null, 'builtin: logged in means no limit', m);

  joinStatus = 403;
  const c2 = await callback({ request: req(`/auth/callback?code=good&state=${state}`, { cookie: stateCookie }), env });
  ok(c2.headers.get('location') === '/?login=ok&joined=0', 'builtin: banned/failed join still logs in, says so');
  const c3 = await callback({ request: req(`/auth/callback?code=good&state=wrong`, { cookie: stateCookie }), env });
  ok(/login=error/.test(c3.headers.get('location')) && !/ezs=/.test(c3.headers.get('set-cookie') || ''), 'builtin: wrong state rejected');
  const c4 = await callback({ request: req(`/auth/callback?code=good&state=${state}`), env });
  ok(/login=error/.test(c4.headers.get('location')), 'builtin: missing state cookie rejected');
  const c5 = await callback({ request: req(`/auth/callback?code=bad&state=${state}`, { cookie: stateCookie }), env });
  ok(/login=error/.test(c5.headers.get('location')), 'builtin: bad code rejected');
  const c6 = await callback({ request: req(`/auth/callback?error=access_denied&state=${state}`, { cookie: stateCookie }), env });
  ok(/cancelled/.test(decodeURIComponent(c6.headers.get('location'))), 'builtin: cancel handled');
  const oldState = await seal('session-secret', { state, exp: now() - 1 });
  const c7 = await callback({ request: req(`/auth/callback?code=good&state=${state}`, { cookie: 'ezst=' + encodeURIComponent(oldState) }), env });
  ok(/login=error/.test(c7.headers.get('location')), 'builtin: expired state rejected');
  globalThis.fetch = realFetch;

  // bot mode wins when both are set; /auth/callback is off then, /auth/done off in builtin mode
  const both = { ...env, AUTH_SECRET: SECRET, BOT_LOGIN_URL: 'https://bot.example.com/login' };
  ok(new URL((await login({ request: req('/auth/login'), env: both })).headers.get('location')).origin === 'https://bot.example.com', 'bot mode wins when both set');
  ok(/login=off/.test((await callback({ request: req('/auth/callback?code=good'), env: both })).headers.get('location')), 'callback off in bot mode');
  ok(/login=off/.test((await done({ request: req('/auth/done?token=x'), env })).headers.get('location')), 'done off in builtin mode');
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
