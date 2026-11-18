// Shared helpers for the EZLARP Pages Functions (no dependencies, Web Crypto only).

const enc = new TextEncoder();

export function b64url(bytes) {
  let s = '';
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64url(t) {
  const s = atob(t.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((t.length + 3) % 4));
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}
const keyCache = new Map();
async function hmacKey(secret) {
  if (!keyCache.has(secret)) keyCache.set(secret, crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']));
  return keyCache.get(secret);
}
export async function hmac(secret, data) {
  return new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(data)));
}
// constant-time compare
export function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
export async function sha256hex(text) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(text)));
  return [...h].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---- our own signed values (session + scan ticket cookies): base64url(json).base64url(hmac)
export async function seal(secret, obj) {
  const body = b64url(enc.encode(JSON.stringify(obj)));
  return body + '.' + b64url(await hmac(secret, body));
}
export async function unseal(secret, token) {
  if (!secret || !token || typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  try {
    if (!same(unb64url(sig), await hmac(secret, body))) return null;
    const obj = JSON.parse(new TextDecoder().decode(unb64url(body)));
    if (obj.exp && obj.exp < Math.floor(Date.now() / 1000)) return null;
    return obj;
  } catch (e) {
    return null;
  }
}

// ---- the bot's login token: a JWT (HS256) signed with AUTH_SECRET
export async function verifyJwt(secret, token, audience) {
  if (!secret || !token) return { error: 'missing token' };
  const parts = String(token).split('.');
  if (parts.length !== 3) return { error: 'malformed token' };
  let header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(unb64url(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(unb64url(parts[1])));
  } catch (e) {
    return { error: 'malformed token' };
  }
  if (header.alg !== 'HS256') return { error: 'wrong algorithm' };
  if (!same(unb64url(parts[2]), await hmac(secret, parts[0] + '.' + parts[1]))) return { error: 'bad signature' };
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) return { error: 'token expired' };
  if (typeof payload.iat === 'number' && payload.iat > now + 60) return { error: 'token from the future' };
  if (payload.exp - (payload.iat || now) > 600) return { error: 'token lives too long' };
  if (audience && payload.aud !== audience) return { error: 'wrong audience' };
  if (!payload.sub || !/^\d{5,25}$/.test(String(payload.sub))) return { error: 'no Discord user id' };
  return { payload };
}

// ---- requests / responses
export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers } });
}
export function cookies(request) {
  const out = {};
  for (const part of (request.headers.get('cookie') || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
export function setCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
export function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For')?.split(',')[0].trim() || '0.0.0.0';
}
// IPv6 users get a whole /64, so count per /64
export function ipKey(ip) {
  if (!ip.includes(':')) return ip;
  let parts = ip.split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  const full = [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  return full.slice(0, 4).map(h => (h || '0').toLowerCase().replace(/^0+(?=.)/, '')).join(':') + '::/64';
}

// ---- settings (Pages → Settings → Variables and Secrets)
export function config(env) {
  const loginReady = !!(env.AUTH_SECRET && env.SESSION_SECRET && env.BOT_LOGIN_URL);
  const limit = Math.max(0, parseInt(env.ANON_SCAN_LIMIT || '2', 10) || 0);
  const hours = Math.max(1, parseInt(env.ANON_WINDOW_HOURS || '24', 10) || 24);
  return {
    loginReady,
    // the free-scan limit only applies once login works and there is somewhere to count
    enforce: loginReady && !!env.EZLARP_KV && limit >= 0 && env.ANON_SCAN_LIMIT !== 'off',
    limit,
    windowSeconds: hours * 3600,
    windowHours: hours,
    sessionDays: Math.max(1, parseInt(env.SESSION_DAYS || '30', 10) || 30),
  };
}

export const SESSION_COOKIE = 'ezs';
export const TICKET_COOKIE = 'ezt';

export async function currentUser(request, env) {
  const s = await unseal(env.SESSION_SECRET, cookies(request)[SESSION_COOKIE]);
  return s && s.id ? s : null;
}
