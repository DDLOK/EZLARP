// POST /auth/logout
import { json, setCookie, SESSION_COOKIE } from '../_shared/util.js';

export async function onRequestPost() {
  return json({ ok: true }, 200, { 'set-cookie': setCookie(SESSION_COOKIE, '', 0) });
}
