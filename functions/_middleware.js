// Runs for /api/* and /auth/* only (see public/_routes.json): blocks VPNs, proxies and Tor.
import { json, clientIp } from './_shared/util.js';
import { vpnReason } from './_shared/vpn.js';

export async function onRequest(context) {
  const { request, env, data } = context;
  const ip = clientIp(request);
  data.ip = ip;
  const why = await vpnReason(request, env, ip);
  if (why) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/auth/')) return Response.redirect(new URL('/?login=vpn', url).toString(), 302);
    return json({ error: 'VPNs and proxies are not allowed. Turn yours off and reload the page.', reason: 'vpn', detail: why }, 403);
  }
  return context.next();
}
