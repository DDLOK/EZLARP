// VPN / proxy / hosting / Tor detection for EZLARP.
//
// 1. ASN list: networks of hosting companies and VPN providers. Edit freely.
//    NOT listed on purpose: Apple (714), Akamai (20940, 36183), Cloudflare (13335) and
//    Fastly (54113): iCloud Private Relay exits there, and lots of iPhone users have it on.
// 2. Tor exit nodes (list from the Tor Project, cached in KV for 6 hours).
// 3. Optional: proxycheck.io (set PROXYCHECK_KEY), verdict cached per IP for 24 hours.
// Switch everything off with VPN_BLOCK=off.

export const VPN_ASNS = new Set([
  // VPN-heavy hosting
  9009,    // M247 (NordVPN, Surfshark, PIA, ...)
  60068,   // Datacamp / CDN77 (lots of VPN exits)
  147049,  // PacketHub
  212238,  // Datacamp
  136787,  // TEFINCOM (NordVPN)
  207137,  // PacketHub
  209854,  // Cyberzone (Surfshark)
  206092,  // IPXO (VPN ranges)
  396356,  // Latitude.sh / Maxihost
  49453,   // Global Layer
  62240,   // Clouvider
  44901,   // Belcloud
  51852,   // Private Layer
  58065,   // Packet Exchange
  25369,   // Hydra Communications (VPN exits)
  // cloud / hosting
  14061,   // DigitalOcean
  16276,   // OVH
  24940,   // Hetzner
  213230,  // Hetzner Cloud
  63949,   // Linode / Akamai Cloud
  20473,   // Vultr / Choopa
  16509, 14618, // Amazon AWS
  396982,  // Google Cloud
  15169,   // Google (cloud egress)
  8075,    // Microsoft Azure
  31898,   // Oracle Cloud
  51167,   // Contabo
  60781, 28753, // Leaseweb
  12876,   // Scaleway
  197540,  // netcup
  36352,   // ColoCrossing
  53667,   // FranTech / BuyVM
  40021,   // Contabo US
  46562,   // Performive
  8100,    // QuadraNet
  32613,   // iWeb
  35916,   // Multacom
  395954,  // Leaseweb US
  9370,    // Sakura
  45102,   // Alibaba Cloud
  132203,  // Tencent Cloud
  135377,  // UCloud
  211252,  // Delis
  42831,   // UK Servers
  202425,  // IP Volume
  210644,  // Aeza
  216246,  // Aeza
  48090,   // Pptechnology
]);

let torSet = null;
let torAt = 0;

async function torExits(env) {
  const now = Date.now();
  // a failed download leaves an empty list: try again after 10 minutes instead of 6 hours
  if (torSet && now - torAt < (torSet.size ? 6 * 3600 * 1000 : 600 * 1000)) return torSet;
  let text = env.EZLARP_KV ? await env.EZLARP_KV.get('vpn:tor') : null;
  if (!text) {
    try {
      const r = await fetch('https://check.torproject.org/torbulkexitlist', { cf: { cacheTtl: 21600 } });
      if (r.ok) {
        text = await r.text();
        if (env.EZLARP_KV) await env.EZLARP_KV.put('vpn:tor', text, { expirationTtl: 21600 });
      }
    } catch (e) { /* list unavailable: skip this check */ }
  }
  torSet = new Set((text || '').split('\n').map(s => s.trim()).filter(Boolean));
  torAt = now;
  return torSet;
}

async function proxycheck(ip, env) {
  if (!env.PROXYCHECK_KEY) return false;
  const key = 'vpn:pc:' + ip;
  const cached = env.EZLARP_KV ? await env.EZLARP_KV.get(key) : null;
  if (cached) return cached === '1';
  try {
    const r = await fetch(`https://proxycheck.io/v2/${encodeURIComponent(ip)}?key=${encodeURIComponent(env.PROXYCHECK_KEY)}&vpn=1&asn=1`);
    const j = await r.json();
    const hit = !!(j[ip] && j[ip].proxy === 'yes');
    if (env.EZLARP_KV) await env.EZLARP_KV.put(key, hit ? '1' : '0', { expirationTtl: 86400 });
    return hit;
  } catch (e) {
    return false;
  }
}

// for tests
export function resetVpnCache() { torSet = null; torAt = 0; }

// returns null when the visitor is fine, or a short reason
export async function vpnReason(request, env, ip) {
  if (String(env.VPN_BLOCK || '').toLowerCase() === 'off') return null;
  const asn = request.cf && Number(request.cf.asn);
  if (asn && VPN_ASNS.has(asn)) return `hosting/VPN network (AS${asn}${request.cf.asOrganization ? ' ' + request.cf.asOrganization : ''})`;
  if ((await torExits(env)).has(ip)) return 'Tor exit node';
  if (await proxycheck(ip, env)) return 'VPN or proxy (proxycheck.io)';
  return null;
}
