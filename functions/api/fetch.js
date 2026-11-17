// GET /api/fetch?url=<link>
// Downloads a file for the page from sites that block in-browser downloads (CORS):
// Discord attachments, MediaFire, Gofile, GitHub releases, CurseForge CDN, Dropbox,
// Google Drive. Only these hosts are allowed so this can't be used as an open proxy.
// Nothing is stored: the file streams straight through to the browser.

const MAX_BYTES = 150 * 1024 * 1024;

const ALLOWED = [
  'cdn.discordapp.com', 'media.discordapp.net',
  'mediafire.com', 'www.mediafire.com',
  'gofile.io', 'api.gofile.io',
  'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com', 'raw.githubusercontent.com', 'codeload.github.com',
  'edge.forgecdn.net', 'mediafilez.forgecdn.net',
  'cdn.modrinth.com',
  'www.dropbox.com', 'dl.dropboxusercontent.com', 'dl.dropbox.com',
  'drive.google.com', 'drive.usercontent.google.com',
];
const ALLOWED_SUFFIX = ['.mediafire.com', '.gofile.io', '.dropboxusercontent.com', '.googleusercontent.com'];

const UA = 'Mozilla/5.0 (EZLARP file fetcher; +https://ezlarp.pages.dev)';

export function hostAllowed(host) {
  host = host.toLowerCase();
  return ALLOWED.includes(host) || ALLOWED_SUFFIX.some(s => host.endsWith(s));
}

class UserError extends Error {}

function fail(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

async function get(url, init = {}) {
  const r = await fetch(url, { redirect: 'follow', ...init, headers: { 'user-agent': UA, ...(init.headers || {}) } });
  const finalHost = new URL(r.url || url).hostname;
  if (!hostAllowed(finalHost)) throw new UserError(`the link redirected to ${finalHost}, which isn't an allowed file host`);
  return r;
}

// MediaFire file pages hold the real link in the download button.
async function mediafire(url) {
  const r = await get(url);
  if (!r.ok) throw new UserError(`MediaFire answered HTTP ${r.status}`);
  const ct = r.headers.get('content-type') || '';
  if (!/text\/html/.test(ct)) return r;
  const html = await r.text();
  const m = /href="(https:\/\/download\d*\.mediafire\.com\/[^"]+)"/.exec(html)
    || /"(https:\/\/download\d*\.mediafire\.com\/[^"]+)"/.exec(html);
  if (!m) throw new UserError('could not find the download button on that MediaFire page (removed, private or needs a captcha)');
  return get(m[1].replace(/&amp;/g, '&'));
}

// Gofile: share pages (gofile.io/d/CODE) need a guest token and the site's "wt" value.
async function gofile(url) {
  const u = new URL(url);
  const token = await gofileToken();
  const headers = { cookie: `accountToken=${token}`, authorization: `Bearer ${token}` };
  const code = /^\/d\/([\w-]+)/.exec(u.pathname);
  if (!code) return get(url, { headers }); // direct store link
  let wt = '4fd6sg89d7s6';
  try {
    const js = await (await fetch('https://gofile.io/dist/js/global.js', { headers: { 'user-agent': UA } })).text();
    const m = /wt["']?\s*[:=]\s*["']([\w]+)["']/.exec(js);
    if (m) wt = m[1];
  } catch (e) { /* use the default */ }
  const info = await (await fetch(`https://api.gofile.io/contents/${code[1]}?wt=${wt}`, { headers: { ...headers, 'user-agent': UA } })).json();
  if (info.status !== 'ok') throw new UserError(`Gofile: ${info.status || 'could not read that link'}`);
  const kids = Object.values(info.data.children || {}).filter(c => c.type === 'file');
  const pick = kids.find(c => /\.(jar|zip|class|apk|dex|exe|dll|mrpack)$/i.test(c.name)) || kids[0];
  if (!pick) throw new UserError('that Gofile folder has no files');
  const r = await get(pick.link, { headers });
  r.ezName = pick.name;
  return r;
}
async function gofileToken() {
  const r = await fetch('https://api.gofile.io/accounts', { method: 'POST', headers: { 'user-agent': UA } });
  const j = await r.json();
  if (j.status !== 'ok') throw new UserError('Gofile would not hand out a guest token');
  return j.data.token;
}

// Rewrites share links into direct download links.
export function directLink(raw) {
  const u = new URL(raw);
  const h = u.hostname.toLowerCase();
  if (h === 'www.dropbox.com' || h === 'dropbox.com') { u.searchParams.set('dl', '1'); return u.toString(); }
  if (h === 'drive.google.com') {
    const id = (/\/file\/d\/([\w-]+)/.exec(u.pathname) || [])[1] || u.searchParams.get('id');
    if (id) return `https://drive.usercontent.google.com/download?id=${id}&export=download&confirm=t`;
  }
  const gh = /^\/([^/]+\/[^/]+)\/(?:blob|raw)\/(.+)$/.exec(u.pathname);
  if (h === 'github.com' && gh) return `https://raw.githubusercontent.com/${gh[1]}/${gh[2]}`;
  return u.toString();
}

function fileNameOf(r, url) {
  if (r.ezName) return r.ezName;
  const cd = r.headers.get('content-disposition') || '';
  const m = /filename\*=UTF-8''([^;]+)/i.exec(cd) || /filename="?([^";]+)"?/i.exec(cd);
  if (m) { try { return decodeURIComponent(m[1]); } catch (e) { return m[1]; } }
  const last = new URL(r.url || url).pathname.split('/').filter(Boolean).pop() || 'download';
  try { return decodeURIComponent(last); } catch (e) { return last; }
}

export async function onRequestGet({ request }) {
  const raw = new URL(request.url).searchParams.get('url') || '';
  let url;
  try {
    url = new URL(raw);
  } catch (e) {
    return fail(400, 'that is not a valid link');
  }
  if (url.protocol !== 'https:') return fail(400, 'only https links are supported');
  if (!hostAllowed(url.hostname)) {
    return fail(403, `${url.hostname} isn't supported. Supported: Discord attachments, MediaFire, Gofile, GitHub, CurseForge CDN, Modrinth, Dropbox and Google Drive links.`);
  }
  try {
    const target = directLink(url.toString());
    const host = new URL(target).hostname;
    let r;
    if (/(^|\.)mediafire\.com$/.test(host)) r = await mediafire(target);
    else if (/(^|\.)gofile\.io$/.test(host)) r = await gofile(target);
    else r = await get(target);
    if (r.status === 404) return fail(404, 'the file was not found (deleted, or the link expired: Discord links expire after about a day)');
    if (!r.ok) return fail(502, `the file host answered HTTP ${r.status}`);
    const ct = r.headers.get('content-type') || '';
    if (/text\/html/.test(ct)) return fail(422, 'that link opens a web page, not a file. Use the direct download link.');
    const len = +r.headers.get('content-length') || 0;
    if (len > MAX_BYTES) return fail(413, `the file is ${Math.round(len / 1048576)} MB; links are limited to ${MAX_BYTES / 1048576} MB. Download it and drop it in instead.`);
    const name = fileNameOf(r, target);
    const headers = {
      'content-type': 'application/octet-stream',
      'cache-control': 'no-store',
      'x-filename': encodeURIComponent(name),
      'access-control-expose-headers': 'x-filename, content-length',
    };
    if (len) headers['content-length'] = String(len);
    return new Response(r.body, { status: 200, headers });
  } catch (e) {
    if (e instanceof UserError) return fail(422, e.message);
    return fail(502, 'could not download that link: ' + (e && e.message || e));
  }
}
