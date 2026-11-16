// Stand-in for the CheerpJ loader in local tests: same API surface, but
// cheerpjRunMain is forwarded to tools/test/server.py, which runs a real JVM.
(() => {
  const fs = new Map();
  const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 32768) s += String.fromCharCode.apply(null, u8.subarray(i, i + 32768)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  window.__cjfs = fs;
  window.__cjcalls = [];
  window.cheerpjInit = async opts => { window.__cjinit = opts; };
  window.cheerpOSAddStringFile = (p, data) => fs.set(p, data instanceof Uint8Array ? data : new TextEncoder().encode(data));
  window.cheerpjRunMain = async (main, cp, ...args) => {
    window.__cjcalls.push({ main, args });
    const files = {};
    for (const a of args) for (const m of String(a).matchAll(/\/(?:str|files)\/[^\s=:]+/g)) if (fs.has(m[0])) files[m[0]] = b64(fs.get(m[0]));
    const r = await fetch('/__jvm', { method: 'POST', body: JSON.stringify({ main, cp, args, files }) });
    const j = await r.json();
    for (const [p, b] of Object.entries(j.out)) fs.set(p, unb64(b));
    const c = document.getElementById('console');
    if (c) for (const line of j.stdout.split('\n')) { c.textContent += line + '\n'; await new Promise(r => setTimeout(r, 0)); }
    if (j.stderr.trim()) console.warn('[jvm stderr]', j.stderr.slice(-800));
    return j.code;
  };
  window.cjFileBlob = async p => { if (!fs.has(p)) throw new Error('file not found ' + p); return new Blob([fs.get(p)]); };
})();
