// EZLARP static indicator scan. Looks at class constant pools (strings and
// method/field references) and at strings pulled out of executables, and
// reports patterns commonly seen in stealers, RATs and backdoored mods.
// Heuristics only: a hit is a reason to read the code, not proof of anything.
'use strict';

const Scan = (() => {

  // sev: high | med | low | info
  // str:   regex tested against string constants
  // refs:  exact "owner.member" references
  // cls:   class-name prefixes (referenced classes)
  const RULES = [
    { id: 'webhook', sev: 'high', title: 'Discord webhook URL',
      why: 'Webhooks are the most common way stealers send stolen data out. Legit mods rarely hardcode one.',
      str: /discord(?:app)?\.com\/api\/webhooks\/|discord\.com\/api\/v\d+\/webhooks\// },
    { id: 'telegram', sev: 'high', title: 'Telegram bot API',
      why: 'Bot API calls are a common exfiltration channel.',
      str: /api\.telegram\.org\/bot/ },
    { id: 'mc-session', sev: 'high', title: 'Reads the Minecraft session token',
      why: 'The access token lets someone log in as you. Only auth and account-switcher mods have a reason to touch it.',
      refs: ['net/minecraft/client/session/Session.getAccessToken', 'net/minecraft/client/util/Session.getAccessToken',
        'net/minecraft/class_320.method_1674', 'net/minecraft/class_320.method_1675',
        'net/minecraft/client/User.getAccessToken', 'net/minecraft/util/Session.func_148254_d', 'net/minecraft/util/Session.func_111286_b',
        'net/minecraft/util/Session.getToken', 'net/minecraft/util/Session.getSessionID',
        'net/minecraft/client/user/User.getAccessToken'],
      str: /^(?:func_148254_d|func_111286_b|method_1674)$/ },
    { id: 'browser-creds', sev: 'high', title: 'Browser password / cookie stores',
      why: 'These are the files browsers keep saved logins and cookies in.',
      str: /(?:^|[\\/])(?:Login Data|Local State|Web Data|logins\.json|cookies\.sqlite|key4\.db)$|\\(?:Google\\Chrome|BraveSoftware|Microsoft\\Edge|Opera Software|Yandex\\YandexBrowser)\\|User Data\\Default/i },
    { id: 'discord-tokens', sev: 'high', title: 'Discord token locations',
      why: 'Reading Discord\'s local storage is how account tokens get stolen.',
      str: /discord(?:canary|ptb)?[\\/]Local Storage|Local Storage[\\/]leveldb|\[\\w-\]\{2[46]\}\\\.\[\\w-\]\{6\}|dQw4w9WgXcQ:/i },
    { id: 'wallets', sev: 'high', title: 'Crypto wallet paths',
      why: 'Wallet files and extension IDs are targeted by stealers.',
      str: /wallet\.dat|\\Exodus\\|\\Electrum\\wallets|\\atomic\\Local Storage|nkbihfbeogaeaoehlefnkodbefgpgknn|\\Ethereum\\keystore/i },
    { id: 'launcher-accounts', sev: 'high', title: 'Launcher account files',
      why: 'These files hold saved Minecraft / launcher logins.',
      str: /launcher_accounts(?:_microsoft_store)?\.json|launcher_profiles\.json|\.lunarclient[\\/]settings[\\/]game[\\/]accounts\.json|essential[\\/]microsoft_accounts\.json|\.feather[\\/]accounts\.json|PolyMC[\\/]accounts\.json|PrismLauncher[\\/]accounts\.json/i },
    { id: 'persistence', sev: 'high', title: 'Startup persistence',
      why: 'Adds itself to things that run on login or boot.',
      str: /CurrentVersion\\Run\b|\\Start Menu\\Programs\\Startup|schtasks(?:\.exe)?\s+\/create|LaunchAgents\/|\/etc\/systemd\/system|crontab\s+-/i },
    { id: 'exec', sev: 'med', title: 'Runs system commands',
      why: 'Starts other programs. Some mods do this legitimately (opening folders, restarting), but it is also how droppers run payloads.',
      refs: ['java/lang/Runtime.exec', 'java/lang/ProcessBuilder.start', 'java/lang/ProcessBuilder.<init>'] },
    { id: 'shell', sev: 'med', title: 'Shell / scripting commands',
      why: 'Command lines for cmd, PowerShell and friends.',
      str: /\bpowershell(?:\.exe)?\b|\bcmd(?:\.exe)?\s+\/c\b|\bwscript\b|\bmshta\b|\bcertutil\b.*-decode|\bbitsadmin\b|\/bin\/(?:ba)?sh\b|\breg(?:\.exe)?\s+add\b|-ExecutionPolicy\s+Bypass|-WindowStyle\s+Hidden/i },
    { id: 'dynload', sev: 'med', title: 'Loads code at runtime',
      why: 'Defining classes from bytes or remote jars hides what actually runs.',
      refs: ['java/lang/ClassLoader.defineClass', 'java/net/URLClassLoader.<init>', 'java/net/URLClassLoader.newInstance',
        'sun/misc/Unsafe.defineAnonymousClass', 'sun/misc/Unsafe.defineClass', 'java/lang/invoke/MethodHandles$Lookup.defineClass',
        'java/lang/invoke/MethodHandles$Lookup.defineHiddenClass'] },
    { id: 'payload-url', sev: 'med', title: 'Downloads an executable or script',
      why: 'A URL that points straight at a runnable file.',
      str: /^https?:\/\/\S+\.(?:exe|dll|bat|cmd|ps1|vbs|scr|msi|jar|sh)(?:\?\S*)?$/i },
    { id: 'file-hosts', sev: 'med', title: 'Paste / file-drop hosts',
      why: 'Often used to fetch second-stage payloads or commands.',
      str: /pastebin\.com\/raw|hastebin\.com|paste\.ee\/r|anonfiles\.com|transfer\.sh|gofile\.io|file\.io\/|catbox\.moe|cdn\.discordapp\.com\/attachments|rentry\.co\/\S+\/raw|ngrok\.io|trycloudflare\.com/i },
    { id: 'ip-lookup', sev: 'med', title: 'Looks up your public IP',
      why: 'IP-lookup services are used for geolocation and victim logging.',
      str: /api\.ipify\.org|checkip\.amazonaws\.com|ip-api\.com|ifconfig\.me|ipinfo\.io|icanhazip\.com|myexternalip\.com|api\.myip\.com|wtfismyip\.com/i },
    { id: 'screen', sev: 'med', title: 'Screen capture',
      why: 'Takes screenshots of the desktop.',
      refs: ['java/awt/Robot.createScreenCapture', 'java/awt/Robot.createMultiResolutionScreenCapture'] },
    { id: 'bukkit-op', sev: 'med', title: 'Grants operator / runs console commands',
      why: 'In a server plugin this can be a backdoor. Check who can trigger it.',
      refs: ['org/bukkit/entity/Player.setOp', 'org/bukkit/OfflinePlayer.setOp', 'org/bukkit/command/CommandSender.setOp',
        'org/bukkit/permissions/ServerOperator.setOp'] },
    { id: 'clipboard', sev: 'low', title: 'Clipboard access',
      why: 'Reads or replaces clipboard contents (crypto address swappers do this).',
      refs: ['java/awt/Toolkit.getSystemClipboard', 'java/awt/datatransfer/Clipboard.setContents', 'java/awt/datatransfer/Clipboard.getData'] },
    { id: 'native', sev: 'low', title: 'Loads native libraries',
      why: 'Native code is outside what a Java decompiler can show.',
      refs: ['java/lang/System.load', 'java/lang/System.loadLibrary', 'java/lang/Runtime.load', 'java/lang/Runtime.loadLibrary'],
      cls: ['com/sun/jna/'] },
    { id: 'net', sev: 'low', title: 'Network access',
      why: 'Opens connections. Normal for update checkers, APIs and multiplayer features.',
      refs: ['java/net/URL.openConnection', 'java/net/URL.openStream', 'java/net/Socket.<init>', 'java/net/http/HttpClient.newHttpClient',
        'java/net/http/HttpClient.newBuilder', 'java/net/HttpURLConnection.connect', 'java/net/DatagramSocket.<init>'],
      cls: ['okhttp3/', 'org/apache/http/'] },
    { id: 'reflect', sev: 'low', title: 'Reflection',
      why: 'Calls methods by name at runtime. Common in mods, but also used to hide behaviour.',
      refs: ['java/lang/reflect/Method.invoke', 'java/lang/Class.forName', 'java/lang/reflect/Field.setAccessible', 'java/lang/reflect/Method.setAccessible'] },
    { id: 'crypto', sev: 'low', title: 'Encryption / encoding',
      why: 'Ciphers and Base64 are normal, but are also used to hide strings and payloads.',
      refs: ['javax/crypto/Cipher.getInstance', 'java/util/Base64.getDecoder', 'javax/crypto/spec/SecretKeySpec.<init>'] },
    { id: 'sysinfo', sev: 'low', title: 'Reads environment details',
      why: 'User name, home directory, OS and environment variables.',
      refs: ['java/lang/System.getenv'],
      str: /^(?:user\.name|user\.home|os\.name|APPDATA|LOCALAPPDATA|USERPROFILE|COMPUTERNAME)$/ },
    { id: 'file-delete', sev: 'low', title: 'Deletes files',
      why: 'Removes files or schedules removal on exit.',
      refs: ['java/io/File.delete', 'java/io/File.deleteOnExit', 'java/nio/file/Files.delete', 'java/nio/file/Files.deleteIfExists'] },
    { id: 'obf-tool', sev: 'low', title: 'Obfuscator marker',
      why: 'Left behind by a commercial or public obfuscator.',
      str: /Allatori|ZKM \d|Stringer Java Obfuscator|skidfuscator|paramorphism|branchlock|qprotect|Obfuscated (?:by|with)|radon\b.*obfuscat/i },
  ];

  const SEV_ORDER = { high: 0, med: 1, low: 2, info: 3 };
  const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s"'<>\\^`{|}]{4,}/gi;
  const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?\b/g;
  const BORING_HOST = /^(?:www\.)?(?:w3\.org|apache\.org|xml\.org|java\.sun\.com|oracle\.com|xmlsoap\.org|json-schema\.org|purl\.org|openjdk\.java\.net|mozilla\.org|gnu\.org|opensource\.org|schemas\.android\.com|schemas\.microsoft\.com|ns\.adobe\.com|localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|slf4j\.org|eclipse\.org|jcp\.org|creativecommons\.org)$/i;

  const refIndex = new Map();   // "owner.member" -> rules
  const clsRules = [];
  const strRules = [];
  for (const r of RULES) {
    for (const ref of r.refs || []) { if (!refIndex.has(ref)) refIndex.set(ref, []); refIndex.get(ref).push(r); }
    if (r.cls) clsRules.push(r);
    if (r.str) strRules.push(r);
  }

  function newResult() {
    return { hits: new Map(), urls: new Map(), ips: new Map(), classCount: 0, obf: null };
  }
  function hit(res, rule, where, evidence) {
    let h = res.hits.get(rule.id);
    if (!h) res.hits.set(rule.id, h = { rule, where: new Map() });
    let ev = h.where.get(where);
    if (!ev) h.where.set(where, ev = new Set());
    if (evidence && ev.size < 6) ev.add(evidence.length > 200 ? evidence.slice(0, 200) + '…' : evidence);
  }
  function note(map, key, where) {
    let s = map.get(key);
    if (!s) map.set(key, s = new Set());
    if (s.size < 20) s.add(where);
  }

  function scanString(res, s, where) {
    if (s.length < 3 || s.length > 4000) return;
    for (const r of strRules) if (r.str.test(s)) hit(res, r, where, s);
    if (s.indexOf('://') > 0) {
      URL_RE.lastIndex = 0;
      for (let m; (m = URL_RE.exec(s));) {
        const url = m[0].replace(/[),.;]+$/, '');
        const host = (/^[a-z]+:\/\/([^/:?#]+)/i.exec(url) || [])[1] || '';
        if (!BORING_HOST.test(host)) note(res.urls, url, where);
      }
    }
    if (s.length < 64) {
      IP_RE.lastIndex = 0;
      for (let m; (m = IP_RE.exec(s));) {
        const ip = m[0];
        const oct = ip.split(':')[0].split('.').map(Number);
        const hasPort = ip.includes(':');
        if (oct[0] === 0 || oct[0] === 127 || oct[0] >= 224) continue;
        // "1.21.4.0"-style version numbers look like IPs; skip those unless there is a port
        if (!hasPort && oct.every(o => o < 30)) continue;
        note(res.ips, ip, where);
      }
    }
  }

  // info: result of Inspect.parseClass(bytes, true)
  function scanClass(res, info) {
    const where = info.name || '?';
    res.classCount++;
    for (const ref of info.refs) {
      const rules = refIndex.get(ref);
      if (rules) for (const r of rules) hit(res, r, where, ref.replace(/\//g, '.'));
    }
    if (clsRules.length) {
      for (const c of info.classes) for (const r of clsRules) for (const pre of r.cls) if (c.startsWith(pre)) hit(res, r, where, c.replace(/\//g, '.'));
    }
    for (const s of info.strings) scanString(res, s, where);
  }

  // Name-based obfuscation heuristic over all class names.
  function scanNames(res, names) {
    if (names.length < 8) return;
    let short = 0, weird = 0;
    for (const n of names) {
      const simple = n.slice(n.lastIndexOf('/') + 1).split('$')[0];
      if (simple.length <= 2) short++;
      else if (/^[Il1]+$|^[O0]+$|[^\x20-\x7e]/.test(simple) || /^(?:a{2,}|[a-z]{1,2}\d*)$/.test(simple) && simple.length <= 3) weird++;
    }
    const frac = (short + weird) / names.length;
    if (frac > 0.3) res.obf = { frac, short, weird, total: names.length };
  }

  function summarize(res) {
    const findings = [...res.hits.values()].sort((a, b) => SEV_ORDER[a.rule.sev] - SEV_ORDER[b.rule.sev] || b.where.size - a.where.size);
    const count = { high: 0, med: 0, low: 0 };
    for (const f of findings) count[f.rule.sev]++;
    let level = 'none';
    if (count.high) level = 'high';
    else if (count.med >= 2) level = 'med';
    else if (count.med || count.low >= 3) level = 'low';
    const label = {
      high: 'high-risk indicators', med: 'review recommended', low: 'minor indicators', none: 'no known indicators'
    }[level];
    return { findings, count, level, label, rulesTotal: RULES.length, rulesHit: findings.length };
  }

  return { RULES, newResult, scanClass, scanString, scanNames, summarize };
})();
