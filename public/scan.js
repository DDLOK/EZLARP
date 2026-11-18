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
    { id: 'android-perms', sev: 'low', title: 'Sensitive Android permissions',
      why: 'SMS, contacts, call log, accessibility, overlay, install-packages and similar permissions. Normal for some apps, abused by spyware and banking trojans.',
      str: /^android\.permission\.(?:READ_SMS|SEND_SMS|RECEIVE_SMS|READ_CONTACTS|READ_CALL_LOG|PROCESS_OUTGOING_CALLS|RECORD_AUDIO|BIND_ACCESSIBILITY_SERVICE|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|BIND_DEVICE_ADMIN|READ_PHONE_STATE|ACCESS_BACKGROUND_LOCATION|BIND_NOTIFICATION_LISTENER_SERVICE|QUERY_ALL_PACKAGES|MANAGE_EXTERNAL_STORAGE)$/ },
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
    { id: 'encoded', sev: 'med', title: 'Hidden string (base64 / hex / reversed)',
      why: 'A URL, path or command stored encoded so it doesn\'t show up in a plain text search. Legit code rarely hides URLs this way.',
      encoded: true },
    { id: 'jar-native', sev: 'low', title: 'Bundled native binaries',
      why: 'The archive ships .dll / .so / .dylib / .exe files. Their code is outside what a Java decompiler can show; their strings were scanned.',
      native: true },
    { id: 'sig-fractureiser', sev: 'high', title: 'fractureiser malware marker',
      why: 'Matches published indicators of the fractureiser malware (2023): its command servers, payload file names or the "neko" injector classes.',
      str: /^(?:85\.217\.144\.130|107\.189\.3\.101)(?::\d+)?$|libWebGL64\.jar|systemd-utility\.service|dev[/.]neko[/.]neko(?:injector|client)/,
      cls: ['dev/neko/nekoinjector/', 'dev/neko/nekoclient/'] },
    { id: 'sig-skyrage', sev: 'high', title: 'Skyrage malware marker',
      why: 'Contacts skyrage.de, the server of the Skyrage Minecraft malware (2023).',
      str: /(?:^|[/.@])skyrage\.de\b/i },
    { id: 'enc-blob', sev: 'med', title: 'Encrypted file inside', blob: true,
      why: 'A file with no known format whose bytes look random. Malware hides its real code like this and decrypts it when it runs. Some mods keep encrypted assets legitimately (licence keys, protected resources).' },
    { id: 'mixin-session', sev: 'high', title: 'Mixin rewrites the Minecraft session (login) class', mixin: true,
      why: 'Lets the mod read or replace your account token from inside Minecraft. Account-switcher mods do this; session stealers do too.' },
    { id: 'obf-tool', sev: 'low', title: 'Obfuscator marker',
      why: 'Left behind by a commercial or public obfuscator.',
      str: /Allatori|ZKM \d|Stringer Java Obfuscator|skidfuscator|paramorphism|branchlock|qprotect|Obfuscated (?:by|with)|radon\b.*obfuscat/i },
  ];

  const SEV_ORDER = { high: 0, med: 1, low: 2, info: 3 };
  const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s"'<>\\^`{|}]{4,}/gi;
  const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?\b/g;
  const BORING_HOST = /^(?:www\.)?(?:w3\.org|apache\.org|xml\.org|java\.sun\.com|oracle\.com|xmlsoap\.org|json-schema\.org|purl\.org|openjdk\.java\.net|mozilla\.org|gnu\.org|opensource\.org|schemas\.android\.com|schemas\.microsoft\.com|ns\.adobe\.com|localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|slf4j\.org|eclipse\.org|jcp\.org|creativecommons\.org)$/i;

  // .NET (C#/VB) equivalents, matched against "Namespace/Type.Member" references from cil.js
  const DOTNET_REFS = {
    exec: ['System/Diagnostics/Process.Start', 'System/Diagnostics/ProcessStartInfo..ctor', 'System/Diagnostics/ProcessStartInfo.set_FileName'],
    dynload: ['System/Reflection/Assembly.Load', 'System/Reflection/Assembly.LoadFile', 'System/Reflection/Assembly.LoadFrom', 'System/Reflection/Assembly.UnsafeLoadFrom',
      'System/AppDomain.Load', 'System/Reflection/MethodBase.Invoke', 'System/Reflection/Emit/DynamicMethod..ctor', 'System/Runtime/InteropServices/Marshal.GetDelegateForFunctionPointer'],
    net: ['System/Net/WebClient..ctor', 'System/Net/Http/HttpClient..ctor', 'System/Net/WebRequest.Create', 'System/Net/HttpWebRequest.GetResponse',
      'System/Net/Sockets/TcpClient..ctor', 'System/Net/Sockets/Socket..ctor', 'System/Net/Sockets/TcpClient.Connect'],
    'payload-url': ['System/Net/WebClient.DownloadFile', 'System/Net/WebClient.DownloadFileAsync', 'System/Net/WebClient.DownloadFileTaskAsync', 'System/Net/WebClient.DownloadData'],
    persistence: ['Microsoft/Win32/RegistryKey.SetValue', 'Microsoft/Win32/Registry.SetValue', 'Microsoft/Win32/TaskScheduler/TaskService..ctor'],
    screen: ['System/Drawing/Graphics.CopyFromScreen', 'System/Windows/Forms/Screen.get_PrimaryScreen', 'System/Windows/Forms/Screen.get_AllScreens'],
    clipboard: ['System/Windows/Forms/Clipboard.GetText', 'System/Windows/Forms/Clipboard.SetText', 'System/Windows/Clipboard.GetText', 'System/Windows/Clipboard.SetText'],
    native: ['System/Runtime/InteropServices/Marshal.Copy', 'System/Runtime/InteropServices/Marshal.AllocHGlobal'],
    reflect: ['System/Type.GetMethod', 'System/Type.InvokeMember', 'System/Type.GetType', 'System/Activator.CreateInstance'],
    crypto: ['System/Security/Cryptography/ProtectedData.Unprotect', 'System/Security/Cryptography/Aes.Create', 'System/Security/Cryptography/AesGcm.Decrypt',
      'System/Convert.FromBase64String', 'System/Security/Cryptography/RijndaelManaged..ctor'],
    sysinfo: ['System/Environment.get_MachineName', 'System/Environment.get_UserName', 'System/Management/ManagementObjectSearcher..ctor', 'System/Environment.GetFolderPath'],
    'file-delete': ['System/IO/File.Delete', 'System/IO/Directory.Delete'],
  };
  // native Windows imports, as "native/<dll>.<function>" (also P/Invoke from .NET)
  const NATIVE_REFS = {
    exec: ['kernel32.dll.CreateProcessW', 'kernel32.dll.CreateProcessA', 'kernel32.dll.WinExec', 'shell32.dll.ShellExecuteW', 'shell32.dll.ShellExecuteA', 'shell32.dll.ShellExecuteExW', 'shell32.dll.ShellExecuteExA'],
    dynload: ['kernel32.dll.CreateRemoteThread', 'kernel32.dll.WriteProcessMemory', 'kernel32.dll.VirtualAllocEx', 'ntdll.dll.NtUnmapViewOfSection', 'ntdll.dll.ZwUnmapViewOfSection',
      'kernel32.dll.SetThreadContext', 'ntdll.dll.NtWriteVirtualMemory', 'kernel32.dll.QueueUserAPC'],
    'payload-url': ['urlmon.dll.URLDownloadToFileW', 'urlmon.dll.URLDownloadToFileA'],
    net: ['wininet.dll.InternetOpenW', 'wininet.dll.InternetOpenA', 'wininet.dll.InternetOpenUrlW', 'wininet.dll.InternetOpenUrlA', 'winhttp.dll.WinHttpOpen', 'ws2_32.dll.connect', 'ws2_32.dll.#4'],
    persistence: ['advapi32.dll.RegSetValueExW', 'advapi32.dll.RegSetValueExA', 'advapi32.dll.CreateServiceW', 'advapi32.dll.CreateServiceA'],
    screen: ['gdi32.dll.BitBlt', 'user32.dll.GetDesktopWindow'],
    clipboard: ['user32.dll.GetClipboardData', 'user32.dll.SetClipboardData'],
    crypto: ['crypt32.dll.CryptUnprotectData', 'advapi32.dll.CryptDecrypt', 'bcrypt.dll.BCryptDecrypt'],
    sysinfo: ['kernel32.dll.GetComputerNameW', 'kernel32.dll.GetComputerNameA', 'advapi32.dll.GetUserNameW', 'advapi32.dll.GetUserNameA'],
    'file-delete': ['kernel32.dll.DeleteFileW', 'kernel32.dll.DeleteFileA'],
    keylog: ['user32.dll.SetWindowsHookExW', 'user32.dll.SetWindowsHookExA', 'user32.dll.GetAsyncKeyState', 'user32.dll.GetKeyState'],
  };
  if (!RULES.some(r => r.id === 'keylog')) RULES.push({ id: 'keylog', sev: 'med', title: 'Watches the keyboard',
    why: 'Keyboard hooks and key-state polling are how keyloggers record what you type. Games and hotkey tools use them too, so check what is done with the keys.' });
  for (const [id, refs] of Object.entries(NATIVE_REFS)) {
    const r = RULES.find(x => x.id === id);
    if (r) r.refs = (r.refs || []).concat(refs.map(x => 'native/' + x));
  }
  for (const [id, refs] of Object.entries(DOTNET_REFS)) {
    const r = RULES.find(x => x.id === id);
    if (r) r.refs = (r.refs || []).concat(refs);
  }
  const refIndex = new Map();   // "owner.member" -> rules
  const ENCODED = RULES.find(r => r.encoded);
  const NATIVE = RULES.find(r => r.native);
  const BLOB = RULES.find(r => r.blob);
  const MIXIN_SESSION = RULES.find(r => r.mixin);
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

  // ---- encoded strings
  const B64_RE = /^[A-Za-z0-9+/_-]{16,}={0,2}$/;
  const HEX_RE = /^(?:[0-9a-fA-F]{2}){10,}$/;
  const INTERESTING = /\b(?:https?|wss?|ftp|tcp):\/\/|webhook|\\AppData|\\Local Storage|Login Data|leveldb|powershell|cmd\.exe|\.exe\b|\/bin\/|HKEY_|discord|telegram|token/i;
  function printable(t) {
    if (!t || t.length < 6) return false;
    let ok = 0;
    for (let i = 0; i < t.length; i++) { const c = t.charCodeAt(i); if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++; }
    return ok / t.length > 0.95;
  }
  function decodeB64(t) {
    if (!B64_RE.test(t) || /^[a-z]+$|^[A-Z]+$|^[0-9]+$/.test(t)) return null;
    try {
      const norm = t.replace(/-/g, '+').replace(/_/g, '/');
      const bin = atob(norm + '='.repeat((4 - norm.length % 4) % 4));
      return printable(bin) ? bin : null;
    } catch (e) { return null; }
  }
  function decodeHex(t) {
    if (!HEX_RE.test(t)) return null;
    let out = '';
    for (let i = 0; i < t.length; i += 2) out += String.fromCharCode(parseInt(t.substr(i, 2), 16));
    return printable(out) ? out : null;
  }
  function decodings(s) {
    const out = [];
    const b = decodeB64(s); if (b) out.push(['base64', b]);
    const h = decodeHex(s); if (h) out.push(['hex', h]);
    if (s.length >= 12 && /^[\x20-\x7e]+$/.test(s)) {
      const r = [...s].reverse().join('');
      if (/^(?:https?|wss?):\/\//i.test(r) || /discord(?:app)?\.com\/api\/webhooks/i.test(r)) out.push(['reversed', r]);
    }
    return out;
  }

  function scanString(res, s, where, nested) {
    if (s.length < 3 || s.length > 4000) return;
    for (const r of strRules) if (r.str.test(s)) hit(res, r, where, nested ? `${nested}: ${s}` : s);
    if (!nested && s.length >= 12) {
      for (const [kind, dec] of decodings(s)) {
        if (!INTERESTING.test(dec)) continue;
        hit(res, ENCODED, where, `${kind} "${s.length > 60 ? s.slice(0, 60) + '…' : s}" → ${dec}`);
        res.decoded = res.decoded || [];
        if (res.decoded.length < 500) res.decoded.push({ where, kind, raw: s, text: dec });
        scanString(res, dec, where, kind);
      }
    }
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

  // info: result of Inspect.parseClass(bytes, true). prefix: "inner.jar!" for nested archives.
  function scanClass(res, info, prefix = '') {
    const where = prefix + (info.name || '?');
    res.classCount++;
    const LOADERS = /^java\/(?:lang\/ClassLoader|security\/SecureClassLoader|net\/URLClassLoader)$/;
    for (const ref of info.refs) {
      let rules = refIndex.get(ref);
      // a call on the class itself runs the inherited method: Loader.defineClass -> ClassLoader.defineClass
      if (!rules && info.superName && ref.startsWith(info.name + '.')) {
        const member = ref.slice(info.name.length + 1);
        rules = refIndex.get(info.superName + '.' + member) || (LOADERS.test(info.superName) ? refIndex.get('java/lang/ClassLoader.' + member) : null);
      }
      if (rules) for (const r of rules) hit(res, r, where, ref.replace(/\//g, '.'));
    }
    if (clsRules.length) {
      for (const c of info.classes) for (const r of clsRules) for (const pre of r.cls) if (c.startsWith(pre)) hit(res, r, where, c.replace(/\//g, '.'));
    }
    for (const s of info.strings) scanString(res, s, where);
  }

  // A native binary bundled in an archive: record it and scan its strings.
  function scanNative(res, where, strings) {
    hit(res, NATIVE, where, `${strings.length} strings scanned`);
    for (const st of strings) scanString(res, st.s, where);
  }

  // ---- encrypted payloads: random-looking files with no known format
  const KNOWN_EXT = /\.(png|jpe?g|gif|webp|bmp|ico|ogg|oga|wav|mp3|flac|ttf|otf|woff2?|jar|zip|gz|xz|bz2|7z|zst|lz4|br|pdf|so|dll|dylib|jnilib|class|nbt|schem|schematic|mca|litematic|kotlin_module|kotlin_builtins|dex|arsc|rsa|dsa|ec|sf)$/i;
  const MAGIC = ['89504e47', 'ffd8ff', '474946', '4f676753', '504b', '1f8b', '52494646', '494433', 'fffb', 'fff3', '664c6143', '774f4646', '774f4632',
    '00010000', '4f54544f', '00000100', '424d', 'cafebabe', 'fd377a58', '425a68', '377abcaf', '28b52ffd', '04224d18', '25504446', '52617221',
    '6465780a', '7f454c46', '4d5a', 'cffaedfe', 'feedfacf', '53514c69', '30820', '3082'];
  function entropy(u8) {
    const n = Math.min(u8.length, 65536);
    if (!n) return 0;
    const f = new Uint32Array(256);
    for (let i = 0; i < n; i++) f[u8[i]]++;
    let e = 0;
    for (let i = 0; i < 256; i++) if (f[i]) { const p = f[i] / n; e -= p * Math.log2(p); }
    return e;
  }
  const blobCandidate = (name, size) => size >= 1024 && size <= 64 * 1048576 && !KNOWN_EXT.test(name) && !/\.class$/i.test(name) && !/META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i.test(name);
  function scanBlob(res, where, u8) {
    if (u8.length < 1024 || KNOWN_EXT.test(where) || /META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i.test(where)) return false;
    let head = '';
    for (let i = 0; i < Math.min(4, u8.length); i++) head += u8[i].toString(16).padStart(2, '0');
    if (MAGIC.some(m => head.startsWith(m))) return false;
    const e = entropy(u8);
    if (e < 7.5) return false;
    hit(res, BLOB, where, `${u8.length >= 1048576 ? (u8.length / 1048576).toFixed(1) + ' MB' : Math.round(u8.length / 1024) + ' KB'} · entropy ${e.toFixed(2)} / 8`);
    return true;
  }
  function scanMixin(res, where, targets) {
    const SESSION = /^(net\/minecraft\/client\/session\/Session|net\/minecraft\/client\/util\/Session|net\/minecraft\/client\/User|net\/minecraft\/util\/Session|net\/minecraft\/class_320)$/;
    for (const t of targets) if (SESSION.test(t)) hit(res, MIXIN_SESSION, where, 'targets ' + t.replace(/\//g, '.'));
  }

  // Short plain-text summary for pasting into Discord / chat. URLs are defanged.
  function textSummary(name, sha256, sum, res) {
    const defang = u => u.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
    const icon = { high: '🔴', med: '🟠', low: '🟡', none: '🟢' }[sum.level];
    const lines = [`**${name}** — ${icon} ${VERDICT_TEXT[sum.verdict] || sum.label}${sum.detections && sum.detections.length ? ': ' + sum.detections.map(d => d.name).join(', ') : ''} (EZLARP static scan)`];
    if (sha256) lines.push('sha256: `' + sha256 + '`');
    for (const f of sum.findings.slice(0, 8)) {
      const w = [...f.where.keys()].slice(0, 2).map(x => x.replace(/\//g, '.')).join(', ');
      lines.push(`- [${f.rule.sev.toUpperCase()}] ${f.rule.title}${w ? ' — ' + w + (f.where.size > 2 ? ` +${f.where.size - 2}` : '') : ''}`);
    }
    const urls = [...res.urls.keys()].slice(0, 6);
    if (urls.length) lines.push('urls: ' + urls.map(u => '`' + defang(u) + '`').join(' '));
    lines.push('_heuristics only — a hit means "read this code", not proof of malware_');
    return lines.join('\n');
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

  // Session-token reads in classes whose only URLs are Mojang / Microsoft endpoints
  // (skin upload, realms, login) are a different thing from token theft.
  const OFFICIAL = /^https?:\/\/(?:[\w-]+\.)*(?:minecraftservices\.com|mojang\.com|minecraft\.net|xboxlive\.com|live\.com|microsoftonline\.com|microsoft\.com)(?:[:/]|$)/i;
  const MC_OFFICIAL = { id: 'mc-session-official', sev: 'med', title: 'Uses the Minecraft session token with Mojang / Microsoft servers',
    why: 'Reads the access token in code that only contacts official Mojang or Microsoft endpoints (skin upload, Realms, login). Common for skin and account mods. Check that the token is not also passed to other classes that send data elsewhere.' };
  function urlsByWhere(res) {
    const m = new Map();
    for (const [u, wheres] of res.urls) for (const w of wheres) { if (!m.has(w)) m.set(w, []); m.get(w).push(u); }
    return m;
  }

  // Named detections, shown as the verdict. Signatures match known malware; the
  // behaviour ones need "steals X" and "sends it out" together.
  const EXFIL = ['webhook', 'telegram'];
  const FAMILIES = [
    { name: 'fractureiser', kind: 'known malware', needs: [['sig-fractureiser']] },
    { name: 'Skyrage', kind: 'known malware', needs: [['sig-skyrage']] },
    { name: 'Minecraft session stealer', kind: 'behaviour', sameClass: true, needs: [['mc-session'], EXFIL] },
    { name: 'Discord token grabber', kind: 'behaviour', needs: [['discord-tokens'], EXFIL] },
    { name: 'Browser password stealer', kind: 'behaviour', needs: [['browser-creds'], EXFIL] },
    { name: 'Crypto wallet stealer', kind: 'behaviour', needs: [['wallets'], EXFIL] },
    { name: 'Launcher account stealer', kind: 'behaviour', needs: [['launcher-accounts'], EXFIL] },
    { name: 'Dropper (downloads and installs a program)', kind: 'behaviour', needs: [['payload-url'], ['persistence']] },
    { name: 'Hidden payload loader', kind: 'behaviour', needs: [['enc-blob'], ['dynload']] },
    { name: 'Minecraft session stealer (mixin)', kind: 'behaviour', needs: [['mixin-session'], EXFIL] },
  ];
  function detectFamilies(res) {
    const out = [];
    for (const fam of FAMILIES) {
      const groups = fam.needs.map(ids => ids.map(id => res.hits.get(id)).filter(Boolean));
      if (groups.some(g => !g.length)) continue;
      let where = null;
      if (fam.sameClass) {
        const sets = groups.map(g => new Set(g.flatMap(h => [...h.where.keys()])));
        const common = [...sets[0]].filter(w => sets.every(st => st.has(w)));
        if (!common.length) continue;
        where = common;
      } else {
        where = [...new Set(groups.flat().flatMap(h => [...h.where.keys()]))];
      }
      out.push({ name: fam.name, kind: fam.kind, where: where.slice(0, 20), because: groups.map(g => g.map(h => h.rule.title).join(' / ')) });
    }
    return out;
  }

  function summarize(res) {
    const sess = res.hits.get('mc-session');
    if (sess) {
      const byWhere = urlsByWhere(res);
      const official = new Map(), other = new Map();
      for (const [w, ev] of sess.where) {
        const urls = byWhere.get(w) || [];
        const exfil = ['webhook', 'telegram'].some(id => res.hits.get(id) && res.hits.get(id).where.has(w));
        if (urls.length && urls.every(u => OFFICIAL.test(u)) && !exfil) official.set(w, new Set([...ev, 'contacts only: ' + urls.join(', ')]));
        else other.set(w, ev);
      }
      if (official.size) {
        res.hits.set('mc-session-official', { rule: MC_OFFICIAL, where: official });
        if (other.size) sess.where = other; else res.hits.delete('mc-session');
      }
    }
    const findings = [...res.hits.values()].sort((a, b) => SEV_ORDER[a.rule.sev] - SEV_ORDER[b.rule.sev] || b.where.size - a.where.size);
    const count = { high: 0, med: 0, low: 0 };
    for (const f of findings) count[f.rule.sev]++;
    let level = 'none';
    if (count.high) level = 'high';
    else if (count.med) level = 'med';
    else if (count.low >= 3) level = 'low';
    const label = {
      high: 'high-risk indicators', med: 'review recommended', low: 'minor indicators', none: 'no known indicators'
    }[level];
    const detections = detectFamilies(res);
    // one-word verdict, like an online scanner
    const verdict = detections.length ? 'malicious' : level === 'high' ? 'suspicious' : level === 'med' ? 'review' : 'clean';
    return { findings, count, level, label, detections, verdict, rulesTotal: RULES.length, rulesHit: findings.length };
  }

  const VERDICT_TEXT = { malicious: 'MALICIOUS', suspicious: 'SUSPICIOUS', review: 'needs review', clean: 'clean' };
  return { RULES, VERDICT_TEXT, newResult, scanClass, scanString, scanNative, scanNames, scanBlob, scanMixin, blobCandidate, entropy, summarize, textSummary, decodings };
})();
