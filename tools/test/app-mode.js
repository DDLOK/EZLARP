// App-mode test: run the helper first (desktop/), then this.
//   HOME=/tmp/home XDG_CACHE_HOME=/tmp/home/.cache EZLARP_SITE=http://127.0.0.1:8799 ./ezlarp --no-window /tmp/fx/dotnet.dll &
//   node tools/test/app-mode.js
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const fs = require('fs');
(async () => {
  const T = fs.readFileSync('/tmp/home/.cache/EZLARP/helper-token', 'utf8').trim();
  const files = await (await fetch('http://127.0.0.1:47613/files?t=' + T)).json();
  const b = await chromium.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox'] });
  const ctx = await b.newContext({ viewport: { width: 1300, height: 900 } });
  await ctx.route(/cdnjs/, r => r.abort());
  const p = await ctx.newPage();
  const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto('http://127.0.0.1:8799/');
  await p.evaluate(() => fetch('/__test/account?mode=off', { method: 'POST' }));
  await p.goto(`http://127.0.0.1:8799/?app=1#app=${T}&open=${files[0].id}`);
  await p.waitForFunction(() => /C# types/.test(document.querySelector('#ftags').textContent), null, { timeout: 30000 });
  console.log('opened from app:', await p.textContent('#fname'), '| hash cleaned:', await p.evaluate(() => location.hash === ''), '| body.app:', await p.evaluate(() => document.body.classList.contains('app')));
  console.log('vs code layout in app:', await p.evaluate(() => document.body.classList.contains('ide')));
  console.log('get-app button hidden in app:', await p.evaluate(() => getComputedStyle(document.getElementById('getapp')).display === 'none'));
  await p.evaluate(() => document.getElementById('appmods').click());
  await p.waitForFunction(() => /hide\.jar/.test(document.body.textContent), null, { timeout: 30000 }).then(() => console.log('mods scan: hide.jar shown'), () => console.log('mods scan: NOT shown'));
  await p.waitForTimeout(1500);
  console.log('fname after mods:', await p.textContent('#fname'));
  // login wall: login enabled, not logged in
  await p.evaluate(() => fetch('/__test/account?mode=limit', { method: 'POST' }));
  await p.goto(`http://127.0.0.1:8799/?app=1&reload=1#app=${T}`);
  await p.waitForTimeout(1500);
  console.log('login wall shown:', await p.evaluate(() => !document.getElementById('appgate').hidden));
  await p.screenshot({ path: '/tmp/shots/appgate.png' });
  // normal site: download popup
  const p2 = await ctx.newPage();
  await p2.goto('http://127.0.0.1:8799/');
  await p2.waitForTimeout(500);
  console.log('normal site: wall hidden:', await p2.evaluate(() => document.getElementById('appgate').hidden), '| mods button hidden:', await p2.evaluate(() => document.getElementById('appmods').hidden));
  await p2.click('#getapp');
  await p2.waitForTimeout(800);
  console.log('download popup:', await p2.evaluate(() => !document.getElementById('appdl').hidden), await p2.textContent('#appdlhash'));
  await p2.screenshot({ path: '/tmp/shots/appdl.png' });
  await p.evaluate(() => fetch('/__test/account?mode=off', { method: 'POST' }));
  console.log('errors:', errs);
  await b.close();
})();
