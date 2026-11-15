const drop     = document.getElementById('drop');
const fileEl   = document.getElementById('file');
const pick     = document.getElementById('pick');
const status   = document.getElementById('status');
const fname    = document.getElementById('fname');
const fsize    = document.getElementById('fsize');
const fstate   = document.getElementById('fstate');
const fill     = document.getElementById('fill');
const result   = document.getElementById('result');
const filetabs = document.getElementById('filetabs');
const code     = document.getElementById('code');
const err      = document.getElementById('err');
const dl       = document.getElementById('dl');

let currentFiles = {};
let currentName  = '';
let cheerpReady  = null;

pick.onclick     = () => fileEl.click();
fileEl.onchange  = e => handle(e.target.files[0]);

['dragenter','dragover'].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault(); drop.classList.add('drag');
}));
['dragleave','drop'].forEach(ev => drop.addEventListener(ev, e => {
  e.preventDefault(); drop.classList.remove('drag');
}));
drop.addEventListener('drop', e => {
  const f = e.dataTransfer.files[0]; if (f) handle(f);
});

function human(b){
  const u=['B','KB','MB','GB']; let i=0;
  while(b>=1024 && i<u.length-1){b/=1024;i++;}
  return b.toFixed(b<10?2:0)+' '+u[i];
}

async function initCheerp(){
  if (cheerpReady) return cheerpReady;
  cheerpReady = (async () => {
    fstate.textContent = 'loading JVM (first time ~10MB)';
    fill.style.width = '15%';
    await cheerpjInit({ status: 'none', natives: {} });
  })();
  return cheerpReady;
}

async function handle(f){
  if (!f) return;
  err.hidden = true;
  result.hidden = true;
  status.hidden = false;
  fname.textContent = f.name;
  fsize.textContent = human(f.size);
  fstate.textContent = 'reading';
  fill.style.width = '5%';

  try {
    const buf = new Uint8Array(await f.arrayBuffer());

    await initCheerp();

    fstate.textContent = 'staging input';
    fill.style.width = '35%';

    cheerpOSAddStringFile('/str/input.jar', buf);

    fstate.textContent = 'decompiling';
    fill.style.width = '55%';

    const exit = await cheerpjRunJar(
      '/app/vineflower.jar',
      '--silent=1',
      '/str/input.jar',
      '/files/'
    );

    if (exit !== 0) throw new Error(`vineflower exit code ${exit}`);

    fstate.textContent = 'collecting output';
    fill.style.width = '85%';

    const outJarBlob = await cjFileBlob('/files/input.jar');
    const outBuf = new Uint8Array(await outJarBlob.arrayBuffer());

    const zip = await JSZip.loadAsync(outBuf);
    const files = {};
    const names = Object.keys(zip.files).filter(n => n.endsWith('.java')).slice(0, 400);
    for (const n of names) files[n] = await zip.files[n].async('string');

    if (!names.length){
      throw new Error('no .java files in decompiled output');
    }

    fill.style.width = '100%';
    fstate.textContent = 'done';

    currentFiles = files;
    currentName  = f.name;
    render();
  } catch(e){
    fstate.textContent = 'error';
    fill.style.width = '100%';
    err.textContent = '[error] ' + (e && e.message || e);
    err.hidden = false;
  }
}

function render(){
  const names = Object.keys(currentFiles);
  filetabs.innerHTML = '';
  names.forEach((n,i) => {
    const t = document.createElement('div');
    t.className = 'ftab' + (i===0?' active':'');
    t.textContent = n;
    t.onclick = () => {
      [...filetabs.children].forEach(x=>x.classList.remove('active'));
      t.classList.add('active');
      code.textContent = currentFiles[n];
    };
    filetabs.appendChild(t);
  });
  code.textContent = currentFiles[names[0]];
  result.hidden = false;
}

dl.onclick = () => {
  const blob = new Blob(
    [Object.entries(currentFiles).map(([k,v])=>`// ===== ${k} =====\n${v}`).join('\n\n')],
    {type:'text/plain'}
  );
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = currentName.replace(/\.(jar|class)$/i,'') + '.decompiled.txt';
  a.click();
};
