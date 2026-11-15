const API = '/api/decompile';
const drop   = document.getElementById('drop');
const fileEl = document.getElementById('file');
const pick   = document.getElementById('pick');
const status = document.getElementById('status');
const fname  = document.getElementById('fname');
const fsize  = document.getElementById('fsize');
const fstate = document.getElementById('fstate');
const fill   = document.getElementById('fill');
const result = document.getElementById('result');
const filetabs = document.getElementById('filetabs');
const code   = document.getElementById('code');
const err    = document.getElementById('err');
const dl     = document.getElementById('dl');

let currentFiles = {};
let currentName  = '';

pick.onclick = () => fileEl.click();
fileEl.onchange = e => handle(e.target.files[0]);

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

async function handle(f){
  if (!f) return;
  err.hidden = true;
  result.hidden = true;
  status.hidden = false;
  fname.textContent = f.name;
  fsize.textContent = human(f.size);
  fstate.textContent = 'uploading';
  fill.style.width = '30%';

  const fd = new FormData();
  fd.append('file', f);

  try{
    fstate.textContent = 'decompiling';
    fill.style.width = '65%';
    const r = await fetch(API, { method:'POST', body:fd });
    if (!r.ok){
      const t = await r.text();
      throw new Error(`${r.status} — ${t.slice(0,400)}`);
    }
    const data = await r.json();
    fill.style.width = '100%';
    fstate.textContent = 'done';
    currentFiles = data.files || {};
    currentName  = f.name;
    render();
  } catch(e){
    fstate.textContent = 'error';
    fill.style.width = '100%';
    err.textContent = '[error] ' + e.message;
    err.hidden = false;
  }
}

function render(){
  const names = Object.keys(currentFiles);
  if (!names.length){
    err.textContent = '[warn] decompiler returned nothing';
    err.hidden = false;
    return;
  }
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
