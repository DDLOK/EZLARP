import express from 'express';
import multer from 'multer';
import AdmZip from 'adm-zip';
import cors from 'cors';
import { execFile } from 'child_process';
import { mkdtemp, rm, readFile, readdir, stat, writeFile, mkdir } from 'fs/promises';
import { tmpdir } from 'os';
import path from 'path';

const PORT       = process.env.PORT || 8787;
const KEY        = process.env.BACKEND_KEY || '';
const VINEFLOWER = process.env.VINEFLOWER || path.resolve('vineflower.jar');
const MAX_BYTES  = 25 * 1024 * 1024;
const MAX_FILES  = 400;

const app = express();
app.use(cors({ origin: true }));
const upload = multer({ limits: { fileSize: MAX_BYTES } });

app.get('/health', (_, res) => res.json({ ok: true, v: '0.1' }));

app.post('/decompile', upload.single('file'), async (req, res) => {
  if (KEY && req.headers['x-ezlarp-key'] !== KEY) return res.status(401).send('unauthorized');
  if (!req.file) return res.status(400).send('no file');

  const work   = await mkdtemp(path.join(tmpdir(), 'ezlarp-'));
  const safe   = req.file.originalname.replace(/[^\w.\-]/g, '_');
  const inPath = path.join(work, safe);
  const outDir = path.join(work, 'out');

  try {
    await writeFile(inPath, req.file.buffer);
    await mkdir(outDir, { recursive: true });

    await execFileP('java', [
      '-jar', VINEFLOWER,
      '--silent=1',
      inPath, outDir
    ], { timeout: 60_000 });

    const files = {};
    if (inPath.toLowerCase().endsWith('.jar')) {
      const outJar = path.join(outDir, path.basename(inPath));
      await collectFromJar(outJar, files);
    } else {
      await collectFromDir(outDir, outDir, files);
    }

    res.json({ files });
  } catch (e) {
    const msg = (e && e.stderr) ? e.stderr.toString() : (e.message || String(e));
    res.status(500).send(msg.slice(0, 2000));
  } finally {
    rm(work, { recursive: true, force: true }).catch(() => {});
  }
});

function execFileP(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, opts, (err, stdout, stderr) => {
      if (err) { err.stderr = stderr; return reject(err); }
      resolve({ stdout, stderr });
    });
  });
}

async function collectFromJar(jarPath, out) {
  const zip = new AdmZip(jarPath);
  const entries = zip.getEntries().filter(e => e.entryName.endsWith('.java'));
  entries.slice(0, MAX_FILES).forEach(e => {
    out[e.entryName] = zip.readAsText(e);
  });
}

async function collectFromDir(root, dir, out) {
  const items = await readdir(dir);
  for (const name of items) {
    const full = path.join(dir, name);
    const st = await stat(full);
    if (st.isDirectory()) {
      await collectFromDir(root, full, out);
    } else if (name.endsWith('.java')) {
      const rel = path.relative(root, full).replace(/\\/g, '/');
      out[rel] = await readFile(full, 'utf8');
      if (Object.keys(out).length >= MAX_FILES) return;
    }
  }
}

app.listen(PORT, () => console.log(`[ezlarp] backend on :${PORT}`));
