# EZLARP

jar / class decompiler &middot; Vineflower engine &middot; slim black UI

## Architecture (free, git-deployed)

```
  browser -> Cloudflare Pages (free)
              |
              +-- public/*               static frontend
              +-- /api/decompile         Pages Function proxy
                        |
                        v
             Render Web Service (free tier)
                  Node + Vineflower + Java 17
```

Both halves live in this one repo. A `git push` to `main` auto-redeploys
both ends &mdash; Cloudflare Pages (reads `wrangler.toml`) and Render
(reads `render.yaml`).

## One-time setup

### 1. Push to GitHub
Already done: https://github.com/DDLOK/EZLARP

### 2. Set up the backend on Render
1. Go to https://dashboard.render.com &rarr; **New** &rarr; **Blueprint**.
2. Connect the `DDLOK/EZLARP` repo. Render reads `render.yaml`, proposes
   a `ezlarp-backend` Docker service.
3. For `BACKEND_KEY` enter any long random string. Keep a copy &mdash; you'll
   paste the same value into Cloudflare Pages below.
4. Click **Apply**. First build takes ~5 min (Java 17 + Node install).
5. Grab the public URL &mdash; e.g. `https://ezlarp-backend.onrender.com`.

Free-tier caveat: the service sleeps after 15 min idle, cold-starts in
~40-60 s on the next request.

### 3. Set up the frontend on Cloudflare Pages
1. Dashboard &rarr; **Workers & Pages** &rarr; **Create** &rarr; **Pages** &rarr;
   **Connect to Git** &rarr; pick `DDLOK/EZLARP`.
2. Build settings:
   - Framework preset: **None**
   - Build command: *(leave blank)*
   - Build output directory: `public`
   - Root directory: `/`
3. **Settings &rarr; Environment variables** &rarr; add both to Production:
   - `BACKEND_URL` = the Render URL from step 2.5
   - `BACKEND_KEY` = the same key you set on Render
4. **Save and Deploy**.

Pages gives you `https://ezlarp.pages.dev` (or similar). Done.

## Updating

```
git add .
git commit -m "..."
git push
```

Both Pages and Render redeploy on the push.

## Notes
- The first jar you drop after a long idle period triggers Render's
  cold start &mdash; the UI will show `decompiling` for ~40-60 s, then normal.
- Frontend upload cap: 100 MB (Pages Function limit). Backend caps at
  25 MB (`MAX_BYTES` in `server.js`).
- If you later upgrade to Render paid ($7/mo) the service stops sleeping
  and cold starts disappear.
