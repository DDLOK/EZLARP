# EZLARP

jar / class decompiler &middot; Vineflower engine &middot; slim black UI &middot; **100% Cloudflare**

```
ezlarp/
  src/worker.js         # Worker: routes /api/* -> container, else -> static assets
  public/               # static frontend (served via Workers Static Assets)
    index.html style.css app.js
  backend/              # container image (Dockerfile + Node + Vineflower)
    server.js package.json Dockerfile vineflower.jar
  wrangler.toml         # Worker + Container + Assets config
  package.json
```

## Architecture

```
  browser -> Worker (edge)
              |
              +-- /api/*       -> Container (Durable Object, Docker image, scales to 0)
              |                     \__ Node + Vineflower + Java 17
              |
              +-- everything   -> Workers Static Assets (public/)
```

No separate host, no second provider. One Cloudflare account, one git repo, one deploy.
Requires **Workers Paid** ($5/month) for the Container binding.

## First-time setup (git-connected, no local Docker needed)

1. Push this folder to a **GitHub** repo.
2. Open your Cloudflare dashboard &rarr; **Workers & Pages** &rarr; **Create** &rarr; **Workers** &rarr; **Import a repository**.
3. Pick the GitHub repo. Cloudflare detects `wrangler.toml` and sets:
   - Build command: `npm install`
   - Deploy command: `npx wrangler deploy`
4. On the project **Settings &rarr; Variables and Secrets**, add:
   - `BACKEND_KEY` = any long random string (used to lock the container endpoint)
5. Click **Save and Deploy**. Cloudflare builds the Dockerfile server-side and pushes the image into their registry.
6. After the deploy, visit `https://ezlarp.<your-subdomain>.workers.dev` &mdash; drop a jar.

Every `git push` to the production branch redeploys automatically.

## Manual deploy (optional, needs local Docker)

If you'd rather deploy from your machine (requires Docker Desktop running):

```
npx wrangler login
npx wrangler secret put BACKEND_KEY
npm run deploy
```

## Local dev

Containers can be tested locally with Docker running:

```
npm run dev
```

Without Docker, you can still smoke-test the Worker's asset serving &mdash; `/api/*` calls will fail until deployed or until Docker is up.

## Notes & gotchas

- The container image is built from `backend/Dockerfile`; `backend/vineflower.jar` must exist before deploy (already present in this repo).
- `instance_type = "standard-1"` gives the JVM 1 GB RAM; bump to `standard-2` in `wrangler.toml` for huge jars.
- Container suspends after 10 min idle (`sleepAfter`), wakes in ~2&ndash;3 s on the next request.
- Max upload through the Worker is 100 MB; backend caps itself at 25 MB (`MAX_BYTES` in `server.js`).
- Rename the Worker project in Cloudflare if `ezlarp` is taken; also update `name =` in `wrangler.toml`.
