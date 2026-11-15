# EZLARP

jar / class decompiler &middot; Vineflower engine &middot; slim black UI
**100% in-browser &middot; no backend &middot; no account anywhere but GitHub + Cloudflare**

## How it works

```
  browser
    |
    +-- loads public/ (static HTML/CSS/JS)
    +-- loads CheerpJ 3 runtime (JVM-in-WASM, ~10 MB, cached)
    +-- loads /vineflower.jar (1.8 MB, cached)
    +-- user drops a .jar
    +-- vineflower runs in the browser's virtual JVM
    +-- output is unzipped with JSZip in the browser
    +-- .java source files render in the UI

  nothing ever leaves the user's machine.
```

Zero servers. The entire decompiler runs client-side.

## Architecture (free, trusted, git-deployed)

- Source lives in: https://github.com/DDLOK/EZLARP
- Static files served by: **Cloudflare Pages** (free, unlimited bandwidth, CDN)
- Deploys triggered by: **GitHub Actions** &rarr; `wrangler pages deploy`
- Alternative: Cloudflare Pages git-connect also redeploys on push (pick one, not both)

## Deploy

### Option 1: Cloudflare Pages git-connect (easiest, zero setup)

1. Dashboard &rarr; **Workers & Pages** &rarr; **Create** &rarr; **Pages** &rarr; **Connect to Git** &rarr; pick `DDLOK/EZLARP`.
2. Build settings:
   - Build command: *(blank)*
   - Build output directory: `public`
3. **Save and Deploy**.

That's it. Every `git push main` auto-redeploys.

### Option 2: GitHub Actions (if you want deploy pipelines in-repo)

The workflow at `.github/workflows/deploy.yml` deploys to Cloudflare Pages
on every push to `main`. One-time secret setup in your GitHub repo:

- Settings &rarr; Secrets and variables &rarr; Actions &rarr; **New repository secret**:
  - `CLOUDFLARE_API_TOKEN` &mdash; create at https://dash.cloudflare.com/profile/api-tokens with the "Edit Cloudflare Workers" template
  - `CLOUDFLARE_ACCOUNT_ID` &mdash; `e3fcc3146ae0b5a2e2470687a8dcde48`

Then `git push` and GitHub Actions deploys.

## Local dev

```
npm install
npm run dev
```

Opens on http://localhost:8788.

## Notes

- First visit downloads ~10 MB of CheerpJ runtime. Cached after that &mdash; subsequent loads are fast.
- First decompile per session takes a few seconds extra (JVM cold start inside the WASM runtime).
- Huge jars (&gt;50 MB) may lag; browser memory is the ceiling, usually fine up to a few hundred MB.
- Nothing is uploaded anywhere. The jar never leaves the user's device.
