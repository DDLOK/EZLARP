# EZLARP for Windows

`EZLARP-Setup.exe` (built from this folder) is the installer and the app in one file.

- **First run** asks to install for the current user (no admin): Start menu and desktop
  shortcuts, **Scan with EZLARP** in the right-click menu of .jar/.exe/.dll/.apk/.class/.mrpack/.dex
  files, and an entry in Settings → Apps to uninstall.
- **The app** opens EZLARP in its own window (Edge or Chrome in app mode, own profile, so the
  Discord login sticks) and runs a helper on `127.0.0.1:47613` that gives that page the files you
  open and the jars in your Minecraft mods folders (vanilla, Prism, CurseForge, Modrinth). The
  helper needs a random per-run token and only answers https://ezlarp.pages.dev. Files are never
  uploaded.
- The app requires a Discord login (when login is set up on the site).
- **Updates**: the helper reads `/download/version.json`; the status bar shows "Update to x.y.z". Clicking it
  downloads the new exe, checks its SHA-256 and size, swaps it for the running one (the old one is renamed and
  deleted on the next start), and restarts the helper with the same page token, so the window stays open.
  To ship an update: bump `Version` in `main.go`, delete `rsrc_windows_amd64.syso`, run `./build.sh`, push.
- The window uses the VS Code layout (`public/ide.js`).

Build: `./build.sh` (Go 1.22+, no other dependencies). It writes `public/download/EZLARP-Setup.exe`
and `version.json`. `winres.py` makes the icon/version/manifest resource (`rsrc_windows_amd64.syso`).

Test on Linux: `go build -o ezlarp . && EZLARP_ORIGINS=http://127.0.0.1:8799 ./ezlarp --no-window some.jar`.
