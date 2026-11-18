// EZLARP desktop app.
//
// Opens EZLARP in its own app window (Edge or Chrome in app mode, with its own profile so the
// Discord login sticks) and runs a small helper on 127.0.0.1 that hands the page the files you
// open with "Scan with EZLARP" or from your Minecraft mods folder. Files never leave the PC:
// the helper only talks to the EZLARP page in the app window, and only with a per-run token.
//
// The same exe is the installer: run from anywhere else, it offers to install itself for the
// current user (no admin needed).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	Version = "1.2.0"
	Port    = 47613
)

var (
	siteURL = envOr("EZLARP_SITE", "https://ezlarp.pages.dev")
	// how long the helper waits for the page before quitting
	idleTimeout = 3 * time.Minute
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return strings.TrimRight(v, "/")
	}
	return def
}

func main() {
	uninstall := flag.Bool("uninstall", false, "remove EZLARP from this PC")
	install := flag.Bool("install", false, "install without asking")
	portable := flag.Bool("portable", false, "run without installing")
	noWindow := flag.Bool("no-window", false, "only run the helper (for testing)")
	updated := flag.Bool("updated", false, "started by the updater")
	flag.Parse()
	files := flag.Args()

	if *uninstall {
		runUninstall()
		return
	}
	if *install || (!*portable && !*noWindow && shouldOfferInstall()) {
		if done := runInstaller(*install, files); done {
			return
		}
	}

	// an update downloaded last time is installed now, before anything opens
	if !*updated && applyPendingOnStart() {
		return
	}
	cleanupOldExe()
	token := newToken()
	// after an update the page keeps its token, so the new helper reuses it
	if t := os.Getenv("EZLARP_TOKEN"); *updated && len(t) == 48 {
		token = t
		os.Unsetenv("EZLARP_TOKEN")
		afterUpdate()
	}
	ln, err := listenRetry(*updated)
	if err != nil {
		// another EZLARP is already running: hand it the files and quit
		if handOff(files) {
			return
		}
		fail("EZLARP could not start its helper on port " + fmt.Sprint(Port) + ".\n\n" + err.Error())
		return
	}
	h := newHelper(token)
	saveToken(token)
	go h.checkUpdate()
	ids := h.addFiles(files)
	go func() {
		if !*noWindow {
			openWindow(h.pageURL(ids))
		}
	}()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go h.watchIdle(srv)
	_ = srv.Serve(ln)
}

// ---------------------------------------------------------------- helper server

type entry struct {
	Path string `json:"-"`
	ID   string `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type helper struct {
	token    string
	update   remoteVersion
	upd      updState
	mu       sync.Mutex
	files    map[string]entry
	lastSeen time.Time
}

func newHelper(token string) *helper {
	return &helper{token: token, files: map[string]entry{}, lastSeen: time.Now()}
}

func (h *helper) pageURL(ids []string) string {
	frag := "app=" + h.token
	if len(ids) > 0 {
		frag += "&open=" + strings.Join(ids, ",")
	}
	return siteURL + "/?app=1#" + frag
}

func (h *helper) addFiles(paths []string) []string {
	var ids []string
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		st, err := os.Stat(abs)
		if err != nil || st.IsDir() {
			continue
		}
		ids = append(ids, h.add(abs, st.Size()))
	}
	return ids
}

func (h *helper) add(path string, size int64) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, e := range h.files {
		if e.Path == path {
			return id
		}
	}
	id := newToken()[:12]
	h.files[id] = entry{Path: path, ID: id, Name: filepath.Base(path), Size: size}
	return id
}

func (h *helper) watchIdle(srv *http.Server) {
	for {
		time.Sleep(15 * time.Second)
		h.mu.Lock()
		idle := time.Since(h.lastSeen)
		h.mu.Unlock()
		if idle > idleTimeout {
			_ = srv.Close()
			os.Exit(0)
		}
	}
}

var allowedOrigins = func() map[string]bool {
	m := map[string]bool{siteURL: true}
	if extra := os.Getenv("EZLARP_ORIGINS"); extra != "" {
		for _, o := range strings.Split(extra, ",") {
			m[strings.TrimRight(strings.TrimSpace(o), "/")] = true
		}
	}
	return m
}()

func (h *helper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !allowedOrigins[origin] {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Headers", "X-EZLARP-Token, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		w.Header().Set("Access-Control-Expose-Headers", "X-EZLARP-Name")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	tok := r.Header.Get("X-EZLARP-Token")
	if tok == "" {
		tok = r.URL.Query().Get("t")
	}
	if len(tok) != len(h.token) || tok != h.token {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	h.mu.Lock()
	h.lastSeen = time.Now()
	h.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")

	switch {
	case r.URL.Path == "/ping":
		writeJSON(w, map[string]any{"ok": true, "version": Version, "os": osName()})
	case r.URL.Path == "/update":
		if r.Method == http.MethodPost {
			h.startUpdate()
		} else if r.URL.Query().Get("check") == "1" {
			h.checkOnce()
		}
		h.mu.Lock()
		u, st := h.update, h.upd
		h.mu.Unlock()
		if st.State == "" {
			st.State = "idle"
		}
		writeJSON(w, map[string]any{"current": Version, "latest": u.Version, "available": u.Version != "" && newer(u.Version, Version),
			"checked": !u.checked.IsZero(), "state": st.State, "progress": st.Progress, "error": st.Error})
	case r.URL.Path == "/quit" && r.Method == http.MethodPost:
		writeJSON(w, map[string]any{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); os.Exit(0) }()
	case r.URL.Path == "/files":
		h.mu.Lock()
		list := make([]entry, 0, len(h.files))
		for _, e := range h.files {
			list = append(list, e)
		}
		h.mu.Unlock()
		writeJSON(w, list)
	case strings.HasPrefix(r.URL.Path, "/f/"):
		id := strings.TrimPrefix(r.URL.Path, "/f/")
		h.mu.Lock()
		e, ok := h.files[id]
		h.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(e.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-EZLARP-Name", url.PathEscape(e.Name))
		_, _ = io.Copy(w, io.LimitReader(f, 1<<30))
	case r.URL.Path == "/mods":
		dirs := modsDirs()
		var list []entry
		for _, d := range dirs {
			items, err := os.ReadDir(d)
			if err != nil {
				continue
			}
			for _, it := range items {
				n := strings.ToLower(it.Name())
				if it.IsDir() || !(strings.HasSuffix(n, ".jar") || strings.HasSuffix(n, ".jar.disabled")) {
					continue
				}
				info, err := it.Info()
				if err != nil {
					continue
				}
				p := filepath.Join(d, it.Name())
				list = append(list, entry{ID: h.add(p, info.Size()), Name: it.Name(), Size: info.Size()})
			}
		}
		sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name) })
		writeJSON(w, map[string]any{"dirs": dirs, "files": list})
	case r.URL.Path == "/open" && r.Method == http.MethodPost:
		// a second EZLARP.exe passing on the files it was started with
		var req struct {
			Files []string `json:"files"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ids := h.addFiles(req.Files)
		go openWindow(h.pageURL(ids))
		writeJSON(w, map[string]any{"ok": true, "opened": len(ids)})
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Minecraft mods folders: the vanilla launcher plus the common third-party launchers
func modsDirs() []string {
	var out []string
	add := func(p string) {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			out = append(out, p)
		}
	}
	appdata := os.Getenv("APPDATA")
	home, _ := os.UserHomeDir()
	if appdata != "" {
		add(filepath.Join(appdata, ".minecraft", "mods"))
	}
	if home != "" {
		add(filepath.Join(home, ".minecraft", "mods"))
		add(filepath.Join(home, "Library", "Application Support", "minecraft", "mods"))
	}
	// Prism / MultiMC / CurseForge / Modrinth instances
	var roots []string
	if appdata != "" {
		roots = append(roots, filepath.Join(appdata, "PrismLauncher", "instances"), filepath.Join(appdata, "ModrinthApp", "profiles"),
			filepath.Join(appdata, "com.modrinth.theseus", "profiles"))
	}
	if home != "" {
		roots = append(roots, filepath.Join(home, "curseforge", "minecraft", "Instances"))
	}
	for _, root := range roots {
		items, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, it := range items {
			if !it.IsDir() {
				continue
			}
			add(filepath.Join(root, it.Name(), "mods"))
			add(filepath.Join(root, it.Name(), ".minecraft", "mods"))
			add(filepath.Join(root, it.Name(), "minecraft", "mods"))
		}
	}
	return out
}

// ---------------------------------------------------------------- single instance

func dataDir() string {
	base, err := os.UserCacheDir() // %LOCALAPPDATA% on Windows
	if err != nil {
		base = os.TempDir()
	}
	d := filepath.Join(base, "EZLARP")
	_ = os.MkdirAll(d, 0o700)
	return d
}

func saveToken(t string) {
	_ = os.WriteFile(filepath.Join(dataDir(), "helper-token"), []byte(t), 0o600)
}

func handOff(files []string) bool {
	b, err := os.ReadFile(filepath.Join(dataDir(), "helper-token"))
	if err != nil {
		return false
	}
	var abs []string
	for _, f := range files {
		if a, err := filepath.Abs(f); err == nil {
			abs = append(abs, a)
		}
	}
	body, _ := json.Marshal(map[string]any{"files": abs})
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/open", Port), strings.NewReader(string(body)))
	req.Header.Set("X-EZLARP-Token", strings.TrimSpace(string(b)))
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: 5 * time.Second}
	res, err := c.Do(req)
	if err != nil {
		return false
	}
	res.Body.Close()
	return res.StatusCode == http.StatusOK
}

func newToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

var errCancelled = errors.New("cancelled")
