package main

// Updates.
//
//   - The helper checks <site>/download/version.json at start and every few hours. A newer
//     version is downloaded in the background into %LOCALAPPDATA%\EZLARP\update ("staged"),
//     checked against its SHA-256 and size, and the page shows "Restart to update".
//   - Clicking it swaps the new exe in and restarts the helper with the same page token, so the
//     app window stays open. Anything staged and not applied yet is applied automatically the
//     next time EZLARP starts.
//   - Swapping never overwrites: the running exe is renamed out of the way under a unique name
//     (a running exe can be renamed but not replaced), the new one is moved in, and leftovers are
//     deleted on later starts. Every step retries for a few seconds, and if the exe is still
//     locked the running EZLARP is asked to quit (or closed) first.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type remoteVersion struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	checked time.Time
}

// what the page sees at GET /update
type updState struct {
	State    string `json:"state"` // idle, downloading, ready, applying, error
	Progress int    `json:"progress"`
	Error    string `json:"error,omitempty"`
}

var httpc = &http.Client{Timeout: 10 * time.Minute}

func fetchVersion() (remoteVersion, error) {
	var v remoteVersion
	c := &http.Client{Timeout: 20 * time.Second}
	res, err := c.Get(siteURL + "/download/version.json")
	if err != nil {
		return v, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return v, fmt.Errorf("version check: HTTP %d", res.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&v)
	v.checked = time.Now()
	if err == nil && (len(v.SHA256) != 64 || v.Version == "") {
		err = errors.New("version.json is incomplete")
	}
	return v, err
}

// "1.10.0" > "1.9.2"
func newer(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 4; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// ---------------------------------------------------------------- background check + download

func (h *helper) setUpd(s updState) {
	h.mu.Lock()
	h.upd = s
	h.mu.Unlock()
}

func (h *helper) checkUpdate() {
	for {
		h.checkOnce()
		time.Sleep(4 * time.Hour)
	}
}

func (h *helper) checkOnce() {
	v, err := fetchVersion()
	if err != nil {
		return
	}
	h.mu.Lock()
	h.update = v
	busy := h.upd.State == "downloading" || h.upd.State == "applying"
	h.mu.Unlock()
	if busy || !newer(v.Version, Version) {
		return
	}
	if _, err := h.stage(v); err != nil {
		h.setUpd(updState{State: "error", Error: err.Error()})
	}
}

func stageDir() string {
	d := filepath.Join(dataDir(), "update")
	_ = os.MkdirAll(d, 0o700)
	return d
}

type staged struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	File    string `json:"file"`
}

// downloads v into the update folder (once) and returns its path
func (h *helper) stage(v remoteVersion) (string, error) {
	dir := stageDir()
	p := filepath.Join(dir, "EZLARP-"+v.Version+".exe")
	if s, err := readStaged(); err == nil && s.Version == v.Version && strings.EqualFold(fileSHA(s.File), v.SHA256) {
		h.setUpd(updState{State: "ready", Progress: 100})
		return s.File, nil
	}
	h.setUpd(updState{State: "downloading"})
	res, err := httpc.Get(siteURL + "/download/EZLARP-Setup.exe")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("download: HTTP %d", res.StatusCode)
	}
	part := p + ".part"
	out, err := os.Create(part)
	if err != nil {
		return "", err
	}
	total := v.Size
	if total <= 0 {
		total = res.ContentLength
	}
	sum := sha256.New()
	pw := &progressWriter{total: total, on: func(pct int) { h.setUpd(updState{State: "downloading", Progress: pct}) }}
	n, err := io.Copy(io.MultiWriter(out, sum, pw), io.LimitReader(res.Body, 200<<20))
	out.Close()
	if err != nil {
		os.Remove(part)
		return "", err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); !strings.EqualFold(got, v.SHA256) || (v.Size > 0 && n != v.Size) {
		os.Remove(part)
		return "", errors.New("the download didn't match its checksum, so it was thrown away")
	}
	_ = os.Remove(p)
	if err := os.Rename(part, p); err != nil {
		return "", err
	}
	_ = os.Chmod(p, 0o755)
	b, _ := json.Marshal(staged{Version: v.Version, SHA256: strings.ToLower(v.SHA256), File: p})
	_ = os.WriteFile(filepath.Join(dir, "staged.json"), b, 0o600)
	// older staged versions are no longer needed
	if items, err := os.ReadDir(dir); err == nil {
		for _, it := range items {
			if n := it.Name(); strings.HasPrefix(n, "EZLARP-") && filepath.Join(dir, n) != p {
				_ = os.Remove(filepath.Join(dir, n))
			}
		}
	}
	h.setUpd(updState{State: "ready", Progress: 100})
	return p, nil
}

type progressWriter struct {
	total, done int64
	last        int
	on          func(int)
}

func (w *progressWriter) Write(b []byte) (int, error) {
	w.done += int64(len(b))
	if w.total > 0 {
		if pct := int(w.done * 100 / w.total); pct != w.last {
			w.last = pct
			w.on(pct)
		}
	}
	return len(b), nil
}

func readStaged() (staged, error) {
	var s staged
	b, err := os.ReadFile(filepath.Join(stageDir(), "staged.json"))
	if err == nil {
		err = json.Unmarshal(b, &s)
	}
	return s, err
}

func fileSHA(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------- applying

// POST /update: apply what's staged now (download first if needed), then restart the helper
func (h *helper) startUpdate() {
	h.mu.Lock()
	st := h.upd.State
	h.mu.Unlock()
	if st == "downloading" || st == "applying" {
		return
	}
	go func() {
		v, err := fetchVersion()
		if err == nil && !newer(v.Version, Version) {
			err = errors.New("already up to date")
		}
		var p string
		if err == nil {
			p, err = h.stage(v)
		}
		if err == nil {
			h.setUpd(updState{State: "applying", Progress: 100})
			err = h.applyStaged(p)
		}
		if err != nil {
			h.setUpd(updState{State: "error", Error: err.Error()})
			return
		}
		time.Sleep(400 * time.Millisecond)
		os.Exit(0)
	}()
}

func (h *helper) applyStaged(p string) error {
	s, err := readStaged()
	if err != nil || s.File != p || !strings.EqualFold(fileSHA(p), s.SHA256) {
		return errors.New("the downloaded update is damaged; it will be downloaded again")
	}
	self := selfPath()
	if self == "" {
		return errors.New("can't find this exe")
	}
	if err := swapIn(p, self); err != nil {
		return err
	}
	clearStaged()
	c := exec.Command(self, "--updated", "--no-window")
	c.Env = append(os.Environ(), "EZLARP_TOKEN="+h.token)
	if err := c.Start(); err != nil {
		return fmt.Errorf("installed, but could not restart: %v (open EZLARP again)", err)
	}
	return nil
}

func clearStaged() {
	dir := stageDir()
	if s, err := readStaged(); err == nil {
		_ = os.Remove(s.File)
	}
	_ = os.Remove(filepath.Join(dir, "staged.json"))
}

// Run at start: an update downloaded earlier and not applied yet is applied now, before
// anything opens, and the new exe is started with the same arguments. Returns true if it did.
func applyPendingOnStart() bool {
	s, err := readStaged()
	if err != nil || !newer(s.Version, Version) {
		if err == nil {
			clearStaged() // same or older than what's running
		}
		return false
	}
	if !strings.EqualFold(fileSHA(s.File), s.SHA256) {
		clearStaged()
		return false
	}
	self := selfPath()
	if self == "" || swapIn(s.File, self) != nil {
		return false
	}
	clearStaged()
	c := exec.Command(self, os.Args[1:]...)
	c.Env = os.Environ()
	return c.Start() == nil
}

// swapIn puts src in place of dst without ever overwriting a file that may be running.
func swapIn(src, dst string) error {
	dir, base := filepath.Dir(dst), filepath.Base(dst)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	tmp := filepath.Join(dir, stem+".new-"+newToken()[:8]+ext)
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o755)
	if _, err := os.Stat(dst); err == nil {
		old := filepath.Join(dir, stem+".old-"+newToken()[:8]+ext)
		if err := retry(func() error { return os.Rename(dst, old) }); err != nil {
			os.Remove(tmp)
			return err
		}
		if err := retry(func() error { return os.Rename(tmp, dst) }); err != nil {
			_ = os.Rename(old, dst)
			os.Remove(tmp)
			return err
		}
		_ = os.Remove(old) // works on Linux; on Windows it's still running and goes on the next start
		return nil
	}
	if err := retry(func() error { return os.Rename(tmp, dst) }); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func retry(f func() error) error {
	var err error
	for i := 0; i < 12; i++ {
		if err = f(); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return err
}

// leftovers from earlier swaps: EZLARP.old-xxxx.exe, EZLARP.new-xxxx.exe, EZLARP.old.exe
func cleanupOldExe() {
	self := selfPath()
	if self == "" {
		return
	}
	go func() {
		time.Sleep(3 * time.Second)
		dir, base := filepath.Dir(self), filepath.Base(self)
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		for _, pat := range []string{stem + ".old-*" + ext, stem + ".new-*" + ext, stem + ".old" + ext} {
			m, _ := filepath.Glob(filepath.Join(dir, pat))
			for _, f := range m {
				_ = os.Remove(f)
			}
		}
	}()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

// ---------------------------------------------------------------- the running app

func appRunning() bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", Port), 400*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// asks a running EZLARP to quit (1.1.0 and later), then closes it if it won't
func stopRunningApp() {
	if !appRunning() {
		return
	}
	if b, err := os.ReadFile(filepath.Join(dataDir(), "helper-token")); err == nil {
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/quit", Port), nil)
		req.Header.Set("X-EZLARP-Token", strings.TrimSpace(string(b)))
		if res, err := (&http.Client{Timeout: 3 * time.Second}).Do(req); err == nil {
			res.Body.Close()
		}
	}
	for i := 0; i < 12 && appRunning(); i++ {
		time.Sleep(250 * time.Millisecond)
	}
	if appRunning() {
		killInstalledApp()
		for i := 0; i < 12 && appRunning(); i++ {
			time.Sleep(250 * time.Millisecond)
		}
	}
	time.Sleep(300 * time.Millisecond) // let Windows release the exe
}

// the updated helper waits for the old one to let go of the port
func listenRetry(wait bool) (net.Listener, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", Port)
	deadline := time.Now().Add(15 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil || !wait || time.Now().After(deadline) {
			return ln, err
		}
		time.Sleep(250 * time.Millisecond)
	}
}
