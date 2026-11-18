package main

// Self-update: the helper reads <site>/download/version.json, and when the page asks it to,
// downloads the new EZLARP-Setup.exe, checks its SHA-256, swaps it in for the running exe
// (a running exe can be renamed, not overwritten) and restarts with the same page token.

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

var httpc = &http.Client{Timeout: 2 * time.Minute}

func fetchVersion() (remoteVersion, error) {
	var v remoteVersion
	res, err := httpc.Get(siteURL + "/download/version.json")
	if err != nil {
		return v, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return v, fmt.Errorf("version check: HTTP %d", res.StatusCode)
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 1<<16)).Decode(&v)
	v.checked = time.Now()
	return v, err
}

func (h *helper) checkUpdate() {
	for {
		if v, err := fetchVersion(); err == nil {
			h.mu.Lock()
			h.update = v
			h.mu.Unlock()
		}
		time.Sleep(6 * time.Hour)
	}
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

func (h *helper) applyUpdate() error {
	v, err := fetchVersion()
	if err != nil {
		return err
	}
	if !newer(v.Version, Version) {
		return errors.New("already up to date")
	}
	if len(v.SHA256) != 64 {
		return errors.New("version.json has no sha256")
	}
	self := selfPath()
	if self == "" {
		return errors.New("can't find this exe")
	}
	res, err := httpc.Get(siteURL + "/download/EZLARP-Setup.exe")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("download: HTTP %d", res.StatusCode)
	}
	tmp := self + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, sum), io.LimitReader(res.Body, 200<<20))
	out.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); !strings.EqualFold(got, v.SHA256) || (v.Size > 0 && n != v.Size) {
		os.Remove(tmp)
		return errors.New("download didn't match its checksum; nothing was changed")
	}
	_ = os.Chmod(tmp, 0o755)
	old := oldExePath(self)
	_ = os.Remove(old)
	if err := os.Rename(self, old); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, self); err != nil {
		_ = os.Rename(old, self)
		return err
	}
	c := exec.Command(self, "--updated", "--no-window")
	c.Env = append(os.Environ(), "EZLARP_TOKEN="+h.token)
	if err := c.Start(); err != nil {
		_ = os.Rename(self, tmp)
		_ = os.Rename(old, self)
		return err
	}
	return nil
}

func oldExePath(self string) string {
	ext := filepath.Ext(self)
	return strings.TrimSuffix(self, ext) + ".old" + ext
}

func cleanupOldExe() {
	if self := selfPath(); self != "" {
		go func() { time.Sleep(5 * time.Second); _ = os.Remove(oldExePath(self)) }()
	}
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
