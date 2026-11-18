//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	mbOK          = 0x0
	mbYesNoCancel = 0x3
	mbYesNo       = 0x4
	mbIconError   = 0x10
	mbIconQ       = 0x20
	mbIconInfo    = 0x40
	mbForeground  = 0x10000
	idYes         = 6
	idNo          = 7
	createNoWin   = 0x08000000
)

var procMessageBox = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")

func msgBox(text string, flags uint32) int {
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString("EZLARP")
	r, _, _ := procMessageBox.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), uintptr(flags|mbForeground))
	return int(r)
}

func osName() string { return "windows" }

func fail(msg string) { msgBox(msg, mbOK|mbIconError) }

func installDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserCacheDir()
	}
	return filepath.Join(base, "Programs", "EZLARP")
}
func installedExe() string { return filepath.Join(installDir(), "EZLARP.exe") }

// after a self-update: keep Settings → Apps in step with the new version
func afterUpdate() {
	if !shouldOfferInstall() {
		_ = hidden("reg", "add", `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\EZLARP`, "/v", "DisplayVersion", "/t", "REG_SZ", "/d", Version, "/f")
	}
}

func selfPath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}

func shouldOfferInstall() bool {
	return !strings.EqualFold(filepath.Clean(selfPath()), filepath.Clean(installedExe()))
}

func hidden(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWin}
	return c.Run()
}

// returns true when this process should exit (installed and relaunched, or cancelled)
func runInstaller(silent bool, files []string) bool {
	_, err := os.Stat(installedExe())
	update := err == nil
	if update {
		if v := installedVersion(); v != "" && v == Version && !silent {
			// same version: nothing to install, just open it
			if msgBox("EZLARP "+Version+" is already installed.\n\nYes = open it   ·   No = reinstall it", mbYesNo|mbIconInfo) == idYes {
				_ = exec.Command(installedExe(), files...).Start()
				return true
			}
		}
	}
	if !silent {
		q := "Install EZLARP on this PC?\n\n" +
			"• Adds EZLARP to the Start menu and desktop\n" +
			"• Adds \"Scan with EZLARP\" when you right-click .jar, .exe, .dll, .apk, .class and .mrpack files\n" +
			"• Installs just for you, no admin needed. Remove it any time from Settings → Apps.\n\n" +
			"Yes = install   ·   No = just run it this once"
		if update {
			from := installedVersion()
			if from == "" {
				from = "your version"
			}
			q = "Update EZLARP " + from + " → " + Version + "?\n\nIf EZLARP is open it closes and reopens by itself.\n\nYes = update   ·   No = just run this copy once"
		}
		switch msgBox(q, mbYesNoCancel|mbIconQ) {
		case idYes:
		case idNo:
			return false
		default:
			return true
		}
	}
	if err := install(); err != nil {
		fail("EZLARP could not be installed:\n\n" + err.Error() + "\n\nIt will run without installing this time.")
		return false
	}
	c := exec.Command(installedExe(), files...)
	if err := c.Start(); err != nil {
		fail("EZLARP was installed but could not start:\n\n" + err.Error())
	}
	return true
}

func install() error {
	dir := installDir()
	exe := installedExe()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// the installed EZLARP may be running: ask it to quit (it reopens after), then swap
	stopRunningApp()
	if err := swapIn(selfPath(), exe); err != nil {
		killInstalledApp()
		time.Sleep(time.Second)
		if err := swapIn(selfPath(), exe); err != nil {
			return fmt.Errorf("EZLARP.exe is in use and couldn't be replaced (%v).\n\nClose every EZLARP window, or restart the PC, and run the installer again", err)
		}
	}
	clearStaged() // an update downloaded by the old version is older than this one
	// shortcuts (PowerShell knows where Desktop and Start menu really are, OneDrive included)
	ps := fmt.Sprintf(`$ws = New-Object -ComObject WScript.Shell
foreach ($d in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
  $s = $ws.CreateShortcut((Join-Path $d 'EZLARP.lnk'))
  $s.TargetPath = '%[1]s'; $s.WorkingDirectory = '%[2]s'; $s.IconLocation = '%[1]s,0'
  $s.Description = 'EZLARP: malware scanner and decompiler'; $s.Save()
}`, psq(exe), psq(dir))
	_ = hidden("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
	// right-click "Scan with EZLARP"
	for _, ext := range []string{".jar", ".exe", ".dll", ".apk", ".class", ".mrpack", ".dex"} {
		key := `HKCU\Software\Classes\SystemFileAssociations\` + ext + `\shell\EZLARP`
		_ = hidden("reg", "add", key, "/ve", "/d", "Scan with EZLARP", "/f")
		_ = hidden("reg", "add", key, "/v", "Icon", "/d", `"`+exe+`"`, "/f")
		_ = hidden("reg", "add", key+`\command`, "/ve", "/d", `"`+exe+`" "%1"`, "/f")
	}
	// Settings → Apps entry
	u := `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\EZLARP`
	size := int64(0)
	if st, err := os.Stat(exe); err == nil {
		size = st.Size() / 1024
	}
	for _, kv := range [][]string{
		{"DisplayName", "REG_SZ", "EZLARP"}, {"DisplayVersion", "REG_SZ", Version}, {"Publisher", "REG_SZ", "EZLARP"},
		{"DisplayIcon", "REG_SZ", exe}, {"UninstallString", "REG_SZ", `"` + exe + `" --uninstall`}, {"InstallLocation", "REG_SZ", dir},
		{"URLInfoAbout", "REG_SZ", siteURL}, {"NoModify", "REG_DWORD", "1"}, {"NoRepair", "REG_DWORD", "1"}, {"EstimatedSize", "REG_DWORD", fmt.Sprint(size)},
	} {
		_ = hidden("reg", "add", u, "/v", kv[0], "/t", kv[1], "/d", kv[2], "/f")
	}
	return nil
}

func runUninstall() {
	if msgBox("Remove EZLARP from this PC?\n\nThis also signs the app out (its saved login is deleted).", mbYesNo|mbIconQ) != idYes {
		return
	}
	stopRunningApp()
	for _, ext := range []string{".jar", ".exe", ".dll", ".apk", ".class", ".mrpack", ".dex"} {
		_ = hidden("reg", "delete", `HKCU\Software\Classes\SystemFileAssociations\`+ext+`\shell\EZLARP`, "/f")
	}
	_ = hidden("reg", "delete", `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\EZLARP`, "/f")
	_ = hidden("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`foreach ($d in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) { Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $d 'EZLARP.lnk') }`)
	_ = os.RemoveAll(dataDir())
	msgBox("EZLARP was removed.", mbOK|mbIconInfo)
	// the exe can't delete itself while running: let cmd do it a moment later
	c := exec.Command("cmd", "/c", "ping -n 3 127.0.0.1 >nul & rmdir /s /q \""+installDir()+"\"")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWin}
	_ = c.Start()
}

// the version Settings → Apps knows about
func installedVersion() string {
	c := exec.Command("reg", "query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\EZLARP`, "/v", "DisplayVersion")
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWin}
	out, err := c.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "DisplayVersion" {
			return f[len(f)-1]
		}
	}
	return ""
}

// closes EZLARP processes started from the install folder (not this one)
func killInstalledApp() {
	ps := fmt.Sprintf(`Get-Process | Where-Object { $_.Path -and $_.Path -like '%s\*' -and $_.Id -ne %d } | Stop-Process -Force -ErrorAction SilentlyContinue`, psq(installDir()), os.Getpid())
	_ = hidden("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps)
}

// app window: Edge or Chrome in app mode with EZLARP's own profile
func openWindow(u string) {
	pf, pf86, local := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")
	candidates := []string{
		filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`), filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(local, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(pf, `Google\Chrome\Application\chrome.exe`), filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(local, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(pf, `BraveSoftware\Brave-Browser\Application\brave.exe`), filepath.Join(local, `BraveSoftware\Brave-Browser\Application\brave.exe`),
	}
	profile := filepath.Join(dataDir(), "browser")
	for _, b := range candidates {
		if st, err := os.Stat(b); err == nil && !st.IsDir() {
			c := exec.Command(b, "--app="+u, "--user-data-dir="+profile, "--window-size=1320,900", "--no-first-run", "--no-default-browser-check")
			if c.Start() == nil {
				return
			}
		}
	}
	// no Chromium browser: default browser in a normal tab
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
}

// single-quote escaping for PowerShell strings
func psq(s string) string { return strings.ReplaceAll(s, "'", "''") }
