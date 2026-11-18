//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Non-Windows builds run the same helper and open the page in the default browser.
// They're used for testing; the installer is Windows-only.

func afterUpdate()      {}
func killInstalledApp() {}

func selfPath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return p
}

func osName() string                                { return runtime.GOOS }
func fail(msg string)                               { fmt.Fprintln(os.Stderr, msg) }
func shouldOfferInstall() bool                      { return false }
func runInstaller(silent bool, files []string) bool { return false }
func runUninstall()                                 { fmt.Println("nothing to uninstall on " + runtime.GOOS) }

func openWindow(u string) {
	cmd := "xdg-open"
	if runtime.GOOS == "darwin" {
		cmd = "open"
	}
	if err := exec.Command(cmd, u).Start(); err != nil {
		fmt.Println("open this in your browser:", u)
	}
}
