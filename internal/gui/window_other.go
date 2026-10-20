//go:build !windows

package gui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Run startet unter Nicht-Windows-Systemen den Server und öffnet den Browser.
func Run(s *Server) {
	go s.Serve()
	fmt.Fprintf(os.Stderr, "EncDetect läuft unter: %s\n", s.URL)
	if os.Getenv("ENCDETECT_NO_BROWSER") == "" {
		cmd := "xdg-open"
		if runtime.GOOS == "darwin" {
			cmd = "open"
		}
		exec.Command(cmd, s.URL).Start()
	}
	waitIdle(s)
}
