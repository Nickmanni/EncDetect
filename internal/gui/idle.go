package gui

import (
	"os"
	"time"
)

// waitIdle beendet den Browser-Modus, sobald die Seite länger als 60 s keine
// Anfragen mehr stellt (Tab geschlossen).
func waitIdle(s *Server) {
	limit := 60 * time.Second
	if os.Getenv("ENCDETECT_KEEP_RUNNING") != "" {
		select {}
	}
	for {
		time.Sleep(5 * time.Second)
		if s.IdleSince() > limit {
			return
		}
	}
}
