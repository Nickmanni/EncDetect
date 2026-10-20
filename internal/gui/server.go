// Package gui stellt die grafische Oberfläche bereit: einen lokalen HTTP-Server
// (nur 127.0.0.1, mit Zufallstoken) und – unter Windows – ein WebView2-Fenster.
package gui

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"encdetect/internal/detect"
	"encdetect/internal/image"
	"encdetect/internal/report"
)

//go:embed web
var webFS embed.FS

type job struct {
	running  bool
	frac     float64
	msg      string
	err      string
	rep      *detect.Report
	cancel   context.CancelFunc
	finished time.Time
}

// Server ist der lokale API-Server der Oberfläche.
type Server struct {
	Token   string
	URL     string
	Dialogs Dialogs
	initial string

	ln       net.Listener
	jobMu    sync.Mutex // schützt job
	job      job
	lastSeen time.Time
	seenMu   sync.Mutex
}

// Dialogs kapselt native Datei-Dialoge (nur unter Windows verfügbar).
type Dialogs interface {
	OpenFile() (string, error)
	SaveFile(defName, filter, ext string) (string, error)
}

func NewServer(initialPath string) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := make([]byte, 16)
	rand.Read(b)
	s := &Server{Token: hex.EncodeToString(b), ln: ln, initial: initialPath, lastSeen: time.Now()}
	s.URL = fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), s.Token)
	return s, nil
}

func (s *Server) Serve() error {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	static := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		static.ServeHTTP(w, r)
	})
	api := func(path string, h func(http.ResponseWriter, *http.Request)) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Token") != s.Token && r.URL.Query().Get("t") != s.Token {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			s.seenMu.Lock()
			s.lastSeen = time.Now()
			s.seenMu.Unlock()
			h(w, r)
		})
	}
	api("/api/info", s.handleInfo)
	api("/api/browse", s.handleBrowse)
	api("/api/analyze", s.handleAnalyze)
	api("/api/status", s.handleStatus)
	api("/api/cancel", s.handleCancel)
	api("/api/export", s.handleExport)
	api("/api/download", s.handleDownload)
	return http.Serve(s.ln, mux)
}

// IdleSince liefert die Zeit seit dem letzten API-Aufruf der Oberfläche.
func (s *Server) IdleSince() time.Duration {
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	return time.Since(s.lastSeen)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	initial := s.initial
	s.initial = ""
	writeJSON(w, map[string]any{
		"version":       detect.Version,
		"nativeDialogs": s.Dialogs != nil,
		"initialPath":   initial,
	})
}

func (s *Server) handleBrowse(w http.ResponseWriter, r *http.Request) {
	if s.Dialogs == nil {
		writeJSON(w, map[string]any{"error": "Kein Dateidialog verfügbar – bitte Pfad eingeben."})
		return
	}
	p, err := s.Dialogs.OpenFile()
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"path": p})
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	path := strings.Trim(strings.TrimSpace(req.Path), `"`)
	if path == "" {
		writeJSON(w, map[string]any{"error": "Bitte ein Image auswählen."})
		return
	}
	if st, err := os.Stat(path); err != nil {
		writeJSON(w, map[string]any{"error": "Datei nicht gefunden: " + path})
		return
	} else if st.IsDir() {
		writeJSON(w, map[string]any{"error": "Das ist ein Ordner, keine Image-Datei."})
		return
	}

	s.jobMu.Lock()
	if s.job.running {
		s.jobMu.Unlock()
		writeJSON(w, map[string]any{"error": "Es läuft bereits eine Analyse."})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.job = job{running: true, msg: "Image wird geöffnet …", cancel: cancel}
	s.jobMu.Unlock()

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				s.jobMu.Lock()
				s.job.err = fmt.Sprintf("Interner Fehler: %v", rec)
				s.job.running = false
				s.jobMu.Unlock()
			}
		}()
		img, err := image.Open(path)
		if err != nil {
			s.jobMu.Lock()
			s.job.err = err.Error()
			s.job.running = false
			s.jobMu.Unlock()
			return
		}
		defer img.Close()
		rep := detect.Analyze(ctx, img, path, func(f float64, m string) {
			s.jobMu.Lock()
			s.job.frac, s.job.msg = f, m
			s.jobMu.Unlock()
		})
		s.jobMu.Lock()
		s.job.rep = rep
		s.job.running = false
		s.job.frac = 1
		s.job.finished = time.Now()
		s.jobMu.Unlock()
	}()
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	out := map[string]any{
		"running":  s.job.running,
		"progress": s.job.frac,
		"message":  s.job.msg,
	}
	if s.job.err != "" {
		out["error"] = s.job.err
	}
	if s.job.rep != nil && !s.job.running {
		out["report"] = s.job.rep
	}
	writeJSON(w, out)
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	s.jobMu.Lock()
	if s.job.cancel != nil {
		s.job.cancel()
	}
	s.jobMu.Unlock()
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) currentReport() *detect.Report {
	s.jobMu.Lock()
	defer s.jobMu.Unlock()
	return s.job.rep
}

func renderReport(rep *detect.Report, format string) ([]byte, string, string, error) {
	var buf bytes.Buffer
	base := strings.TrimSuffix(rep.FileName, filepath.Ext(rep.FileName))
	switch format {
	case "json":
		err := report.JSON(&buf, rep)
		return buf.Bytes(), base + "_EncDetect.json", "application/json", err
	case "txt":
		report.Text(&buf, rep)
		return buf.Bytes(), base + "_EncDetect.txt", "text/plain; charset=utf-8", nil
	default:
		err := report.HTML(&buf, rep)
		return buf.Bytes(), base + "_EncDetect.html", "text/html; charset=utf-8", err
	}
}

// handleExport speichert den Bericht über den nativen Speichern-Dialog.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	rep := s.currentReport()
	if rep == nil {
		writeJSON(w, map[string]any{"error": "Noch kein Ergebnis vorhanden."})
		return
	}
	format := r.URL.Query().Get("format")
	data, name, _, err := renderReport(rep, format)
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	if s.Dialogs == nil {
		writeJSON(w, map[string]any{"download": true})
		return
	}
	filters := map[string][2]string{
		"json": {"JSON-Datei (*.json)\x00*.json\x00", "json"},
		"txt":  {"Textdatei (*.txt)\x00*.txt\x00", "txt"},
		"html": {"HTML-Bericht (*.html)\x00*.html\x00", "html"},
	}
	f, ok := filters[format]
	if !ok {
		f = filters["html"]
	}
	p, err := s.Dialogs.SaveFile(name, f[0], f[1])
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	if p == "" {
		writeJSON(w, map[string]any{"cancelled": true})
		return
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"saved": p})
}

// handleDownload liefert den Bericht als Download (Browser-Modus).
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	rep := s.currentReport()
	if rep == nil {
		http.Error(w, "Noch kein Ergebnis vorhanden.", http.StatusNotFound)
		return
	}
	data, name, ctype, err := renderReport(rep, r.URL.Query().Get("format"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Write(data)
}
