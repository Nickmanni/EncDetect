// Package detect analysiert Datenträger-Images auf Verschlüsselung und
// ermittelt – soweit aus den Metadaten möglich – das Verfahren.
package detect

import (
	"fmt"
	"io"
	"time"

	"encdetect/internal/image"
)

// Status beschreibt das Ergebnis für ein Volume.
type Status string

const (
	StEncrypted Status = "encrypted" // verschlüsselt, Schlüssel geschützt
	StClearKey  Status = "clearkey"  // verschlüsselt, aber ohne Passwort entschlüsselbar
	StPartial   Status = "partial"   // teilweise verschlüsselt / Vorgang läuft
	StSuspected Status = "suspected" // statistisch wahrscheinlich verschlüsselt
	StPlain     Status = "plain"     // unverschlüsselt
	StEmpty     Status = "empty"     // leer / genullt
	StUnknown   Status = "unknown"
)

// Rangfolge für die Gesamtbewertung (höher = relevanter).
func (s Status) rank() int {
	switch s {
	case StClearKey:
		return 6
	case StEncrypted:
		return 5
	case StPartial:
		return 4
	case StSuspected:
		return 3
	case StUnknown:
		return 2
	case StPlain:
		return 1
	}
	return 0
}

// Label ist die deutsche Bezeichnung des Status.
func (s Status) Label() string {
	switch s {
	case StEncrypted:
		return "Verschlüsselt"
	case StClearKey:
		return "Verschlüsselt – Clear Key (ungeschützt)"
	case StPartial:
		return "Teilweise verschlüsselt"
	case StSuspected:
		return "Vermutlich verschlüsselt"
	case StPlain:
		return "Nicht verschlüsselt"
	case StEmpty:
		return "Leer"
	}
	return "Unbekannt"
}

type KV = image.KV

// SubVolume ist z. B. ein APFS-Volume innerhalb eines Containers.
type SubVolume struct {
	Name      string `json:"name"`
	Status    Status `json:"status"`
	Algorithm string `json:"algorithm,omitempty"`
	Summary   string `json:"summary"`
	Details   []KV   `json:"details,omitempty"`
}

// Entropy fasst die statistische Auswertung zusammen.
type Entropy struct {
	Samples        int     `json:"samples"`
	ZeroBlocks     int     `json:"zeroBlocks"`
	RandomBlocks   int     `json:"randomBlocks"`
	AvgEntropy     float64 `json:"avgEntropy"`
	RandomFraction float64 `json:"randomFraction"`
	// Verlauf der Entropie (Bit/Byte) über das Volume für die Grafik.
	Profile []float64 `json:"profile"`
}

// Volume ist eine Partition (oder das gesamte Image, falls nicht partitioniert).
type Volume struct {
	Index      int         `json:"index"`
	Label      string      `json:"label"`
	Offset     int64       `json:"offset"`
	Size       int64       `json:"size"`
	PartType   string      `json:"partType,omitempty"`
	PartName   string      `json:"partName,omitempty"`
	Status     Status      `json:"status"`
	StatusText string      `json:"statusText"`
	Scheme     string      `json:"scheme"`
	Algorithm  string      `json:"algorithm,omitempty"`
	Confidence int         `json:"confidence"`
	Summary    string      `json:"summary"`
	Filesystem string      `json:"filesystem,omitempty"`
	Details    []KV        `json:"details,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
	Sub        []SubVolume `json:"sub,omitempty"`
	Entropy    *Entropy    `json:"entropy,omitempty"`
}

func (v *Volume) add(k, val string) { v.Details = append(v.Details, KV{Key: k, Value: val}) }
func (v *Volume) addf(k, f string, a ...any) {
	v.Details = append(v.Details, KV{Key: k, Value: fmt.Sprintf(f, a...)})
}
func (v *Volume) note(f string, a ...any) { v.Notes = append(v.Notes, fmt.Sprintf(f, a...)) }

// Report ist das Gesamtergebnis einer Analyse.
type Report struct {
	Tool            string    `json:"tool"`
	Version         string    `json:"version"`
	Path            string    `json:"path"`
	FileName        string    `json:"fileName"`
	Format          string    `json:"format"`
	Size            int64     `json:"size"`
	Meta            []KV      `json:"meta,omitempty"`
	PartitionScheme string    `json:"partitionScheme"`
	DiskNotes       []string  `json:"diskNotes,omitempty"`
	Volumes         []Volume  `json:"volumes"`
	Overall         Status    `json:"overall"`
	OverallText     string    `json:"overallText"`
	OverallSummary  string    `json:"overallSummary"`
	Started         time.Time `json:"started"`
	DurationMs      int64     `json:"durationMs"`
	Warnings        []string  `json:"warnings,omitempty"`
}

// Progress meldet den Fortschritt (0..1) und einen Text.
type Progress func(frac float64, msg string)

// readAt liest genau len(b) Bytes oder liefert einen Fehler.
func readAt(r io.ReaderAt, off int64, n int) ([]byte, error) {
	b := make([]byte, n)
	m, err := r.ReadAt(b, off)
	if m == n {
		return b, nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return b[:m], err
}

// HumanSize formatiert Bytes lesbar (binäre Einheiten).
func HumanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
