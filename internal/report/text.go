// Package report erzeugt Text-, JSON- und HTML-Berichte.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"encdetect/internal/detect"
)

func JSON(w io.Writer, r *detect.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

func Text(w io.Writer, r *detect.Report) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f+"\n", a...) }
	p("EncDetect %s – Analysebericht", r.Version)
	p("%s", strings.Repeat("=", 60))
	p("Datei:          %s", r.Path)
	p("Format:         %s", r.Format)
	p("Größe:          %s (%d Bytes)", detect.HumanSize(r.Size), r.Size)
	for _, m := range r.Meta {
		p("%-15s %s", m.Key+":", m.Value)
	}
	p("Partitionen:    %s", r.PartitionScheme)
	p("")
	p("ERGEBNIS: %s", strings.ToUpper(r.OverallText))
	p("%s", r.OverallSummary)
	for _, n := range r.DiskNotes {
		p("  ! %s", n)
	}
	for _, n := range r.Warnings {
		p("  ⚠ %s", n)
	}
	for _, v := range r.Volumes {
		p("")
		p("%s", strings.Repeat("-", 60))
		name := v.Label
		if v.PartName != "" {
			name += " „" + v.PartName + "“"
		}
		p("%s  [%s]", name, v.StatusText)
		p("  Offset %d, Größe %s, Typ: %s", v.Offset, detect.HumanSize(v.Size), v.PartType)
		p("  Verfahren:   %s", v.Scheme)
		if v.Algorithm != "" {
			p("  Algorithmus: %s", v.Algorithm)
		}
		p("  Konfidenz:   %d %%", v.Confidence)
		p("  %s", v.Summary)
		for _, d := range v.Details {
			p("    %-28s %s", d.Key+":", d.Value)
		}
		for _, s := range v.Sub {
			p("    • %s – %s", s.Name, s.Summary)
			for _, d := range s.Details {
				p("        %-26s %s", d.Key+":", d.Value)
			}
		}
		if v.Entropy != nil {
			p("    Entropie: Ø %.3f Bit/Byte, %d/%d Stichproben zufällig, %d leer", v.Entropy.AvgEntropy, v.Entropy.RandomBlocks, v.Entropy.Samples-v.Entropy.ZeroBlocks, v.Entropy.ZeroBlocks)
		}
		for _, n := range v.Notes {
			p("    → %s", n)
		}
	}
	p("")
	p("Analysedauer: %d ms", r.DurationMs)
}
