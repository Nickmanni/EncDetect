// Package image öffnet forensische Datenträger-Images (RAW/dd, gesplittete
// RAW-Images und EnCase E01) als einheitliches, rein lesendes io.ReaderAt.
package image

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Image ist ein geöffnetes Datenträger-Image. Es wird ausschließlich lesend
// zugegriffen.
type Image interface {
	io.ReaderAt
	Size() int64
	Format() string
	// Meta liefert zusätzliche Informationen aus dem Container (z. B. Fallnummer,
	// Ermittler und gespeicherte Hashwerte bei E01).
	Meta() []KV
	Close() error
}

// KV ist ein Schlüssel/Wert-Paar für die Anzeige.
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Open erkennt das Format anhand der Signatur (nicht nur der Endung) und öffnet
// das Image.
func Open(path string) (Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 8)
	n, _ := io.ReadFull(f, sig)
	f.Close()
	sig = sig[:n]

	switch {
	case n == 8 && string(sig) == "EVF\x09\x0d\x0a\xff\x00":
		return openEWF(path)
	case n == 8 && string(sig) == "EVF2\x0d\x0a\x81\x00":
		return nil, fmt.Errorf("Ex01 (EWF2-Format) wird nicht unterstützt – bitte mit FTK Imager oder ewfexport in E01 oder dd umwandeln. Ex01-Images können zusätzlich selbst verschlüsselt sein (EnCase-Containerverschlüsselung)")
	case n == 8 && string(sig) == "LVF\x09\x0d\x0a\xff\x00":
		return nil, fmt.Errorf("L01 ist ein logischer Container (Dateien statt Datenträger) und enthält kein Volume-Image")
	case n >= 4 && string(sig[:4]) == "KDMV":
		return nil, fmt.Errorf("VMDK-Sparse-Images werden nicht unterstützt – bitte in RAW umwandeln (z. B. qemu-img convert -O raw)")
	case n >= 8 && string(sig[:8]) == "vhdxfile":
		return nil, fmt.Errorf("VHDX wird nicht unterstützt – bitte in RAW umwandeln (z. B. qemu-img convert -O raw)")
	}
	return openRaw(path)
}

// SegmentFiles liefert die Liste der Teil-Dateien eines gesplitteten Images
// (z. B. image.001, image.002, …). Für ein einzelnes Image nur den Pfad selbst.
func splitRawSegments(path string) []string {
	ext := filepath.Ext(path)
	if len(ext) == 4 && isDigits(ext[1:]) && ext == ".001" {
		base := strings.TrimSuffix(path, ext)
		var out []string
		for i := 1; i < 10000; i++ {
			p := fmt.Sprintf("%s.%03d", base, i)
			if _, err := os.Stat(p); err != nil {
				break
			}
			out = append(out, p)
		}
		return out
	}
	return []string{path}
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
