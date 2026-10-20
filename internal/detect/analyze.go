package detect

import (
	"context"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strings"
	"time"

	"encdetect/internal/image"
)

const Version = "1.0.1"

// Analyze untersucht ein geöffnetes Image vollständig.
func Analyze(ctx context.Context, img image.Image, path string, prog Progress) *Report {
	if prog == nil {
		prog = func(float64, string) {}
	}
	rep := &Report{
		Tool:     "EncDetect",
		Version:  Version,
		Path:     path,
		FileName: filepath.Base(path),
		Format:   img.Format(),
		Size:     img.Size(),
		Meta:     img.Meta(),
		Started:  time.Now(),
	}
	defer func() { rep.DurationMs = time.Since(rep.Started).Milliseconds() }()

	prog(0.02, "Partitionstabelle wird gelesen …")
	scheme, parts, warn := readPartitions(img, img.Size())
	rep.Warnings = append(rep.Warnings, warn...)
	if scheme == "" {
		rep.PartitionScheme = "keine (Volume-Image oder unpartitioniert)"
		parts = []partition{{offset: 0, size: img.Size(), typ: "gesamtes Image"}}
	} else {
		rep.PartitionScheme = scheme
	}

	// Bootloader-Kennungen am Datenträgeranfang (MBR + Lücke vor der 1. Partition)
	head := int64(1 << 20)
	if head > img.Size() {
		head = img.Size()
	}
	if b, err := readAt(img, 0, int(head)); err == nil || len(b) > 0 {
		for _, m := range scanMarkers(b) {
			rep.DiskNotes = append(rep.DiskNotes, "Bootloader-Kennung im Datenträgeranfang: "+m)
		}
	}

	for i, p := range parts {
		if ctx.Err() != nil {
			rep.Warnings = append(rep.Warnings, "Analyse abgebrochen.")
			break
		}
		label := fmt.Sprintf("Partition %d", i+1)
		if scheme == "" {
			label = "Volume"
		}
		prog(0.05+0.9*float64(i)/float64(len(parts)), fmt.Sprintf("%s wird analysiert …", label))
		v := Volume{Index: i + 1, Label: label, Offset: p.offset, Size: p.size, PartType: p.typ, PartName: p.name}
		analyzeVolume(io.NewSectionReader(img, p.offset, p.size), p, &v, rep)
		v.StatusText = v.Status.Label()
		rep.Volumes = append(rep.Volumes, v)
	}

	// Hinweis auf VeraCrypt/TrueCrypt-Systemverschlüsselung (MBR-Modus): Der
	// Volume-Header liegt dann in Sektor 62, die Partitionstabelle bleibt
	// unverschlüsselt, die Systempartition wirkt zufällig.
	if strings.HasPrefix(scheme, "MBR") {
		suspect := false
		for _, v := range rep.Volumes {
			if v.Status == StSuspected {
				suspect = true
			}
		}
		if s62, err := readAt(img, 62*512, 512); err == nil && suspect && looksRandomSmall(s62) {
			rep.DiskNotes = append(rep.DiskNotes, "Sektor 62 enthält Zufallsdaten: typisch für den Volume-Header einer VeraCrypt/TrueCrypt-Systemverschlüsselung (MBR-Modus).")
			for i := range rep.Volumes {
				if rep.Volumes[i].Status == StSuspected {
					rep.Volumes[i].Scheme = "VeraCrypt/TrueCrypt (Systemverschlüsselung, wahrscheinlich)"
					rep.Volumes[i].Confidence = max(rep.Volumes[i].Confidence, 90)
				}
			}
		}
	}

	summarize(rep)
	prog(1, "Fertig")
	return rep
}

func analyzeVolume(r *io.SectionReader, p partition, v *Volume, rep *Report) {
	size := p.size
	if size < 4096 {
		v.Status = StEmpty
		v.Scheme = "Leer"
		v.Summary = "Zu klein für eine Analyse."
		return
	}
	detectors := []func(io.ReaderAt, int64, *Volume) bool{
		detectBitLocker, detectLUKS, detectAPFS, detectCoreStorage, detectGELI,
	}
	for _, d := range detectors {
		if d(r, size, v) {
			return
		}
	}

	fs, kv := identifyFS(r, size)
	if fs != "" {
		v.Filesystem = fs
		v.Scheme = fs
		v.Details = append(v.Details, kv...)
		v.Status = StPlain
		v.Confidence = 90
		v.Summary = fmt.Sprintf("Unverschlüsseltes Dateisystem (%s).", fs)
		for _, x := range kv {
			if x.Key == "fscrypt" {
				v.Status = StPartial
				v.Scheme = fs + " + fscrypt"
				v.Algorithm = "fscrypt (meist AES-256-XTS für Inhalte, AES-256-CTS für Dateinamen)"
				v.Summary = "Dateisystem mit aktivierter dateibasierter Verschlüsselung (fscrypt, z. B. Android FBE oder verschlüsselte Home-Verzeichnisse). Einzelne Verzeichnisse können verschlüsselt sein."
			}
		}
		if p.gptType == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" || strings.HasPrefix(fs, "FAT") {
			n := size
			if n > 64<<20 {
				n = 64 << 20
			}
			if b, err := readAt(r, 0, int(n)); err == nil || len(b) > 0 {
				for _, m := range scanMarkers(b) {
					rep.DiskNotes = append(rep.DiskNotes, fmt.Sprintf("%s (%s): Kennung gefunden – %s", v.Label, fs, m))
				}
			}
		}
		if fs == "LVM2 Physical Volume" {
			v.note("LVM-Container: Logische Volumes darin werden nicht einzeln untersucht (LUKS liegt oft innerhalb eines LV).")
			v.Status = StUnknown
			v.Summary = "LVM2-Container. Die enthaltenen logischen Volumes können verschlüsselt sein."
			v.Entropy = measureEntropy(r, size, 128, 1<<20)
			if v.Entropy.RandomFraction > 0.8 {
				v.Status = StSuspected
				v.Summary += " Die Daten sind überwiegend zufällig verteilt – vermutlich verschlüsselte LVs (z. B. LUKS)."
			}
		}
		return
	}

	// Bekannte Datei-/Archivformate (kein Datenträger-Image)
	if s0, err := readAt(r, 0, 512); err == nil {
		if f := fileMagic(s0); f != "" && strings.Contains(f, "verschlüsselt") {
			v.Status = StEncrypted
			v.Scheme = f
			v.Confidence = 90
			v.Summary = "Keine Datenträgerstruktur, sondern eine verschlüsselte Datei (" + f + ")."
			return
		} else if f != "" {
			v.Status = StUnknown
			v.Scheme = f
			v.Confidence = 90
			v.Summary = "Keine Datenträgerstruktur: Der Inhalt beginnt mit der Signatur einer Datei (" + f + "). Komprimierte Daten sind statistisch nicht von Verschlüsselung zu unterscheiden, daher wird keine Entropie-Bewertung vorgenommen."
			return
		}
	}

	// Kein Header, kein Dateisystem → Statistik
	e := measureEntropy(r, size, 256, 0)
	v.Entropy = e
	nonzero := e.Samples - e.ZeroBlocks
	s0, _ := readAt(r, 0, 512)
	randomHeader := len(s0) == 512 && looksRandomSmall(s0)
	if randomHeader {
		v.add("Sektor 0", "zufällig (kein lesbarer Header)")
	}
	switch {
	case randomHeader && e.RandomFraction < 0.9:
		v.Status = StSuspected
		v.Scheme = "VeraCrypt/TrueCrypt (wahrscheinlich)"
		v.Algorithm = "nicht bestimmbar ohne Passwort"
		v.Confidence = 60
		v.Summary = fmt.Sprintf("Der erste Sektor besteht aus Zufallsdaten – typisch für den Header von VeraCrypt/TrueCrypt (64 Byte Salt + verschlüsselter Header). Nur %.0f %% der übrigen Stichproben wirken zufällig (Rest leer oder unverschlüsselt) – evtl. unvollständiges oder nachträglich überschriebenes Image.", e.RandomFraction*100)
		v.note("Header-lose Verfahren speichern Algorithmus und Modus verschlüsselt. VeraCrypt kann AES, Serpent, Twofish, Camellia, Kuznyechik sowie Kaskaden davon nutzen. Das Verfahren lässt sich erst mit dem Passwort ermitteln (z. B. VeraCrypt „Mount“, hashcat -m 13711–13783 / 29411–29483).")
	case e.Samples > 0 && nonzero == 0:
		v.Status = StEmpty
		v.Scheme = "Leer"
		v.Confidence = 90
		v.Summary = "Keine Daten (nur Nullen) – leer oder gelöscht."
	case e.RandomFraction >= 0.9:
		v.Status = StSuspected
		v.Scheme = "Header-lose Verschlüsselung"
		v.Algorithm = "nicht bestimmbar ohne Passwort"
		v.Confidence = 80
		if randomHeader {
			v.Confidence = 85
		}
		v.Summary = fmt.Sprintf("Kein Dateisystem erkennbar, %.0f %% der Stichproben sind statistisch nicht von Zufallsdaten zu unterscheiden. Typisch für VeraCrypt/TrueCrypt, dm-crypt (plain) o. Ä.", e.RandomFraction*100)
		switch {
		case p.gptType == "7FFEC5C9-2D00-49B7-8941-3EA10A5586B7":
			v.Scheme = "dm-crypt (plain)"
			v.Confidence = 90
		case p.mbrType == 0x07 || p.mbrType == 0x0b || p.mbrType == 0x0c || p.gptType == "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7":
			v.Scheme = "VeraCrypt/TrueCrypt (wahrscheinlich)"
			v.Confidence = 85
			v.note("Partitionstyp verweist auf ein Windows-Dateisystem, der Inhalt ist jedoch zufällig: typisch für VeraCrypt/TrueCrypt-Partitions- oder Systemverschlüsselung.")
		}
		v.note("Header-lose Verfahren speichern Algorithmus und Modus verschlüsselt. VeraCrypt kann AES, Serpent, Twofish, Camellia, Kuznyechik sowie Kaskaden davon nutzen. Das Verfahren lässt sich erst mit dem Passwort ermitteln (z. B. VeraCrypt „Mount“, hashcat -m 13711–13783 / 29411–29483).")
		v.note("Alternativ möglich: sicher mit Zufallsdaten überschriebener Bereich oder Daten eines unbekannten Verfahrens.")
		if p.typ == "gesamtes Image" {
			v.note("Bei einer einzelnen Datei kann es sich um einen VeraCrypt/TrueCrypt-Dateicontainer handeln.")
		}
	case e.RandomFraction >= 0.5:
		v.Status = StSuspected
		v.Scheme = "unklar"
		v.Confidence = 50
		v.Summary = fmt.Sprintf("Kein Dateisystem erkennbar, %.0f %% der Stichproben wirken zufällig. Möglich: teilweise verschlüsselte, komprimierte oder überschriebene Daten.", e.RandomFraction*100)
	default:
		v.Status = StUnknown
		v.Scheme = "unbekannt"
		v.Confidence = 40
		v.Summary = "Kein bekanntes Dateisystem und keine Zufallsdaten – unbekanntes Format, beschädigt oder unformatiert."
	}
}

func looksRandomSmall(b []byte) bool {
	var h [256]int
	for _, c := range b {
		h[c]++
	}
	distinct := 0
	var ent float64
	for _, c := range h {
		if c > 0 {
			distinct++
			p := float64(c) / float64(len(b))
			ent -= p * math.Log2(p)
		}
	}
	return distinct >= 180 && ent > 7.4
}

func summarize(rep *Report) {
	best := StEmpty
	var enc []string
	for _, v := range rep.Volumes {
		if v.Status.rank() > best.rank() {
			best = v.Status
		}
		switch v.Status {
		case StEncrypted, StClearKey, StPartial, StSuspected:
			s := v.Scheme
			if v.Algorithm != "" {
				s += " (" + v.Algorithm + ")"
			}
			enc = append(enc, fmt.Sprintf("%s: %s", v.Label, s))
		}
	}
	rep.Overall = best
	rep.OverallText = best.Label()
	switch {
	case len(enc) > 0:
		rep.OverallSummary = fmt.Sprintf("%d von %d Volume(s) betroffen – %s", len(enc), len(rep.Volumes), strings.Join(enc, "; "))
	case best == StPlain:
		rep.OverallSummary = "Keine Verschlüsselung gefunden."
	default:
		rep.OverallSummary = "Keine Verschlüsselung erkannt; einzelne Bereiche konnten nicht zugeordnet werden."
	}
}

// fileMagic erkennt gängige Datei- und Archivformate anhand der Signatur.
func fileMagic(b []byte) string {
	sigs := []struct{ magic, name string }{
		{"\xfd7zXZ\x00", "xz-Archiv"},
		{"\x1f\x8b", "gzip-Archiv"},
		{"BZh", "bzip2-Archiv"},
		{"\x28\xb5\x2f\xfd", "zstd-Archiv"},
		{"PK\x03\x04", "ZIP-Archiv / Office-Dokument"},
		{"7z\xbc\xaf\x27\x1c", "7-Zip-Archiv"},
		{"Rar!\x1a\x07", "RAR-Archiv"},
		{"\x89PNG", "PNG-Bild"},
		{"\xff\xd8\xff", "JPEG-Bild"},
		{"%PDF", "PDF-Dokument"},
		{"MSCF", "Microsoft-CAB-Archiv"},
		{"\x04\x22\x4d\x18", "LZ4-Archiv"},
		{"SQLite format 3", "SQLite-Datenbank"},
		{"-----BEGIN PGP", "PGP-Daten (ASCII)"},
		{"AES\x02", "AES Crypt-Datei"},
		{"Salted__", "OpenSSL-verschlüsselte Datei (enc)"},
		{"age-encryption.org", "age-verschlüsselte Datei"},
		{"\x85\x01\x0c", "PGP/GPG-verschlüsselte Datei"},
		{"\x84\x8c\x03", "PGP/GPG-verschlüsselte Datei"},
	}
	for _, s := range sigs {
		if len(b) >= len(s.magic) && string(b[:len(s.magic)]) == s.magic {
			return s.name
		}
	}
	return ""
}
