package image

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// EWF (Expert Witness Format, EnCase E01) Version 1.
//
// Aufbau eines Segments: 13 Byte Dateikopf, danach eine verkettete Liste von
// Sektionen. Jede Sektion beginnt mit einem 76 Byte großen Deskriptor (Typ,
// Offset der nächsten Sektion, Größe). Die Nutzdaten liegen in "sectors"-
// Sektionen als Chunks (meist 32 KiB, zlib-komprimiert oder roh + Adler32);
// "table"-Sektionen enthalten die Offsets der Chunks.

const ewfSectionDescSize = 76

type ewfChunk struct {
	seg        int
	offset     int64
	size       int64
	compressed bool
}

type ewfImage struct {
	files     []File
	chunks    []ewfChunk
	chunkSize int64
	size      int64
	meta      []KV

	mu    sync.Mutex
	cache map[int][]byte
	order []int
}

const ewfCacheChunks = 128

func ewfSegmentName(first string, n int) string {
	if n == 1 {
		return first
	}
	ext := filepath.Ext(first)
	base := strings.TrimSuffix(first, ext)
	lead := "E"
	if len(ext) >= 2 {
		lead = ext[1:2]
	}
	if n <= 99 {
		return fmt.Sprintf("%s.%s%02d", base, lead, n)
	}
	// E99 → EAA … EZZ → FAA … ZZZ
	k := n - 100
	upper := lead == strings.ToUpper(lead)
	a := byte('a')
	if upper {
		a = 'A'
	}
	c3 := a + byte(k%26)
	c2 := a + byte((k/26)%26)
	c1 := lead[0] + byte(k/(26*26))
	return fmt.Sprintf("%s.%c%c%c", base, c1, c2, c3)
}

func openEWF(fsys FS, path string) (Image, error) {
	img := &ewfImage{cache: map[int][]byte{}}
	var sectorsPerChunk, bytesPerSector uint32
	var sectorCount uint64
	var headerText string
	var md5sum, sha1sum string

	for segNo := 1; ; segNo++ {
		p := ewfSegmentName(path, segNo)
		f, err := fsys.Open(p)
		if err != nil {
			if segNo == 1 {
				return nil, err
			}
			img.Close()
			return nil, fmt.Errorf("Segment %s fehlt (mehrteiliges E01). Bitte alle Segmente (%s, %s, …) im selben Ordner bereitstellen bzw. gemeinsam in das Fenster ziehen", filepath.Base(p), filepath.Base(ewfSegmentName(path, 1)), filepath.Base(ewfSegmentName(path, 2)))
		}
		img.files = append(img.files, f)
		segIdx := len(img.files) - 1
		fsize := f.Size()

		hdr := make([]byte, 13)
		if _, err := f.ReadAt(hdr, 0); err != nil {
			img.Close()
			return nil, fmt.Errorf("%s: Dateikopf nicht lesbar: %w", p, err)
		}
		if string(hdr[:8]) != "EVF\x09\x0d\x0a\xff\x00" {
			img.Close()
			return nil, fmt.Errorf("%s: keine gültige EWF-Segmentdatei", p)
		}

		off := int64(13)
		var lastSectorsStart, lastSectorsEnd int64 = -1, -1
		haveTable := false
		done := false
		next := false
		for off+ewfSectionDescSize <= fsize {
			desc := make([]byte, ewfSectionDescSize)
			if _, err := f.ReadAt(desc, off); err != nil {
				break
			}
			typ := strings.TrimRight(string(desc[:16]), "\x00")
			nextOff := int64(binary.LittleEndian.Uint64(desc[16:]))
			secSize := int64(binary.LittleEndian.Uint64(desc[24:]))
			dataOff := off + ewfSectionDescSize
			dataSize := secSize - ewfSectionDescSize

			switch typ {
			case "header2", "header":
				if dataSize > 0 && dataSize < 1<<20 && (headerText == "" || typ == "header2") {
					buf := make([]byte, dataSize)
					if _, err := f.ReadAt(buf, dataOff); err == nil {
						if t := ewfDecodeHeader(buf, typ == "header2"); t != "" {
							headerText = t
						}
					}
				}
			case "volume", "disk", "data":
				if sectorsPerChunk == 0 && dataSize >= 20 {
					buf := make([]byte, min64(dataSize, 1052))
					if _, err := f.ReadAt(buf, dataOff); err == nil {
						sectorsPerChunk = binary.LittleEndian.Uint32(buf[8:])
						bytesPerSector = binary.LittleEndian.Uint32(buf[12:])
						if len(buf) >= 1052 {
							sectorCount = binary.LittleEndian.Uint64(buf[16:])
						} else {
							sectorCount = uint64(binary.LittleEndian.Uint32(buf[16:]))
						}
					}
				}
			case "sectors":
				lastSectorsStart, lastSectorsEnd = dataOff, off+secSize
			case "table", "table2":
				if typ == "table2" && haveTable {
					break
				}
				if typ == "table" {
					haveTable = true
				}
				chunks, err := ewfParseTable(f, dataOff, dataSize, off, lastSectorsStart, lastSectorsEnd, segIdx)
				if err != nil {
					img.Close()
					return nil, fmt.Errorf("%s: %w", p, err)
				}
				img.chunks = append(img.chunks, chunks...)
				lastSectorsStart, lastSectorsEnd = -1, -1
			case "hash":
				buf := make([]byte, 16)
				if _, err := f.ReadAt(buf, dataOff); err == nil && !allZero(buf) {
					md5sum = hex.EncodeToString(buf)
				}
			case "digest":
				buf := make([]byte, 36)
				if _, err := f.ReadAt(buf, dataOff); err == nil {
					if !allZero(buf[:16]) {
						md5sum = hex.EncodeToString(buf[:16])
					}
					if !allZero(buf[16:36]) {
						sha1sum = hex.EncodeToString(buf[16:36])
					}
				}
			case "done":
				done = true
			case "next":
				next = true
			}
			if done || next || nextOff <= off {
				break
			}
			off = nextOff
		}
		// table2 wird nur genutzt, wenn table fehlt – ansonsten doppelte Chunks
		// vermeiden: ewfParseTable wird für table2 nur ohne table aufgerufen.
		if done || !next {
			break
		}
	}

	if sectorsPerChunk == 0 || bytesPerSector == 0 {
		img.Close()
		return nil, fmt.Errorf("EWF: Volume-Sektion fehlt oder ist beschädigt")
	}
	img.chunkSize = int64(sectorsPerChunk) * int64(bytesPerSector)
	img.size = int64(sectorCount) * int64(bytesPerSector)
	if img.size == 0 || img.size > int64(len(img.chunks))*img.chunkSize {
		img.size = int64(len(img.chunks)) * img.chunkSize
	}

	img.meta = append(img.meta, KV{"Segmente", strconv.Itoa(len(img.files))})
	img.meta = append(img.meta, KV{"Bytes pro Sektor", strconv.Itoa(int(bytesPerSector))})
	img.meta = append(img.meta, ewfHeaderKV(headerText)...)
	if md5sum != "" {
		img.meta = append(img.meta, KV{"MD5 (gespeichert)", md5sum})
	}
	if sha1sum != "" {
		img.meta = append(img.meta, KV{"SHA1 (gespeichert)", sha1sum})
	}
	return img, nil
}

func ewfParseTable(f File, dataOff, dataSize, sectionStart, sectorsStart, sectorsEnd int64, seg int) ([]ewfChunk, error) {
	if dataSize < 24 {
		return nil, fmt.Errorf("Tabellen-Sektion zu klein")
	}
	head := make([]byte, 24)
	if _, err := f.ReadAt(head, dataOff); err != nil {
		return nil, err
	}
	n := int64(binary.LittleEndian.Uint32(head[0:]))
	base := int64(binary.LittleEndian.Uint64(head[8:]))
	if n == 0 {
		return nil, nil
	}
	if n*4+24 > dataSize {
		return nil, fmt.Errorf("Tabellen-Sektion beschädigt (%d Einträge)", n)
	}
	raw := make([]byte, n*4)
	if _, err := f.ReadAt(raw, dataOff+24); err != nil {
		return nil, err
	}
	out := make([]ewfChunk, n)
	overflow := false
	var prev int64 = -1
	for i := int64(0); i < n; i++ {
		v := binary.LittleEndian.Uint32(raw[i*4:])
		var o int64
		comp := false
		if overflow {
			o = int64(v)
		} else {
			o = int64(v & 0x7fffffff)
			comp = v&0x80000000 != 0
			// Ältere EnCase-Versionen: Offsets über 2 GiB überlaufen ins
			// Kompressions-Bit (so behandelt es auch libewf).
			if prev >= 0 && o+base < prev && int64(v)+base > prev {
				overflow = true
				o = int64(v)
				comp = false
			}
		}
		out[i] = ewfChunk{seg: seg, offset: o + base, compressed: comp}
		prev = o + base
	}
	for i := int64(0); i < n-1; i++ {
		out[i].size = out[i+1].offset - out[i].offset
	}
	end := sectionStart
	if sectorsEnd > 0 && sectorsEnd > out[n-1].offset {
		end = sectorsEnd
	}
	out[n-1].size = end - out[n-1].offset
	for i := range out {
		if out[i].size <= 0 || out[i].size > 64<<20 {
			return nil, fmt.Errorf("ungültige Chunk-Größe in Tabelle (Eintrag %d)", i)
		}
	}
	return out, nil
}

func (e *ewfImage) chunk(i int) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if b, ok := e.cache[i]; ok {
		return b, nil
	}
	c := e.chunks[i]
	raw := make([]byte, c.size)
	if _, err := e.files[c.seg].ReadAt(raw, c.offset); err != nil && err != io.EOF {
		return nil, err
	}
	var data []byte
	if c.compressed {
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("Chunk %d: zlib-Fehler: %w", i, err)
		}
		data = make([]byte, e.chunkSize)
		n, err := io.ReadFull(zr, data)
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("Chunk %d: Dekompression fehlgeschlagen: %w", i, err)
		}
		data = data[:n]
	} else {
		data = raw
		if int64(len(data)) > e.chunkSize {
			data = data[:e.chunkSize] // Adler32-Prüfsumme abschneiden
		}
	}
	if int64(len(data)) < e.chunkSize {
		d := make([]byte, e.chunkSize)
		copy(d, data)
		data = d
	}
	e.cache[i] = data
	e.order = append(e.order, i)
	if len(e.order) > ewfCacheChunks {
		delete(e.cache, e.order[0])
		e.order = e.order[1:]
	}
	return data, nil
}

func (e *ewfImage) ReadAt(p []byte, off int64) (int, error) {
	if off >= e.size {
		return 0, io.EOF
	}
	total := 0
	for total < len(p) {
		pos := off + int64(total)
		if pos >= e.size {
			return total, io.EOF
		}
		ci := int(pos / e.chunkSize)
		if ci >= len(e.chunks) {
			return total, io.EOF
		}
		data, err := e.chunk(ci)
		if err != nil {
			return total, err
		}
		in := pos % e.chunkSize
		n := copy(p[total:], data[in:])
		if rem := e.size - pos; int64(n) > rem {
			n = int(rem)
		}
		total += n
	}
	return total, nil
}

func (e *ewfImage) Size() int64    { return e.size }
func (e *ewfImage) Format() string { return "EnCase E01 (EWF)" }
func (e *ewfImage) Meta() []KV     { return e.meta }

func (e *ewfImage) Close() error {
	for _, f := range e.files {
		f.Close()
	}
	return nil
}

func ewfDecodeHeader(buf []byte, utf16le bool) string {
	zr, err := zlib.NewReader(bytes.NewReader(buf))
	if err != nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(zr, 1<<20))
	if err != nil && len(data) == 0 {
		return ""
	}
	if utf16le {
		if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe {
			data = data[2:]
		}
		u := make([]uint16, len(data)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(data[i*2:])
		}
		return string(utf16.Decode(u))
	}
	return string(data)
}

var ewfHeaderNames = map[string]string{
	"c":  "Fallnummer",
	"n":  "Asservatennummer",
	"a":  "Beschreibung",
	"e":  "Ermittler",
	"t":  "Notizen",
	"av": "Erstellt mit",
	"ov": "Betriebssystem (Akquise)",
	"m":  "Akquisitionsdatum",
	"u":  "Systemdatum",
	"md": "Modell",
	"sn": "Seriennummer",
	"l":  "Gerätebezeichnung",
}

var ewfHeaderOrder = []string{"c", "n", "a", "e", "t", "m", "u", "md", "sn", "l", "av", "ov"}

func ewfHeaderKV(text string) []KV {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "main" || i+2 >= len(lines) {
			continue
		}
		keys := strings.Split(lines[i+1], "\t")
		vals := strings.Split(lines[i+2], "\t")
		m := map[string]string{}
		for j, k := range keys {
			if j < len(vals) {
				m[strings.TrimSpace(k)] = strings.TrimSpace(vals[j])
			}
		}
		var out []KV
		for _, k := range ewfHeaderOrder {
			v := m[k]
			if v == "" {
				continue
			}
			if k == "m" || k == "u" {
				v = ewfFormatDate(v)
			}
			out = append(out, KV{ewfHeaderNames[k], v})
		}
		return out
	}
	return nil
}

func ewfFormatDate(v string) string {
	if ts, err := strconv.ParseInt(v, 10, 64); err == nil && ts > 0 {
		return time.Unix(ts, 0).UTC().Format("02.01.2006 15:04:05 UTC")
	}
	// Format "JJJJ MM TT hh mm ss"
	var y, mo, d, h, mi, s int
	if n, _ := fmt.Sscanf(v, "%d %d %d %d %d %d", &y, &mo, &d, &h, &mi, &s); n == 6 {
		return fmt.Sprintf("%02d.%02d.%04d %02d:%02d:%02d", d, mo, y, h, mi, s)
	}
	return v
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
