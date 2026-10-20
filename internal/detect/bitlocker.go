package detect

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"
)

// BitLocker (FVE). Struktur nach libbde/cryptsetup:
//   Volume-Header (Sektor 0): Signatur "-FVE-FS-" ab Byte 3 (bzw. "MSWIN4.1" bei
//   BitLocker To Go), GUID + drei Offsets der FVE-Metadatenblöcke.
//   FVE-Metadatenblock: 64 Byte Block-Header, 48 Byte Metadaten-Header, danach
//   Einträge (VMKs mit Schutzvorrichtungen, FVEK, Beschreibung …).

var (
	bdeGUIDNormal = []byte{0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01}
	bdeGUIDEOW    = []byte{0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8}
)

var bdeMethods = map[uint16]string{
	0x8000: "AES-CBC 128 Bit mit Elephant-Diffuser",
	0x8001: "AES-CBC 256 Bit mit Elephant-Diffuser",
	0x8002: "AES-CBC 128 Bit",
	0x8003: "AES-CBC 256 Bit",
	0x8004: "XTS-AES 128 Bit",
	0x8005: "XTS-AES 256 Bit",
}

var bdeProtectors = map[uint16]string{
	0x0000: "Clear Key (ungeschützt!)",
	0x0100: "TPM",
	0x0200: "Systemstartschlüssel (USB-Schlüssel / .BEK)",
	0x0300: "TPM + Systemstartschlüssel",
	0x0400: "TPM + PIN + Systemstartschlüssel",
	0x0500: "TPM + PIN",
	0x0800: "Wiederherstellungskennwort (48 Ziffern)",
	0x1000: "Smartcard",
	0x2000: "Kennwort",
}

var bdeStates = map[uint16]string{
	0: "unbekannt (0)",
	1: "entschlüsselt",
	2: "Ver-/Entschlüsselung läuft",
	3: "Verschlüsselung bei Schreibzugriff aktiv",
	4: "vollständig verschlüsselt",
	5: "Verschlüsselung angehalten (pausiert)",
}

type bdeVMK struct {
	guid       string
	protection uint16
	modified   time.Time
	name       string
	clearKey   []byte // nur bei Clear Key
	encNonce   []byte
	encMAC     []byte
	encData    []byte
}

func guidString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(b[0:]), binary.LittleEndian.Uint16(b[4:]),
		binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}

func filetime(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	const epoch = 116444736000000000
	if v < epoch {
		return time.Time{}
	}
	return time.Unix(0, int64(v-epoch)*100).UTC()
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

func detectBitLocker(r io.ReaderAt, size int64, v *Volume) bool {
	vbr, err := readAt(r, 0, 512)
	if err != nil {
		return false
	}
	sig := string(vbr[3:11])
	var offsets []int64
	var guid []byte
	variant := ""
	switch {
	case sig == "-FVE-FS-" && bytes.Equal(vbr[0:3], []byte{0xeb, 0x52, 0x90}):
		// Windows Vista: Metadaten-LCN bei 0x38
		variant = "BitLocker (Windows Vista)"
		bps := int64(binary.LittleEndian.Uint16(vbr[11:]))
		spc := int64(vbr[13])
		lcn := int64(binary.LittleEndian.Uint64(vbr[0x38:]))
		if bps > 0 && spc > 0 {
			offsets = []int64{lcn * bps * spc}
		}
	case sig == "-FVE-FS-":
		variant = "BitLocker"
		guid = vbr[160:176]
		for i := 0; i < 3; i++ {
			offsets = append(offsets, int64(binary.LittleEndian.Uint64(vbr[176+i*8:])))
		}
	case sig == "MSWIN4.1" && (bytes.Equal(vbr[424:440], bdeGUIDNormal) || bytes.Equal(vbr[424:440], bdeGUIDEOW)):
		variant = "BitLocker To Go"
		guid = vbr[424:440]
		for i := 0; i < 3; i++ {
			offsets = append(offsets, int64(binary.LittleEndian.Uint64(vbr[440+i*8:])))
		}
	default:
		return false
	}

	v.Scheme = variant
	v.Status = StEncrypted
	v.Confidence = 95
	if guid != nil && bytes.Equal(guid, bdeGUIDEOW) {
		v.add("Modus", "Nur belegter Speicherplatz verschlüsselt (Encrypt-on-Write)")
		v.note("Modus „nur belegter Speicherplatz“: Bereiche, die vor der Aktivierung frei waren und seitdem nicht beschrieben wurden, können noch unverschlüsselte Altdaten enthalten.")
	}
	sectorSize := int64(binary.LittleEndian.Uint16(vbr[11:]))
	if sectorSize != 512 && sectorSize != 4096 {
		sectorSize = 512
	}

	// Ersten gültigen FVE-Metadatenblock suchen
	var meta []byte
	var metaOff int64
	for _, o := range offsets {
		if o <= 0 || o >= size {
			continue
		}
		b, err := readAt(r, o, 64*1024)
		if err != nil && len(b) < 112 {
			continue
		}
		if string(b[0:8]) != "-FVE-FS-" {
			continue
		}
		meta, metaOff = b, o
		break
	}
	if meta == nil {
		v.Algorithm = "unbekannt"
		v.Summary = "BitLocker-Signatur gefunden, aber kein lesbarer FVE-Metadatenblock (Image unvollständig oder beschädigt)."
		v.Confidence = 80
		return true
	}

	fveVersion := binary.LittleEndian.Uint16(meta[10:])
	curState := binary.LittleEndian.Uint16(meta[12:])
	nextState := binary.LittleEndian.Uint16(meta[14:])
	encSize := binary.LittleEndian.Uint64(meta[16:])
	volHdrOff := int64(binary.LittleEndian.Uint64(meta[56:]))
	mdSize := int(binary.LittleEndian.Uint32(meta[64:]))
	volGUID := guidString(meta[64+16 : 64+32])
	method := binary.LittleEndian.Uint16(meta[64+36:])
	created := filetime(binary.LittleEndian.Uint64(meta[64+40:]))

	if name, ok := bdeMethods[method]; ok {
		v.Algorithm = name
	} else {
		v.Algorithm = fmt.Sprintf("unbekannt (0x%04x)", method)
	}
	v.addf("FVE-Version", "%d", fveVersion)
	v.add("Volume-GUID", volGUID)
	if !created.IsZero() {
		v.add("Verschlüsselt seit", created.Format("02.01.2006 15:04:05 UTC"))
	}
	st := bdeStates[curState]
	if st == "" {
		st = fmt.Sprintf("unbekannt (%d)", curState)
	}
	v.add("Zustand", st)
	if nextState != curState && bdeStates[nextState] != "" {
		v.add("Zielzustand", bdeStates[nextState])
	}
	v.addf("Metadaten-Offset", "%d (0x%x)", metaOff, metaOff)

	// Einträge parsen
	if mdSize > len(meta)-64 || mdSize < 48 {
		mdSize = len(meta) - 64
	}
	var vmks []bdeVMK
	var fvekNonce, fvekMAC, fvekData []byte
	pos := 64 + 48
	end := 64 + mdSize
	for pos+8 <= end {
		esz := int(binary.LittleEndian.Uint16(meta[pos:]))
		if esz < 8 || pos+esz > end {
			break
		}
		etype := binary.LittleEndian.Uint16(meta[pos+2:])
		vtype := binary.LittleEndian.Uint16(meta[pos+4:])
		data := meta[pos+8 : pos+esz]
		switch {
		case etype == 0x0007 && vtype == 0x0002:
			v.add("Beschreibung", utf16le(data))
		case etype == 0x0002 && vtype == 0x0008 && len(data) >= 28:
			vmks = append(vmks, parseVMK(data))
		case etype == 0x0003 && vtype == 0x0005 && len(data) > 28:
			fvekNonce, fvekMAC, fvekData = data[:12], data[12:28], data[28:]
		case etype == 0x000f && vtype == 0x000f && len(data) >= 16:
			volHdrOff = int64(binary.LittleEndian.Uint64(data))
		}
		pos += esz
	}

	// Schutzvorrichtungen auflisten
	var clear *bdeVMK
	var prot []string
	for i := range vmks {
		k := &vmks[i]
		p, ok := bdeProtectors[k.protection]
		if !ok {
			p = fmt.Sprintf("unbekannt (0x%04x)", k.protection)
		}
		if k.name != "" {
			p += " – " + k.name
		}
		if k.protection == 0 {
			clear = k
		}
		prot = append(prot, p)
		v.add(fmt.Sprintf("Schutzvorrichtung %d", i+1), p+"  {"+k.guid+"}")
	}
	if len(vmks) == 0 {
		v.add("Schutzvorrichtungen", "keine gefunden")
	}

	partial := curState == 2 || curState == 5 || (curState == 1 && nextState == 4)
	if encSize > 0 && size > 0 && int64(encSize) < size && partial {
		v.addf("Verschlüsselungsfortschritt", "%.1f %% (%s von %s)", float64(encSize)*100/float64(size), HumanSize(int64(encSize)), HumanSize(size))
	}

	switch {
	case clear != nil:
		v.Status = StClearKey
		v.Confidence = 99
		v.Summary = "BitLocker mit Clear Key: Der Schlüssel liegt ungeschützt im Volume (BitLocker angehalten oder nicht fertig eingerichtet). Das Volume lässt sich ohne Passwort oder Wiederherstellungsschlüssel entschlüsseln."
		fvek, verified, info := bdeVerifyClearKey(r, sectorSize, clear, method, fvekNonce, fvekMAC, fvekData, volHdrOff)
		switch {
		case verified:
			v.add("Clear Key geprüft", "✔ erfolgreich – entschlüsselter Bootsektor: "+info)
		case fvek != nil:
			v.add("Clear Key geprüft", "VMK und FVEK entschlüsselt ("+info+")")
		default:
			v.add("Clear Key geprüft", "nicht möglich: "+info)
		}
		if fvek != nil {
			v.add("FVEK (Hex)", hex.EncodeToString(fvek))
		}
		v.note("Entschlüsseln z. B. mit: dislocker -c (clearkey), bdemount ohne Schlüssel, cryptsetup bitlkOpen, Arsenal Image Mounter, X-Ways, Magnet AXIOM oder EnCase.")
	case partial:
		v.Status = StPartial
		v.Summary = fmt.Sprintf("BitLocker im Übergangszustand (%s). Teile des Volumes liegen noch unverschlüsselt vor.", st)
	case curState == 1:
		v.Status = StPlain
		v.Summary = "BitLocker-Metadaten vorhanden, Zustand „entschlüsselt“."
	default:
		v.Summary = "BitLocker-verschlüsselt. Zum Entschlüsseln wird eine der Schutzvorrichtungen benötigt (z. B. Wiederherstellungskennwort)."
	}
	if clear == nil && len(prot) > 0 {
		v.Summary += " Schutz: " + strings.Join(dedup(prot), ", ") + "."
	}
	for _, k := range vmks {
		if k.protection == 0x0100 || k.protection == 0x0500 {
			v.note("TPM-geschützt: Der Schlüssel ist an den TPM-Chip des Originalgeräts gebunden. Ohne Gerät wird das Wiederherstellungskennwort benötigt (Microsoft-Konto, Azure AD/Entra ID, Active Directory, Ausdruck).")
			break
		}
	}
	for _, k := range vmks {
		if k.protection == 0x0800 {
			v.note("Wiederherstellungskennwort-ID: %s – damit lässt sich der passende Schlüssel z. B. im Microsoft-Konto (account.microsoft.com/devices/recoverykey) oder in Entra ID/AD finden.", strings.ToUpper(k.guid))
		}
	}
	return true
}

func parseVMK(data []byte) bdeVMK {
	k := bdeVMK{
		guid:       guidString(data[0:16]),
		modified:   filetime(binary.LittleEndian.Uint64(data[16:])),
		protection: binary.LittleEndian.Uint16(data[26:]),
	}
	pos := 28
	for pos+8 <= len(data) {
		esz := int(binary.LittleEndian.Uint16(data[pos:]))
		if esz < 8 || pos+esz > len(data) {
			break
		}
		vtype := binary.LittleEndian.Uint16(data[pos+4:])
		d := data[pos+8 : pos+esz]
		switch vtype {
		case 0x0001: // Schlüssel im Klartext (Clear Key)
			if len(d) > 4 {
				k.clearKey = append([]byte(nil), d[4:]...)
			}
		case 0x0005: // AES-CCM-verschlüsselter Schlüssel
			if len(d) > 28 && k.encData == nil {
				k.encNonce, k.encMAC, k.encData = d[:12], d[12:28], d[28:]
			}
		case 0x0002:
			k.name = utf16le(d)
		}
		pos += esz
	}
	return k
}

// bdeVerifyClearKey entschlüsselt VMK und FVEK mit dem Clear Key und prüft das
// Ergebnis anhand des umgelagerten Bootsektors.
func bdeVerifyClearKey(r io.ReaderAt, sectorSize int64, k *bdeVMK, method uint16, fn, fm, fd []byte, volHdrOff int64) ([]byte, bool, string) {
	if k.clearKey == nil || k.encData == nil {
		return nil, false, "Clear-Key-Struktur unvollständig"
	}
	vmkRaw, err := aesCCMDecrypt(k.clearKey, k.encNonce, k.encMAC, k.encData)
	if err != nil || len(vmkRaw) < 12+32 {
		return nil, false, "VMK-Entschlüsselung fehlgeschlagen"
	}
	vmk := vmkRaw[12 : 12+32]
	if fd == nil {
		return nil, false, "kein FVEK-Eintrag gefunden"
	}
	fvekRaw, err := aesCCMDecrypt(vmk, fn, fm, fd)
	if err != nil || len(fvekRaw) < 12+16 {
		return nil, false, "FVEK-Entschlüsselung fehlgeschlagen"
	}
	n := int(binary.LittleEndian.Uint16(fvekRaw))
	if n > len(fvekRaw) || n < 12+16 {
		n = len(fvekRaw)
	}
	fvek := append([]byte(nil), fvekRaw[12:n]...)

	if volHdrOff <= 0 {
		return fvek, false, "Offset des Bootsektors unbekannt"
	}
	sizes := []int64{sectorSize}
	if sectorSize != 512 {
		sizes = append(sizes, 512)
	}
	for _, ss := range sizes {
		ct, err := readAt(r, volHdrOff, int(ss))
		if err != nil {
			return fvek, false, "Bootsektor nicht lesbar"
		}
		var pt []byte
		switch method {
		case 0x8004:
			if len(fvek) >= 32 {
				pt, _ = xtsDecrypt(fvek[:32], uint64(volHdrOff/ss), ct)
			}
		case 0x8005:
			if len(fvek) >= 64 {
				pt, _ = xtsDecrypt(fvek[:64], uint64(volHdrOff/ss), ct)
			}
		case 0x8002:
			pt, _ = cbcEboivDecrypt(fvek[:16], uint64(volHdrOff), ct)
		case 0x8003:
			if len(fvek) >= 32 {
				pt, _ = cbcEboivDecrypt(fvek[:32], uint64(volHdrOff), ct)
			}
		default:
			return fvek, false, "Prüfung für Elephant-Diffuser nicht implementiert"
		}
		if pt != nil {
			if fs := bootSectorFS(pt); fs != "" {
				return fvek, true, fs
			}
		}
	}
	return fvek, false, "Bootsektor nach Entschlüsselung nicht erkannt"
}

func bootSectorFS(b []byte) string {
	if len(b) < 90 {
		return ""
	}
	switch {
	case string(b[3:11]) == "NTFS    ":
		return "NTFS"
	case string(b[3:11]) == "EXFAT   ":
		return "exFAT"
	case string(b[82:87]) == "FAT32":
		return "FAT32"
	case string(b[54:59]) == "FAT16" || string(b[54:59]) == "FAT12":
		return string(b[54:59])
	case string(b[3:7]) == "ReFS":
		return "ReFS"
	}
	return ""
}

func dedup(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
