package detect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// detectCoreStorage erkennt Apples CoreStorage (Basis von FileVault 2 unter
// OS X 10.7 – 10.12 sowie von Fusion Drives). Die Metadaten sind mit einem
// Schlüssel verschlüsselt, der im Header selbst steht (Key-Data + PV-UUID).
// Darin beschreibt ein XML-Block, ob das logische Volume verschlüsselt ist.
func detectCoreStorage(r io.ReaderAt, size int64, v *Volume) bool {
	h, err := readAt(r, 0, 512)
	if err != nil {
		return false
	}
	if string(h[88:90]) != "CS" || binary.LittleEndian.Uint16(h[8:]) != 1 {
		return false
	}
	v.Scheme = "CoreStorage"
	v.Filesystem = "CoreStorage Physical Volume"
	v.add("PV-UUID", uuidBE(h[304:320]))
	bs := int64(binary.LittleEndian.Uint32(h[96:]))
	v.addf("Blockgröße", "%d", bs)

	ctx := coreStorageContext(r, h, bs)
	if ctx.found {
		if ctx.encrypted {
			v.Status = StEncrypted
			v.Scheme = "FileVault 2 (CoreStorage)"
			v.Algorithm = ctx.algo + " 128 Bit (FileVault 2)"
			v.Confidence = 98
			v.Summary = fmt.Sprintf("FileVault 2 (OS X 10.7 – 10.12, HFS+ auf CoreStorage), %d Entsperr-Schlüssel.", len(ctx.users))
			if ctx.status != "" && ctx.status != "Complete" {
				v.Status = StPartial
				v.Summary += " Die Verschlüsselung ist noch nicht abgeschlossen (" + ctx.status + ")."
			}
		} else {
			v.Status = StPlain
			v.Confidence = 90
			v.Summary = "CoreStorage-Volume ohne Verschlüsselung (z. B. Fusion Drive)."
		}
		if ctx.status != "" {
			v.add("Konvertierungsstatus", ctx.status)
		}
		for i, u := range ctx.users {
			v.add(fmt.Sprintf("Entsperr-Schlüssel %d", i+1), u)
		}
		if ctx.hint != "" {
			v.add("Passwort-Hinweis", ctx.hint)
		}
		if ctx.encrypted {
			v.note("Werkzeuge: cryptsetup (Typ fvault2), libfvde (fvdemount), Passware. Passwort-Hash: fvde2john / hashcat -m 16700.")
		}
		return true
	}

	// Metadaten nicht auswertbar → Statistik
	e := measureEntropy(r, size, 64, 1<<20)
	v.Entropy = e
	if e.RandomFraction >= 0.6 {
		v.Status = StEncrypted
		v.Scheme = "FileVault 2 (CoreStorage)"
		v.Algorithm = "AES-XTS 128 Bit (FileVault 2)"
		v.Confidence = 85
		v.Summary = "CoreStorage-Volume mit zufällig verteilten Daten – vermutlich FileVault 2."
	} else {
		v.Status = StUnknown
		v.Confidence = 50
		v.Summary = "CoreStorage-Volume, Metadaten nicht auswertbar."
	}
	return true
}

type csContext struct {
	found, encrypted bool
	algo, status     string
	hint             string
	users            []string
}

var (
	reCSStatus = regexp.MustCompile(`<key>ConversionStatus</key><string[^>]*>([^<]*)</string>`)
	reCSAlgo   = regexp.MustCompile(`<key>BlockAlgorithm</key><string[^>]*>([^<]*)</string>`)
	reCSUser   = regexp.MustCompile(`<key>UserType</key><integer[^>]*>([^<]*)</integer><key>UserIdent</key><string[^>]*>([^<]*)</string>`)
	reCSHint   = regexp.MustCompile(`<key>PassphraseHint</key><string[^>]*>([^<]+)</string>`)
)

func coreStorageContext(r io.ReaderAt, h []byte, bs int64) csContext {
	var c csContext
	if bs < 512 || bs > 65536 {
		return c
	}
	key := append(append([]byte{}, h[176:192]...), h[304:320]...)
	dl := int64(binary.LittleEndian.Uint64(h[104:]))
	md, err := readAt(r, dl*bs, 8192)
	if err != nil {
		return c
	}
	vgOff := int64(binary.LittleEndian.Uint32(md[220:]))
	vg, err := readAt(r, dl*bs+vgOff, 40)
	if err != nil {
		return c
	}
	n := int64(binary.LittleEndian.Uint64(vg[8:]))
	start := int64(binary.LittleEndian.Uint64(vg[32:]))
	if n > 64 {
		n = 64
	}
	for i := int64(0); i < n; i++ {
		b, err := readAt(r, start*bs+i*8192, 8192)
		if err != nil || allZeroB(b) {
			break
		}
		p, err := xtsDecrypt(key, uint64(i), b)
		if err != nil || binary.LittleEndian.Uint16(p[10:]) != 0x0019 {
			continue
		}
		x := string(p)
		if !strings.Contains(x, "com.apple.corestorage.lvf.encryption.context") {
			continue
		}
		c.found = true
		if m := reCSStatus.FindStringSubmatch(x); m != nil {
			c.status = m[1]
		}
		for _, m := range reCSAlgo.FindAllStringSubmatch(x, -1) {
			if m[1] != "None" && m[1] != "" {
				c.algo = m[1]
				c.encrypted = true
			}
		}
		for _, m := range reCSUser.FindAllStringSubmatch(x, -1) {
			c.users = append(c.users, fmt.Sprintf("%s (Typ %s)", m[2], m[1]))
		}
		if m := reCSHint.FindStringSubmatch(x); m != nil {
			c.hint = m[1]
		}
		break
	}
	return c
}

// detectGELI erkennt FreeBSD GELI (Metadaten im letzten Sektor).
func detectGELI(r io.ReaderAt, size int64, v *Volume) bool {
	if size < 4096 {
		return false
	}
	for _, ss := range []int64{512, 4096} {
		b, err := readAt(r, size-ss, 512)
		if err != nil || string(b[0:9]) != "GEOM::ELI" {
			continue
		}
		ver := binary.LittleEndian.Uint32(b[16:])
		ealgo := binary.LittleEndian.Uint16(b[24:])
		keylen := binary.LittleEndian.Uint16(b[26:])
		aalgo := binary.LittleEndian.Uint16(b[28:])
		algos := map[uint16]string{22: "AES-XTS", 11: "AES-CBC", 21: "Camellia-CBC", 3: "Blowfish-CBC", 2: "3DES-CBC", 9: "NULL (keine Verschlüsselung)"}
		a := algos[ealgo]
		if a == "" {
			a = fmt.Sprintf("Algorithmus %d", ealgo)
		}
		v.Scheme = "FreeBSD GELI"
		v.Status = StEncrypted
		v.Confidence = 95
		v.Algorithm = fmt.Sprintf("%s %d Bit", a, keylen)
		v.addf("GELI-Version", "%d", ver)
		if aalgo != 0 {
			v.addf("Integrität (Auth-Algorithmus)", "%d", aalgo)
		}
		v.Summary = "FreeBSD-GELI-verschlüsselter Provider, " + v.Algorithm + "."
		return true
	}
	return false
}

// identifyFS erkennt gängige unverschlüsselte Dateisysteme und Container.
func identifyFS(r io.ReaderAt, size int64) (string, []KV) {
	b, _ := readAt(r, 0, 4096)
	if len(b) < 512 {
		return "", nil
	}
	if fs := bootSectorFS(b); fs != "" {
		return fs, nil
	}
	if string(b[0:4]) == "XFSB" {
		return "XFS", nil
	}
	if string(b[0:4]) == "hsqs" {
		return "SquashFS", nil
	}
	if len(b) >= 4096 && string(b[4086:4096]) == "SWAPSPACE2" {
		return "Linux Swap", nil
	}
	if len(b) >= 1024+32 && string(b[512:520]) == "LABELONE" && string(b[512+24:512+32]) == "LVM2 001" {
		return "LVM2 Physical Volume", nil
	}
	if len(b) >= 1026 && (string(b[1024:1026]) == "H+" || string(b[1024:1026]) == "HX") {
		return "HFS+", nil
	}
	if len(b) >= 1024+100 && binary.LittleEndian.Uint16(b[1024+56:]) == 0xEF53 {
		var kv []KV
		compat := binary.LittleEndian.Uint32(b[1024+0x5c:])
		incompat := binary.LittleEndian.Uint32(b[1024+0x60:])
		name := "ext2"
		if compat&0x4 != 0 {
			name = "ext3"
		}
		if incompat&0x40 != 0 || incompat&0x200 != 0 {
			name = "ext4"
		}
		if incompat&0x10000 != 0 {
			kv = append(kv, KV{Key: "fscrypt", Value: "aktiv"})
		}
		label := cstr(b[1024+0x78 : 1024+0x88])
		if label != "" {
			kv = append(kv, KV{Key: "Label", Value: label})
		}
		return name, kv
	}
	if len(b) >= 1028 && binary.LittleEndian.Uint32(b[1024:]) == 0xF2F52010 {
		return "F2FS", nil
	}
	if bt, err := readAt(r, 65536+64, 8); err == nil && string(bt) == "_BHRfS_M" {
		return "Btrfs", nil
	}
	if iso, err := readAt(r, 32769, 5); err == nil && string(iso) == "CD001" {
		return "ISO 9660", nil
	}
	if string(b[0:8]) == "\x00\x00\x00\x00\x00\x00\x00\x00" && string(b[8:16]) != "\x00\x00\x00\x00\x00\x00\x00\x00" {
		// ZFS-Label: Uberblock-Magic 0x00bab10c ab 128 KiB
		if z, err := readAt(r, 128*1024, 8); err == nil && (binary.LittleEndian.Uint64(z) == 0x00bab10c || binary.BigEndian.Uint64(z) == 0x00bab10c) {
			return "ZFS", nil
		}
	}
	return "", nil
}

// Bekannte Bootloader-/Produktkennungen von Festplattenverschlüsselungen.
var bootMarkers = []struct {
	needle, product string
}{
	{"VeraCrypt", "VeraCrypt (Systemverschlüsselung / Bootloader)"},
	{"TrueCrypt", "TrueCrypt (Systemverschlüsselung / Bootloader)"},
	{"DcsBoot", "VeraCrypt EFI-Bootloader (DcsBoot)"},
	{"DiskCryptor", "DiskCryptor"},
	{"SafeBoot", "McAfee / Trellix Endpoint Encryption (SafeBoot)"},
	{"PGPGUARD", "Symantec / PGP Whole Disk Encryption"},
	{"PGP WDE", "Symantec / PGP Whole Disk Encryption"},
	{"Symantec Encryption", "Symantec Endpoint Encryption"},
	{"SafeGuard", "Sophos SafeGuard"},
	{"Check Point", "Check Point Full Disk Encryption"},
	{"BestCrypt", "Jetico BestCrypt Volume Encryption"},
	{"WinMagic", "WinMagic SecureDoc"},
	{"SecureDoc", "WinMagic SecureDoc"},
	{"DriveLock", "DriveLock Full Disk Encryption"},
	{"Pointsec", "Check Point Pointsec"},
}

// scanMarkers sucht Produktkennungen in einem Bereich (ASCII und UTF-16).
func scanMarkers(b []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range bootMarkers {
		u16 := make([]byte, 0, len(m.needle)*2)
		for _, c := range []byte(m.needle) {
			u16 = append(u16, c, 0)
		}
		if bytes.Contains(b, []byte(m.needle)) || bytes.Contains(b, u16) {
			if !seen[m.product] {
				seen[m.product] = true
				out = append(out, m.product)
			}
		}
	}
	return out
}

func hasAnyFold(s string, subs ...string) bool {
	s = strings.ToLower(s)
	for _, x := range subs {
		if strings.Contains(s, strings.ToLower(x)) {
			return true
		}
	}
	return false
}
