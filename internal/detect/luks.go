package detect

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// LUKS1/LUKS2 (Linux Unified Key Setup). Der Header liegt im Klartext vor und
// enthält Algorithmus, Modus, Hash/KDF und die Schlüsselplätze.

func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

func detectLUKS(r io.ReaderAt, size int64, v *Volume) bool {
	h, err := readAt(r, 0, 4096)
	if err != nil && len(h) < 592 {
		return false
	}
	if string(h[0:6]) != "LUKS\xba\xbe" {
		return false
	}
	ver := binary.BigEndian.Uint16(h[6:])
	v.Status = StEncrypted
	v.Confidence = 99
	switch ver {
	case 1:
		luks1(h, v)
	case 2:
		luks2(r, h, v)
	default:
		v.Scheme = fmt.Sprintf("LUKS (Version %d)", ver)
		v.Summary = "LUKS-Header mit unbekannter Version."
	}
	v.note("Entschlüsselung nur mit Passphrase oder Schlüsseldatei möglich (z. B. cryptsetup luksOpen). Zum Brute-Forcing: hashcat (LUKS1 -m 14600, LUKS2 -m 34100) bzw. John the Ripper.")
	return true
}

func cipherDesc(name, mode string, keyBits int) string {
	name = strings.ToUpper(name)
	if strings.HasPrefix(name, "AES") {
		name = "AES"
	}
	s := name
	if mode != "" {
		s += "-" + mode
	}
	if keyBits > 0 {
		if strings.HasPrefix(mode, "xts") {
			s += fmt.Sprintf(" (%d-Bit-Schlüssel = %s-%d im XTS-Modus)", keyBits, name, keyBits/2)
		} else {
			s += fmt.Sprintf(" (%d Bit)", keyBits)
		}
	}
	return s
}

func luks1(h []byte, v *Volume) {
	v.Scheme = "LUKS1"
	cname := cstr(h[8:40])
	cmode := cstr(h[40:72])
	hash := cstr(h[72:104])
	payload := binary.BigEndian.Uint32(h[104:])
	keyBytes := int(binary.BigEndian.Uint32(h[108:]))
	iters := binary.BigEndian.Uint32(h[164:])
	uuid := cstr(h[168:208])
	v.Algorithm = cipherDesc(cname, cmode, keyBytes*8)
	v.add("Cipher", cname)
	v.add("Modus", cmode)
	v.addf("Schlüssellänge", "%d Bit", keyBytes*8)
	v.add("Hash (PBKDF2)", hash)
	v.addf("Master-Key-Iterationen", "%d", iters)
	v.add("UUID", uuid)
	v.addf("Daten-Offset", "%d Sektoren (%s)", payload, HumanSize(int64(payload)*512))
	active := 0
	for i := 0; i < 8; i++ {
		ks := h[208+i*48:]
		state := binary.BigEndian.Uint32(ks)
		if state == 0x00AC71F3 {
			active++
			v.addf(fmt.Sprintf("Keyslot %d", i), "aktiv, PBKDF2-%s, %d Iterationen", hash, binary.BigEndian.Uint32(ks[4:]))
		}
	}
	v.addf("Aktive Keyslots", "%d von 8", active)
	v.Summary = fmt.Sprintf("LUKS1-Container, %s, %d aktive Schlüsselplätze.", v.Algorithm, active)
}

type luks2JSON struct {
	Keyslots map[string]struct {
		Type    string `json:"type"`
		KeySize int    `json:"key_size"`
		Area    struct {
			Encryption string `json:"encryption"`
		} `json:"area"`
		KDF struct {
			Type       string `json:"type"`
			Hash       string `json:"hash"`
			Time       int    `json:"time"`
			Memory     int    `json:"memory"`
			CPUs       int    `json:"cpus"`
			Iterations int    `json:"iterations"`
		} `json:"kdf"`
	} `json:"keyslots"`
	Tokens map[string]struct {
		Type string `json:"type"`
	} `json:"tokens"`
	Segments map[string]struct {
		Type       string `json:"type"`
		Offset     string `json:"offset"`
		Size       string `json:"size"`
		Encryption string `json:"encryption"`
		SectorSize int    `json:"sector_size"`
		Integrity  *struct {
			Type string `json:"type"`
		} `json:"integrity"`
	} `json:"segments"`
	Digests map[string]struct {
		Type string `json:"type"`
		Hash string `json:"hash"`
	} `json:"digests"`
}

func luks2(r io.ReaderAt, h []byte, v *Volume) {
	v.Scheme = "LUKS2"
	hdrSize := int64(binary.BigEndian.Uint64(h[8:]))
	label := cstr(h[24:72])
	csum := cstr(h[72:104])
	uuid := cstr(h[168:208])
	subsys := cstr(h[208:256])
	v.add("UUID", uuid)
	if label != "" {
		v.add("Label", label)
	}
	if subsys != "" {
		v.add("Subsystem", subsys)
	}
	v.add("Header-Prüfsumme", csum)
	if hdrSize < 4096 || hdrSize > 4<<20 {
		hdrSize = 16384
	}
	raw, err := readAt(r, 4096, int(hdrSize-4096))
	if err != nil && len(raw) == 0 {
		v.Summary = "LUKS2-Header gefunden, JSON-Metadaten nicht lesbar."
		return
	}
	if i := strings.IndexByte(string(raw), 0); i >= 0 {
		raw = raw[:i]
	}
	var j luks2JSON
	if err := json.Unmarshal(raw, &j); err != nil {
		v.Summary = "LUKS2-Header gefunden, JSON-Metadaten beschädigt."
		return
	}

	for _, k := range sortedKeys(j.Segments) {
		s := j.Segments[k]
		if s.Type != "crypt" {
			continue
		}
		parts := strings.SplitN(s.Encryption, "-", 2)
		mode := ""
		if len(parts) == 2 {
			mode = parts[1]
		}
		// Schlüssellänge steht im Keyslot
		bits := 0
		for _, ks := range j.Keyslots {
			bits = ks.KeySize * 8
			break
		}
		if v.Algorithm == "" {
			v.Algorithm = cipherDesc(parts[0], mode, bits)
		}
		v.addf("Segment "+k, "%s, Sektorgröße %d, Offset %s", s.Encryption, s.SectorSize, s.Offset)
		if s.Integrity != nil {
			v.add("Integritätsschutz", s.Integrity.Type)
		}
	}
	kdfs := map[string]bool{}
	for _, k := range sortedKeys(j.Keyslots) {
		ks := j.Keyslots[k]
		desc := ks.KDF.Type
		switch ks.KDF.Type {
		case "argon2i", "argon2id":
			desc = fmt.Sprintf("%s (Zeit %d, Speicher %d KiB, Threads %d)", ks.KDF.Type, ks.KDF.Time, ks.KDF.Memory, ks.KDF.CPUs)
		case "pbkdf2":
			desc = fmt.Sprintf("PBKDF2-%s (%d Iterationen)", ks.KDF.Hash, ks.KDF.Iterations)
		}
		kdfs[ks.KDF.Type] = true
		v.addf("Keyslot "+k, "%s, %d Bit, Bereich %s, KDF %s", ks.Type, ks.KeySize*8, ks.Area.Encryption, desc)
	}
	v.addf("Aktive Keyslots", "%d", len(j.Keyslots))
	for _, k := range sortedKeys(j.Tokens) {
		t := j.Tokens[k].Type
		v.add("Token "+k, t)
		switch {
		case strings.Contains(t, "tpm2"):
			v.note("Token %s (%s): Schlüssel ist an einen TPM2-Chip gebunden (systemd-cryptenroll).", k, t)
		case strings.Contains(t, "fido2"):
			v.note("Token %s (%s): Entsperrung über FIDO2-Sicherheitsschlüssel.", k, t)
		case strings.Contains(t, "clevis"):
			v.note("Token %s (%s): Clevis/Tang (netzwerkgebundene Entsperrung).", k, t)
		}
	}
	var kl []string
	for k := range kdfs {
		kl = append(kl, k)
	}
	sort.Strings(kl)
	if v.Algorithm == "" {
		v.Algorithm = "unbekannt"
	}
	v.Summary = fmt.Sprintf("LUKS2-Container, %s, %d Schlüsselplätze (KDF: %s).", v.Algorithm, len(j.Keyslots), strings.Join(kl, ", "))
}

func sortedKeys[T any](m map[string]T) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Slice(k, func(a, b int) bool {
		ia, ea := strconv.Atoi(k[a])
		ib, eb := strconv.Atoi(k[b])
		if ea == nil && eb == nil {
			return ia < ib
		}
		return k[a] < k[b]
	})
	return k
}
