package detect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

// APFS (Apple File System) inkl. FileVault.
//
// Ablauf: Container-Superblock (NXSB) → neuester Checkpoint → Objekt-Map
// (B-Baum) → Volume-Superblöcke (APSB). Das Flag APFS_FS_UNENCRYPTED zeigt, ob
// ein Volume verschlüsselt ist. Die Container-Keybag (mit der Container-UUID
// AES-XTS-verschlüsselt, also ohne Passwort lesbar) verweist auf die Volume-
// Keybags; deren Einträge zeigen, welche Benutzer/Wiederherstellungsschlüssel
// das Volume entsperren können (= FileVault).

const (
	apfsFSUnencrypted = 0x1
	apfsFSOneKey      = 0x8
)

var apfsRoles = map[uint16]string{
	0x0000: "",
	0x0001: "System",
	0x0002: "User",
	0x0004: "Recovery",
	0x0008: "VM (Swap)",
	0x0010: "Preboot",
	0x0020: "Installer",
	0x0040: "Data",
	0x0080: "Baseband",
	0x00C0: "Update",
	0x0100: "xART",
	0x0140: "Hardware",
	0x0180: "Backup (Time Machine)",
	0x0240: "Enterprise",
	0x02C0: "Prelogin",
}

var apfsSpecialUUIDs = map[string]string{
	"EBC6C064-0000-11AA-AA11-00306543ECAC": "Persönlicher Wiederherstellungsschlüssel",
	"C064EBC6-0000-11AA-AA11-00306543ECAC": "Institutioneller Wiederherstellungsschlüssel",
	"2FA31400-BAFF-4DE7-AE2A-C3AA6E1FD340": "Institutioneller Benutzer",
	"64C0C6EB-0000-11AA-AA11-00306543ECAC": "iCloud-Wiederherstellung",
	"EC1C2AD9-B618-4ED6-BD8D-50F361C27507": "iCloud-Benutzer",
}

func uuidBE(b []byte) string {
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

type apfs struct {
	r    io.ReaderAt
	bs   int64
	size int64
}

func (a *apfs) block(paddr int64) ([]byte, error) {
	if paddr <= 0 || (paddr+1)*a.bs > a.size {
		return nil, fmt.Errorf("Block %d außerhalb des Containers", paddr)
	}
	return readAt(a.r, paddr*a.bs, int(a.bs))
}

// omapLookup sucht die physische Adresse eines virtuellen Objekts.
func (a *apfs) omapLookup(treeAddr int64, oid, maxXid uint64) (int64, bool) {
	addr := treeAddr
	for depth := 0; depth < 16; depth++ {
		n, err := a.block(addr)
		if err != nil {
			return 0, false
		}
		flags := binary.LittleEndian.Uint16(n[32:])
		level := binary.LittleEndian.Uint16(n[34:])
		nkeys := int(binary.LittleEndian.Uint32(n[36:]))
		tOff := int(binary.LittleEndian.Uint16(n[40:]))
		tLen := int(binary.LittleEndian.Uint16(n[42:]))
		keyBase := 56 + tOff + tLen
		valEnd := int(a.bs)
		if flags&1 != 0 { // Wurzelknoten: btree_info_t am Ende
			valEnd -= 40
		}
		if flags&4 == 0 || nkeys <= 0 || 56+tOff+nkeys*4 > len(n) {
			return 0, false // OMAP verwendet immer feste Schlüsselgrößen
		}
		best := -1
		var bestXid uint64
		for i := 0; i < nkeys; i++ {
			ko := keyBase + int(binary.LittleEndian.Uint16(n[56+tOff+i*4:]))
			if ko+16 > len(n) {
				continue
			}
			koid := binary.LittleEndian.Uint64(n[ko:])
			kxid := binary.LittleEndian.Uint64(n[ko+8:])
			if level == 0 {
				if koid == oid && kxid <= maxXid && (best < 0 || kxid > bestXid) {
					best, bestXid = i, kxid
				}
			} else if koid < oid || (koid == oid && kxid <= maxXid) {
				best = i
			}
		}
		if best < 0 {
			return 0, false
		}
		vo := valEnd - int(binary.LittleEndian.Uint16(n[56+tOff+best*4+2:]))
		if level == 0 {
			if vo < 0 || vo+16 > len(n) {
				return 0, false
			}
			return int64(binary.LittleEndian.Uint64(n[vo+8:])), true
		}
		if vo < 0 || vo+8 > len(n) {
			return 0, false
		}
		addr = int64(binary.LittleEndian.Uint64(n[vo:]))
	}
	return 0, false
}

type kbEntry struct {
	uuid string
	tag  uint16
	data []byte
}

// readKeybag entschlüsselt eine Keybag (AES-XTS-128, Schlüssel = UUID doppelt,
// Tweak = 512-Byte-Sektornummer) und liefert ihre Einträge.
func (a *apfs) readKeybag(paddr, count int64, uuid []byte, wantType uint32) ([]kbEntry, error) {
	if count <= 0 || count > 16 {
		count = 1
	}
	key := append(append([]byte{}, uuid...), uuid...)
	var all []byte
	for i := int64(0); i < count; i++ {
		b, err := a.block(paddr + i)
		if err != nil {
			return nil, err
		}
		spb := a.bs / 512
		for s := int64(0); s < spb; s++ {
			pt, err := xtsDecrypt(key, uint64((paddr+i)*spb+s), b[s*512:(s+1)*512])
			if err != nil {
				return nil, err
			}
			all = append(all, pt...)
		}
	}
	if binary.LittleEndian.Uint32(all[24:]) != wantType {
		return nil, fmt.Errorf("Keybag-Entschlüsselung lieferte keinen gültigen Typ")
	}
	nkeys := int(binary.LittleEndian.Uint16(all[34:]))
	pos := 48
	var out []kbEntry
	for i := 0; i < nkeys && pos+24 <= len(all); i++ {
		tag := binary.LittleEndian.Uint16(all[pos+16:])
		kl := int(binary.LittleEndian.Uint16(all[pos+18:]))
		if pos+24+kl > len(all) {
			break
		}
		out = append(out, kbEntry{uuid: uuidBE(all[pos : pos+16]), tag: tag, data: all[pos+24 : pos+24+kl]})
		pos += (24 + kl + 15) &^ 15
	}
	return out, nil
}

func detectAPFS(r io.ReaderAt, size int64, v *Volume) bool {
	sb, err := readAt(r, 0, 4096)
	if err != nil && len(sb) < 1400 {
		return false
	}
	if string(sb[32:36]) != "NXSB" {
		return false
	}
	bs := int64(binary.LittleEndian.Uint32(sb[36:]))
	if bs < 4096 || bs > 65536 {
		bs = 4096
	}
	a := &apfs{r: r, bs: bs, size: size}
	if bs != 4096 {
		if b, err := readAt(r, 0, int(bs)); err == nil {
			sb = b
		}
	}

	// neuesten gültigen Checkpoint-Superblock suchen
	descBlocks := binary.LittleEndian.Uint32(sb[104:])
	descBase := int64(binary.LittleEndian.Uint64(sb[112:]))
	bestXid := binary.LittleEndian.Uint64(sb[16:])
	if descBlocks&0x80000000 == 0 && descBlocks < 100000 {
		for i := int64(0); i < int64(descBlocks); i++ {
			b, err := a.block(descBase + i)
			if err != nil {
				break
			}
			if string(b[32:36]) == "NXSB" && binary.LittleEndian.Uint32(b[24:])&0xffff == 1 {
				if x := binary.LittleEndian.Uint64(b[16:]); x > bestXid && apfsChecksumOK(b) {
					bestXid, sb = x, b
				}
			}
		}
	}

	v.Scheme = "APFS"
	v.Filesystem = "APFS-Container"
	v.Confidence = 95
	containerUUID := sb[72:88]
	v.add("Container-UUID", uuidBE(containerUUID))
	v.addf("Blockgröße", "%d", bs)
	v.addf("Containergröße", "%s", HumanSize(int64(binary.LittleEndian.Uint64(sb[40:]))*bs))

	keylocker := int64(binary.LittleEndian.Uint64(sb[1296:]))
	keylockerN := int64(binary.LittleEndian.Uint64(sb[1304:]))
	var ckb []kbEntry
	if keylocker > 0 {
		ckb, err = a.readKeybag(keylocker, keylockerN, containerUUID, 0x6b657973) // 'keys'
		if err != nil {
			v.note("Container-Keybag vorhanden, aber nicht auswertbar: %v", err)
		}
	}

	omapOID := int64(binary.LittleEndian.Uint64(sb[160:]))
	var tree int64
	if om, err := a.block(omapOID); err == nil {
		tree = int64(binary.LittleEndian.Uint64(om[48:]))
	}

	anyEnc, anyFV, anyPass, anyPlain := false, false, false, false
	for i := 0; i < 100; i++ {
		oid := binary.LittleEndian.Uint64(sb[184+i*8:])
		if oid == 0 {
			continue
		}
		paddr, ok := a.omapLookup(tree, oid, bestXid)
		if !ok {
			v.note("Volume %d: Objekt-Map-Eintrag nicht gefunden.", i+1)
			continue
		}
		vb, err := a.block(paddr)
		if err != nil || string(vb[32:36]) != "APSB" {
			v.note("Volume %d: Superblock nicht lesbar.", i+1)
			continue
		}
		sv := apfsVolume(a, vb, ckb)
		switch sv.Status {
		case StEncrypted:
			anyEnc = true
			if strings.Contains(sv.Algorithm, "FileVault") {
				anyFV = true
			}
			if strings.Contains(sv.Algorithm, "Volume-Passwort") {
				anyPass = true
			}
		case StPlain:
			anyPlain = true
		}
		v.Sub = append(v.Sub, sv)
	}

	switch {
	case anyFV:
		v.Status = StEncrypted
		v.Scheme = "APFS / FileVault"
		v.Algorithm = "AES-XTS (FileVault, 256-Bit-Schlüssel)"
		v.Summary = "APFS-Container mit FileVault-verschlüsseltem Volume. Entsperren mit Benutzerpasswort oder Wiederherstellungsschlüssel."
		v.note("Werkzeuge: apfs-fuse/fsapfsmount (Passwort oder Recovery Key), Passware, Magnet AXIOM, X-Ways. Passwort-Hash z. B. mit apfs2john/hashcat (-m 18300).")
	case anyPass:
		v.Status = StEncrypted
		v.Scheme = "APFS verschlüsselt (Passwort)"
		v.Algorithm = "AES-XTS (APFS-Verschlüsselung, 256-Bit-Schlüssel)"
		v.Summary = "APFS-Container mit passwortgeschütztem, verschlüsseltem Volume (externes Laufwerk oder Disk-Image)."
		v.note("Werkzeuge: apfs-fuse/fsapfsmount mit Passwort, Passware, Magnet AXIOM. Passwort-Hash z. B. mit apfs2john/hashcat (-m 18300).")
	case anyEnc:
		v.Status = StEncrypted
		v.Scheme = "APFS (verschlüsselt)"
		v.Algorithm = "AES-XTS"
		v.Summary = "APFS-Container mit verschlüsseltem Volume (ohne Benutzer-Entsperrschlüssel – vermutlich Hardware-Verschlüsselung über T2/Apple Silicon, oder Keybag nicht lesbar)."
	case anyPlain:
		v.Status = StPlain
		v.Summary = "APFS-Container, alle Volumes unverschlüsselt."
	default:
		v.Status = StUnknown
		v.Summary = "APFS-Container gefunden, Volumes konnten nicht ausgewertet werden."
	}
	if anyEnc {
		v.Confidence = 98
	}
	return true
}

func apfsVolume(a *apfs, vb []byte, ckb []kbEntry) SubVolume {
	name := cstr(vb[704:960])
	role := binary.LittleEndian.Uint16(vb[964:])
	flags := binary.LittleEndian.Uint64(vb[264:])
	volUUIDb := vb[240:256]
	volUUID := uuidBE(volUUIDb)
	formatted := cstr(vb[272:304])
	lastMod := binary.LittleEndian.Uint64(vb[256:])

	sv := SubVolume{Name: name}
	if r, ok := apfsRoles[role]; ok && r != "" {
		sv.Name = fmt.Sprintf("%s (%s)", name, r)
	}
	sv.Details = append(sv.Details, KV{Key: "Volume-UUID", Value: volUUID})
	if formatted != "" {
		sv.Details = append(sv.Details, KV{Key: "Formatiert mit", Value: formatted})
	}
	if lastMod > 0 {
		sv.Details = append(sv.Details, KV{Key: "Zuletzt geändert", Value: time.Unix(0, int64(lastMod)).UTC().Format("02.01.2006 15:04:05 UTC")})
	}
	if flags&apfsFSUnencrypted != 0 {
		sv.Status = StPlain
		sv.Summary = "nicht verschlüsselt"
		return sv
	}

	sv.Status = StEncrypted
	sv.Algorithm = "AES-XTS"
	if flags&apfsFSOneKey != 0 {
		sv.Details = append(sv.Details, KV{Key: "Schlüsselmodell", Value: "ein Schlüssel für das gesamte Volume (FileVault/Software)"})
	} else {
		sv.Details = append(sv.Details, KV{Key: "Schlüsselmodell", Value: "Schlüssel pro Datei (Data Protection)"})
	}

	// Container-Keybag: VEK und Ort der Volume-Keybag
	hasVEK := false
	var recsAddr, recsCount int64
	for _, e := range ckb {
		if e.uuid != volUUID {
			continue
		}
		switch e.tag {
		case 2:
			hasVEK = true
		case 3:
			if len(e.data) >= 16 {
				recsAddr = int64(binary.LittleEndian.Uint64(e.data))
				recsCount = int64(binary.LittleEndian.Uint64(e.data[8:]))
			}
		}
	}
	if hasVEK {
		sv.Details = append(sv.Details, KV{Key: "Volume-Schlüssel (VEK)", Value: "in Container-Keybag vorhanden (verschlüsselt)"})
	}
	var users, recovery []string
	volPass := false
	hint := ""
	if recsAddr > 0 {
		vkb, err := a.readKeybag(recsAddr, recsCount, volUUIDb, 0x72656373) // 'recs'
		if err != nil {
			sv.Details = append(sv.Details, KV{Key: "Volume-Keybag", Value: "nicht auswertbar: " + err.Error()})
		}
		for _, e := range vkb {
			switch e.tag {
			case 3:
				if s, ok := apfsSpecialUUIDs[e.uuid]; ok {
					recovery = append(recovery, s)
				} else if e.uuid == volUUID {
					volPass = true
				} else {
					users = append(users, e.uuid)
				}
			case 4:
				hint = cstr(e.data)
			}
		}
	}
	for i, u := range users {
		sv.Details = append(sv.Details, KV{Key: fmt.Sprintf("Entsperr-Benutzer %d", i+1), Value: u})
	}
	for _, r := range recovery {
		sv.Details = append(sv.Details, KV{Key: "Entsperrbar mit", Value: r})
	}
	if hint != "" {
		sv.Details = append(sv.Details, KV{Key: "Passwort-Hinweis", Value: hint})
	}

	if volPass {
		sv.Details = append(sv.Details, KV{Key: "Entsperrbar mit", Value: "Volume-Passwort (verschlüsseltes externes Laufwerk / Disk-Image)"})
	}
	if len(users) == 0 && len(recovery) == 0 && volPass {
		sv.Algorithm = "AES-XTS (APFS, Volume-Passwort)"
		sv.Summary = "verschlüsselt – mit Volume-Passwort geschützt (kein FileVault-Systemvolume)"
	} else if len(users)+len(recovery) > 0 {
		sv.Algorithm = "AES-XTS (FileVault)"
		sv.Summary = fmt.Sprintf("verschlüsselt – FileVault aktiv, %d Benutzer-Schlüssel", len(users))
		if len(recovery) > 0 {
			sv.Summary += ", " + strings.Join(recovery, ", ")
		}
	} else if recsAddr == 0 && hasVEK {
		sv.Summary = "verschlüsselt – keine Benutzer-Entsperrschlüssel (Hardware-Schlüssel über Secure Enclave/T2 – FileVault vermutlich aus)"
	} else {
		sv.Summary = "verschlüsselt"
	}
	return sv
}

// apfsChecksumOK prüft die Fletcher-64-Prüfsumme eines APFS-Objekts.
func apfsChecksumOK(b []byte) bool {
	const mod = 0xffffffff
	var s1, s2 uint64
	for i := 8; i+4 <= len(b); i += 4 {
		s1 = (s1 + uint64(binary.LittleEndian.Uint32(b[i:]))) % mod
		s2 = (s2 + s1) % mod
	}
	c1 := mod - ((s1 + s2) % mod)
	c2 := mod - ((s1 + c1) % mod)
	want := c2<<32 | c1
	return bytes.Equal(b[:8], binary.LittleEndian.AppendUint64(nil, want))
}
