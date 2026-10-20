package detect

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

type partition struct {
	offset, size int64
	typ, name    string
	mbrType      byte
	gptType      string
}

var gptTypes = map[string]string{
	"C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI-Systempartition",
	"E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved",
	"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basisdaten",
	"DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows-Wiederherstellung",
	"5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM-Metadaten",
	"AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows LDM-Daten",
	"E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Windows Storage Spaces",
	"7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
	"48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
	"53746F72-6167-11AA-AA11-00306543ECAC": "Apple CoreStorage",
	"426F6F74-0000-11AA-AA11-00306543ECAC": "Apple Boot (Recovery HD)",
	"69646961-6700-11AA-AA11-00306543ECAC": "Apple ISC/Hardware",
	"52637672-7900-11AA-AA11-00306543ECAC": "Apple Recovery",
	"0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux-Dateisystem",
	"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux Root (x86-64)",
	"933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux /home",
	"CA7D7CCB-63ED-4C53-861C-1742536059CC": "Linux LUKS",
	"7FFEC5C9-2D00-49B7-8941-3EA10A5586B7": "Linux dm-crypt (plain)",
	"E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
	"A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
	"0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux Swap",
	"BC13C2FF-59E6-4262-A352-B275FD6F7172": "Linux /boot (XBOOTLDR)",
	"21686148-6449-6E6F-744E-656564454649": "BIOS-Boot",
	"516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD Daten",
	"516E7CBA-6ECF-11D6-8FF8-00022D09712B": "FreeBSD ZFS",
	"6A898CC3-1DD2-11B2-99A6-080020736631": "ZFS",
	"EBC6C064-0000-11AA-AA11-00306543ECAC": "Apple Recovery Key",
}

var mbrTypes = map[byte]string{
	0x01: "FAT12", 0x04: "FAT16", 0x05: "Erweitert", 0x06: "FAT16", 0x07: "NTFS/exFAT/BitLocker",
	0x0b: "FAT32", 0x0c: "FAT32 (LBA)", 0x0e: "FAT16 (LBA)", 0x0f: "Erweitert (LBA)",
	0x11: "Versteckt FAT12", 0x17: "Versteckt NTFS", 0x1b: "Versteckt FAT32", 0x1c: "Versteckt FAT32",
	0x27: "Windows-Wiederherstellung", 0x42: "Windows LDM", 0x82: "Linux Swap", 0x83: "Linux",
	0x85: "Linux erweitert", 0x8e: "Linux LVM", 0xa5: "FreeBSD", 0xa8: "macOS UFS", 0xab: "Apple Boot",
	0xaf: "Apple HFS/HFS+", 0xe8: "LUKS", 0xee: "GPT-Schutz", 0xef: "EFI", 0xfd: "Linux RAID",
}

func guidMixed(b []byte) string { return strings.ToUpper(guidString(b)) }

// readPartitions liefert das Partitionsschema und die Partitionen.
func readPartitions(r io.ReaderAt, size int64) (string, []partition, []string) {
	var warn []string
	for _, ss := range []int64{512, 4096} {
		h, err := readAt(r, ss, 512)
		if err != nil || string(h[0:8]) != "EFI PART" {
			continue
		}
		parts, w := readGPT(r, size, ss, h)
		warn = append(warn, w...)
		scheme := "GPT"
		if ss == 4096 {
			scheme = "GPT (4K-Sektoren)"
		}
		return scheme, parts, warn
	}

	s0, err := readAt(r, 0, 512)
	if err != nil || s0[510] != 0x55 || s0[511] != 0xaa {
		return "", nil, nil
	}
	// Ein Volume-Bootsektor (NTFS, FAT, BitLocker …) ist keine Partitionstabelle.
	if bootSectorFS(s0) != "" || string(s0[3:11]) == "-FVE-FS-" || string(s0[3:11]) == "MSWIN4.1" {
		return "", nil, nil
	}
	var parts []partition
	totalSect := size / 512
	for i := 0; i < 4; i++ {
		e := s0[446+i*16 : 446+(i+1)*16]
		if e[0] != 0 && e[0] != 0x80 {
			return "", nil, nil
		}
		typ := e[4]
		start := int64(binary.LittleEndian.Uint32(e[8:]))
		cnt := int64(binary.LittleEndian.Uint32(e[12:]))
		if typ == 0 || cnt == 0 {
			continue
		}
		if start == 0 || start > totalSect {
			return "", nil, nil
		}
		if typ == 0x05 || typ == 0x0f || typ == 0x85 {
			parts = append(parts, readEBR(r, size, start)...)
			continue
		}
		parts = append(parts, mkMBRPart(start, cnt, typ, size, &warn))
	}
	if len(parts) == 0 {
		return "", nil, nil
	}
	return "MBR", parts, warn
}

func mkMBRPart(start, cnt int64, typ byte, size int64, warn *[]string) partition {
	p := partition{offset: start * 512, size: cnt * 512, mbrType: typ}
	p.typ = fmt.Sprintf("0x%02X", typ)
	if n, ok := mbrTypes[typ]; ok {
		p.typ += " " + n
	}
	if p.offset+p.size > size {
		*warn = append(*warn, fmt.Sprintf("Partition bei Sektor %d reicht über das Image-Ende hinaus (Image unvollständig?).", start))
		p.size = size - p.offset
	}
	return p
}

func readEBR(r io.ReaderAt, size, extStart int64) []partition {
	var out []partition
	var w []string
	cur := extStart
	for i := 0; i < 128; i++ {
		b, err := readAt(r, cur*512, 512)
		if err != nil || b[510] != 0x55 || b[511] != 0xaa {
			break
		}
		e1 := b[446:462]
		e2 := b[462:478]
		if e1[4] != 0 {
			start := cur + int64(binary.LittleEndian.Uint32(e1[8:]))
			cnt := int64(binary.LittleEndian.Uint32(e1[12:]))
			if cnt > 0 && start*512 < size {
				out = append(out, mkMBRPart(start, cnt, e1[4], size, &w))
			}
		}
		if e2[4] == 0 {
			break
		}
		next := extStart + int64(binary.LittleEndian.Uint32(e2[8:]))
		if next <= cur {
			break
		}
		cur = next
	}
	return out
}

func readGPT(r io.ReaderAt, size, ss int64, h []byte) ([]partition, []string) {
	var warn []string
	entLBA := int64(binary.LittleEndian.Uint64(h[72:]))
	n := int(binary.LittleEndian.Uint32(h[80:]))
	esz := int(binary.LittleEndian.Uint32(h[84:]))
	if esz < 128 || esz > 4096 || n <= 0 || n > 1024 {
		return nil, []string{"GPT-Header beschädigt"}
	}
	tbl, err := readAt(r, entLBA*ss, n*esz)
	if err != nil && len(tbl) < esz {
		return nil, []string{"GPT-Partitionstabelle nicht lesbar"}
	}
	var out []partition
	for i := 0; i+esz <= len(tbl) && i/esz < n; i += esz {
		e := tbl[i : i+esz]
		if allZeroB(e[0:16]) {
			continue
		}
		first := int64(binary.LittleEndian.Uint64(e[32:]))
		last := int64(binary.LittleEndian.Uint64(e[40:]))
		if last < first {
			continue
		}
		t := guidMixed(e[0:16])
		p := partition{offset: first * ss, size: (last - first + 1) * ss, gptType: t, name: utf16le(e[56:128])}
		if d, ok := gptTypes[t]; ok {
			p.typ = d
		} else {
			p.typ = t
		}
		if p.offset >= size {
			warn = append(warn, fmt.Sprintf("Partition „%s“ liegt außerhalb des Images (Image unvollständig?).", p.name))
			continue
		}
		if p.offset+p.size > size {
			warn = append(warn, fmt.Sprintf("Partition „%s“ reicht über das Image-Ende hinaus (Image unvollständig?).", p.name))
			p.size = size - p.offset
		}
		out = append(out, p)
	}
	return out, warn
}

func allZeroB(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
