package detect

import (
	"io"
	"math"
)

const entropyBlock = 64 * 1024

// Für 65536 zufällige Bytes ist Chi-Quadrat (255 Freiheitsgrade) im Mittel 255
// mit Standardabweichung ≈ 22,6. Komprimierte Daten (ZIP, JPEG …) haben zwar
// ebenfalls hohe Entropie, liegen aber meist deutlich über diesem Wert.
const (
	minRandomEntropy = 7.995
	maxRandomChi2    = 380.0
)

func blockStats(b []byte) (entropy, chi2 float64, zero bool) {
	var h [256]int
	for _, c := range b {
		h[c]++
	}
	if h[0] == len(b) {
		return 0, 0, true
	}
	n := float64(len(b))
	exp := n / 256
	for _, c := range h {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	for _, c := range h {
		d := float64(c) - exp
		chi2 += d * d / exp
	}
	return entropy, chi2, false
}

func isRandomBlock(e, chi2 float64) bool {
	return e >= minRandomEntropy && chi2 <= maxRandomChi2
}

// measureEntropy liest gleichmäßig verteilte Stichproben (je 64 KiB) und
// bewertet, wie viele davon wie Zufallsdaten (= Chiffretext) aussehen.
func measureEntropy(r io.ReaderAt, size int64, samples int, skip int64) *Entropy {
	e := &Entropy{}
	if skip >= size {
		skip = 0
	}
	span := size - skip - entropyBlock
	if span < 0 {
		span = 0
	}
	if max := int((size-skip)/entropyBlock) + 1; samples > max {
		samples = max
	}
	if samples < 1 {
		samples = 1
	}
	var sum float64
	nonzero := 0
	for i := 0; i < samples; i++ {
		var off int64
		if samples > 1 {
			off = skip + span*int64(i)/int64(samples-1)
		} else {
			off = skip
		}
		off &^= 511
		n := entropyBlock
		if off+int64(n) > size {
			n = int(size - off)
		}
		if n < 4096 {
			continue
		}
		b, err := readAt(r, off, n)
		if err != nil && len(b) < 4096 {
			continue
		}
		e.Samples++
		ent, chi2, zero := blockStats(b)
		e.Profile = append(e.Profile, math.Round(ent*1000)/1000)
		if zero {
			e.ZeroBlocks++
			continue
		}
		nonzero++
		sum += ent
		// kleine Blöcke: Chi-Quadrat-Schranke skalieren
		if len(b) == entropyBlock && isRandomBlock(ent, chi2) ||
			len(b) < entropyBlock && ent > 7.9 && chi2 <= maxRandomChi2 {
			e.RandomBlocks++
		}
	}
	if nonzero > 0 {
		e.AvgEntropy = math.Round(sum/float64(nonzero)*1000) / 1000
		e.RandomFraction = math.Round(float64(e.RandomBlocks)/float64(nonzero)*1000) / 1000
	}
	return e
}
