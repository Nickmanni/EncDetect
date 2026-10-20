package image

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Vergleicht den Inhalt von E01-Images mit dem Roh-Image (MD5).
// Aufruf: EWF_TEST="roh.dd:img1.E01,img2.E01" go test ./internal/image
func TestEWFMatchesRaw(t *testing.T) {
	spec := os.Getenv("EWF_TEST")
	if spec == "" {
		t.Skip("EWF_TEST nicht gesetzt")
	}
	for _, group := range strings.Split(spec, ";") {
		raw, list, _ := strings.Cut(group, ":")
		want := md5Of(t, raw)
		for _, e := range strings.Split(list, ",") {
			got := md5Of(t, e)
			if got != want {
				t.Errorf("%s: MD5 %s, erwartet %s", filepath.Base(e), got, want)
			} else {
				t.Logf("%s: MD5 identisch (%s)", filepath.Base(e), got)
			}
		}
	}
}

func md5Of(t *testing.T, p string) string {
	img, err := Open(p)
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	defer img.Close()
	h := md5.New()
	// ungerade Puffergröße, damit Lesezugriffe Chunk-Grenzen überschreiten
	if _, err := io.CopyBuffer(h, io.NewSectionReader(img, 0, img.Size()), make([]byte, 100003)); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	for _, m := range img.Meta() {
		if strings.HasPrefix(m.Key, "MD5") && m.Value != hex.EncodeToString(h.Sum(nil)) {
			t.Errorf("%s: gespeicherter MD5 %s weicht ab", p, m.Value)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
