package image

import (
	"fmt"
	"io"
	"os"
)

// File ist eine geöffnete, nur lesbare Datei (Teil eines Images).
type File interface {
	io.ReaderAt
	Size() int64
	Close() error
}

// FS liefert Dateien zum Lesen. Neben dem echten Dateisystem gibt es z. B. die
// per Drag & Drop in die Oberfläche gezogenen Dateien.
type FS interface {
	Open(name string) (File, error)
	Exists(name string) bool
}

// OSFS ist das normale Dateisystem.
type OSFS struct{}

type osFile struct {
	*os.File
	size int64
}

func (f osFile) Size() int64 { return f.size }

func (OSFS) Open(name string) (File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.IsDir() {
		f.Close()
		return nil, fmt.Errorf("%s ist ein Verzeichnis", name)
	}
	return osFile{f, st.Size()}, nil
}

func (OSFS) Exists(name string) bool {
	st, err := os.Stat(name)
	return err == nil && !st.IsDir()
}
