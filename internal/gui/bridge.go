package gui

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"encdetect/internal/image"
)

// Drag & Drop: Eine Web-Oberfläche erfährt beim Ablegen einer Datei nur deren
// Namen und Inhalt, nicht den Pfad. Die Brücke stellt die abgelegten Dateien
// der Analyse als Dateisystem bereit; jeder Lesezugriff wird als Anfrage an die
// Seite geschickt, die den Bereich per File.slice() liest und zurückschickt.
// Gelesen wird in 1-MiB-Blöcken mit Cache, damit wenige Rundreisen nötig sind.

const (
	bridgeBlock   = 1 << 20
	bridgeCache   = 96
	bridgeTimeout = 60 * time.Second
)

var errBridgeClosed = errors.New("Verbindung zur Oberfläche unterbrochen – die Datei ist nicht mehr lesbar (Fenster geschlossen oder neues Image gewählt)")

type bridgeReq struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Off  int64  `json:"off"`
	Len  int    `json:"len"`
	resp chan []byte
}

type bridge struct {
	id      string
	sizes   map[string]int64
	reqs    chan *bridgeReq
	closed  chan struct{}
	once    sync.Once
	mu      sync.Mutex
	nextID  int64
	pending map[int64]*bridgeReq
}

func newBridge(files map[string]int64) *bridge {
	b := make([]byte, 8)
	rand.Read(b)
	return &bridge{
		id:      hex.EncodeToString(b),
		sizes:   files,
		reqs:    make(chan *bridgeReq, 16),
		closed:  make(chan struct{}),
		pending: map[int64]*bridgeReq{},
	}
}

func (b *bridge) Close() { b.once.Do(func() { close(b.closed) }) }

// fetch fordert einen Bereich bei der Seite an und wartet auf die Daten.
func (b *bridge) fetch(name string, off int64, n int) ([]byte, error) {
	b.mu.Lock()
	b.nextID++
	r := &bridgeReq{ID: b.nextID, Name: name, Off: off, Len: n, resp: make(chan []byte, 1)}
	b.pending[r.ID] = r
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, r.ID)
		b.mu.Unlock()
	}()
	select {
	case b.reqs <- r:
	case <-b.closed:
		return nil, errBridgeClosed
	}
	select {
	case d := <-r.resp:
		if len(d) != n {
			return nil, io.ErrUnexpectedEOF
		}
		return d, nil
	case <-b.closed:
		return nil, errBridgeClosed
	case <-time.After(bridgeTimeout):
		return nil, errBridgeClosed
	}
}

// next liefert offene Leseanfragen (wartet bis zu wait auf die erste).
func (b *bridge) next(wait time.Duration) ([]*bridgeReq, bool) {
	var out []*bridgeReq
	select {
	case r := <-b.reqs:
		out = append(out, r)
	case <-b.closed:
		return nil, true
	case <-time.After(wait):
		return nil, false
	}
	for {
		select {
		case r := <-b.reqs:
			out = append(out, r)
		default:
			return out, false
		}
	}
}

func (b *bridge) deliver(id int64, data []byte) bool {
	b.mu.Lock()
	r := b.pending[id]
	b.mu.Unlock()
	if r == nil {
		return false
	}
	r.resp <- data
	return true
}

// image.FS-Implementierung

func (b *bridge) Exists(name string) bool {
	_, ok := b.sizes[name]
	return ok
}

func (b *bridge) Open(name string) (image.File, error) {
	size, ok := b.sizes[name]
	if !ok {
		return nil, errors.New("Datei " + name + " wurde nicht mit hineingezogen")
	}
	return &bridgeFile{b: b, name: name, size: size, cache: map[int64][]byte{}}, nil
}

type bridgeFile struct {
	b     *bridge
	name  string
	size  int64
	mu    sync.Mutex
	cache map[int64][]byte
	order []int64
}

func (f *bridgeFile) Size() int64  { return f.size }
func (f *bridgeFile) Close() error { return nil }

func (f *bridgeFile) block(idx int64) ([]byte, error) {
	if d, ok := f.cache[idx]; ok {
		return d, nil
	}
	off := idx * bridgeBlock
	n := int64(bridgeBlock)
	if off+n > f.size {
		n = f.size - off
	}
	d, err := f.b.fetch(f.name, off, int(n))
	if err != nil {
		return nil, err
	}
	f.cache[idx] = d
	f.order = append(f.order, idx)
	if len(f.order) > bridgeCache {
		delete(f.cache, f.order[0])
		f.order = f.order[1:]
	}
	return d, nil
}

func (f *bridgeFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if off >= f.size {
		return 0, io.EOF
	}
	total := 0
	for total < len(p) && off+int64(total) < f.size {
		pos := off + int64(total)
		d, err := f.block(pos / bridgeBlock)
		if err != nil {
			return total, err
		}
		total += copy(p[total:], d[pos%bridgeBlock:])
	}
	if total < len(p) {
		return total, io.EOF
	}
	return total, nil
}
