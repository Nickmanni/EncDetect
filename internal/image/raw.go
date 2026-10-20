package image

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
)

type rawSeg struct {
	f     File
	name  string
	start int64
	size  int64
}

// rawImage ist ein dd/RAW-Image, optional auf mehrere Dateien (.001, .002, …)
// verteilt.
type rawImage struct {
	segs []rawSeg
	size int64
}

func openRaw(fsys FS, path string) (Image, error) {
	paths := splitRawSegments(fsys, path)
	r := &rawImage{}
	for _, p := range paths {
		f, err := fsys.Open(p)
		if err != nil {
			r.Close()
			return nil, err
		}
		r.segs = append(r.segs, rawSeg{f: f, name: p, start: r.size, size: f.Size()})
		r.size += f.Size()
	}
	return r, nil
}

func (r *rawImage) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.size {
		return 0, io.EOF
	}
	total := 0
	i := sort.Search(len(r.segs), func(i int) bool { return r.segs[i].start+r.segs[i].size > off })
	for total < len(p) && i < len(r.segs) {
		s := r.segs[i]
		rel := off + int64(total) - s.start
		want := len(p) - total
		if int64(want) > s.size-rel {
			want = int(s.size - rel)
		}
		n, err := s.f.ReadAt(p[total:total+want], rel)
		total += n
		if err != nil && err != io.EOF {
			return total, err
		}
		if n < want {
			break
		}
		i++
	}
	if total < len(p) {
		return total, io.EOF
	}
	return total, nil
}

func (r *rawImage) Size() int64 { return r.size }

func (r *rawImage) Format() string {
	if len(r.segs) > 1 {
		return fmt.Sprintf("RAW/dd (gesplittet, %d Teile)", len(r.segs))
	}
	return "RAW/dd"
}

func (r *rawImage) Meta() []KV {
	if len(r.segs) == 0 {
		return nil
	}
	return []KV{{"Datei", filepath.Base(r.segs[0].name)}}
}

func (r *rawImage) Close() error {
	for _, s := range r.segs {
		s.f.Close()
	}
	return nil
}
