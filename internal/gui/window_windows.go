//go:build windows

package gui

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
)

var (
	comdlg32             = syscall.NewLazyDLL("comdlg32.dll")
	procGetOpenFileNameW = comdlg32.NewProc("GetOpenFileNameW")
	procGetSaveFileNameW = comdlg32.NewProc("GetSaveFileNameW")
	procCommDlgError     = comdlg32.NewProc("CommDlgExtendedError")
	user32               = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW      = user32.NewProc("MessageBoxW")
	procSetProcessDPI    = user32.NewProc("SetProcessDPIAware")
	shcore               = syscall.NewLazyDLL("shcore.dll")
	procSetDPIAwareness  = shcore.NewProc("SetProcessDpiAwareness")
)

type openFileNameW struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

const (
	ofnOverwritePrompt = 0x2
	ofnHideReadOnly    = 0x4
	ofnNoChangeDir     = 0x8
	ofnPathMustExist   = 0x800
	ofnFileMustExist   = 0x1000
	ofnExplorer        = 0x80000
)

const imageFilter = "Forensische Images (*.E01, *.dd, *.raw, *.img, *.001 …)\x00*.E01;*.e01;*.dd;*.raw;*.img;*.001;*.bin;*.dmg;*.iso;*.vhd\x00Alle Dateien (*.*)\x00*.*\x00\x00"

func utf16z(s string) []uint16 {
	u, _ := syscall.UTF16FromString(s)
	return u
}

type winDialogs struct {
	w       webview2.WebView
	lastDir string
}

// call führt f auf dem UI-Thread aus und wartet auf das Ergebnis.
func (d *winDialogs) call(f func()) {
	done := make(chan struct{})
	d.w.Dispatch(func() {
		f()
		close(done)
	})
	<-done
}

func (d *winDialogs) run(save bool, title, filter, defName, defExt string) (string, error) {
	buf := make([]uint16, 32768)
	if defName != "" {
		copy(buf, utf16z(defName))
	}
	filt := utf16z(filter)
	t := utf16z(title)
	ofn := openFileNameW{
		lpstrFilter:  &filt[0],
		nFilterIndex: 1,
		lpstrFile:    &buf[0],
		nMaxFile:     uint32(len(buf)),
		lpstrTitle:   &t[0],
		flags:        ofnExplorer | ofnNoChangeDir | ofnHideReadOnly | ofnPathMustExist,
	}
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	if d.lastDir != "" {
		dir := utf16z(d.lastDir)
		ofn.lpstrInitialDir = &dir[0]
	}
	if defExt != "" {
		e := utf16z(defExt)
		ofn.lpstrDefExt = &e[0]
	}
	proc := procGetOpenFileNameW
	if save {
		ofn.flags |= ofnOverwritePrompt
		proc = procGetSaveFileNameW
	} else {
		ofn.flags |= ofnFileMustExist
	}
	var ok uintptr
	d.call(func() {
		ofn.hwndOwner = uintptr(d.w.Window())
		ok, _, _ = proc.Call(uintptr(unsafe.Pointer(&ofn)))
	})
	runtime.KeepAlive(filt)
	runtime.KeepAlive(t)
	if ok == 0 {
		if code, _, _ := procCommDlgError.Call(); code != 0 {
			return "", errors.New("Dateidialog konnte nicht geöffnet werden")
		}
		return "", nil // abgebrochen
	}
	p := syscall.UTF16ToString(buf)
	d.lastDir = filepath.Dir(p)
	return p, nil
}

func (d *winDialogs) OpenFile() (string, error) {
	return d.run(false, "Image auswählen", imageFilter, "", "")
}

func (d *winDialogs) SaveFile(defName, filter, ext string) (string, error) {
	return d.run(true, "Bericht speichern", filter+"\x00", defName, ext)
}

func messageBox(title, text string) {
	t, x := utf16z(title), utf16z(text)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(&x[0])), uintptr(unsafe.Pointer(&t[0])), 0x40)
}

// Run öffnet das Programmfenster. Ist WebView2 nicht verfügbar, wird die
// Oberfläche im Standardbrowser geöffnet.
func Run(s *Server) {
	if procSetDPIAwareness.Find() == nil {
		procSetDPIAwareness.Call(2) // Per-Monitor-DPI
	} else if procSetProcessDPI.Find() == nil {
		procSetProcessDPI.Call()
	}
	dataDir := filepath.Join(os.Getenv("LOCALAPPDATA"), "EncDetect", "WebView2")
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		DataPath:  dataDir,
		WindowOptions: webview2.WindowOptions{
			Title:  "EncDetect – Verschlüsselungsanalyse",
			Width:  1280,
			Height: 860,
			IconId: 1,
			Center: true,
		},
	})
	if w == nil {
		runBrowser(s)
		return
	}
	defer w.Destroy()
	s.Dialogs = &winDialogs{w: w}
	w.SetSize(1040, 680, webview2.HintMin)
	go s.Serve()
	w.Navigate(s.URL)
	w.Run()
}

func runBrowser(s *Server) {
	go s.Serve()
	if err := exec.Command("rundll32", "url.dll,FileProtocolHandler", s.URL).Start(); err != nil {
		messageBox("EncDetect", "WebView2 ist nicht verfügbar und der Browser konnte nicht gestartet werden.\n\nBitte diese Adresse im Browser öffnen:\n"+s.URL)
	}
	waitIdle(s)
}
