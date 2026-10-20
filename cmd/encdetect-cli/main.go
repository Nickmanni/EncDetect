// encdetect-cli analysiert ein Image auf der Kommandozeile.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"encdetect/internal/detect"
	"encdetect/internal/image"
	"encdetect/internal/report"
)

func main() {
	asJSON := flag.Bool("json", false, "Ausgabe als JSON")
	htmlOut := flag.String("html", "", "HTML-Bericht in diese Datei schreiben")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "EncDetect %s – erkennt Verschlüsselung in E01- und dd-Images\n\nAufruf: encdetect-cli [-json] [-html bericht.html] <image> [<image> …]\n\n", detect.Version)
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	rc := 0
	for _, path := range flag.Args() {
		img, err := image.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			rc = 1
			continue
		}
		rep := detect.Analyze(context.Background(), img, path, nil)
		img.Close()
		if *asJSON {
			report.JSON(os.Stdout, rep)
		} else {
			report.Text(os.Stdout, rep)
		}
		if *htmlOut != "" {
			f, err := os.Create(*htmlOut)
			if err == nil {
				err = report.HTML(f, rep)
				f.Close()
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "HTML-Bericht: %v\n", err)
				rc = 1
			}
		}
	}
	os.Exit(rc)
}
