// EncDetect – grafische Oberfläche. Ein Image kann auch per Drag & Drop auf die
// EXE gezogen werden; es wird dann sofort analysiert.
package main

import (
	"fmt"
	"os"

	"encdetect/internal/gui"
)

func main() {
	initial := ""
	if len(os.Args) > 1 {
		initial = os.Args[1]
	}
	s, err := gui.NewServer(initial)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	gui.Run(s)
}
