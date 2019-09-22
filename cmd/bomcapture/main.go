package main

import (
	"flag"
	"log"
	"os"

	"github.com/kushaldas/bomcapture/pkg/capturing"
)

/*
Entry point for the executable
*/
func main() {
	log.SetOutput(os.Stderr)
	device := flag.String("device", "wg0", "The device to capture (as root).")
	stdout := flag.Bool("stdout", false, "Print output only on stdout")
	flag.Parse()

	capturing.StartCapture(*device, *stdout)
}
