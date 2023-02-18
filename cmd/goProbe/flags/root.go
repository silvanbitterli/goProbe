// Package flags is for parsing goProbe's command line parameters.
package flags

import (
	"errors"
	"flag"
)

// Flags stores goProbe's command line parameters
type Flags struct {
	Config  string
	Version bool

	Profiling          bool
	ProfilingOutputDir string
}

// CmdLine globally exposes the parsed flags
var CmdLine = &Flags{}

// Read reads in the command line parameters
func Read() error {
	flag.StringVar(&CmdLine.Config, "config", "", "path to goProbe's configuration file (required)")
	flag.BoolVar(&CmdLine.Version, "version", false, "print goProbe's version and exit")

	flag.BoolVar(&CmdLine.Profiling, "profiling", false, "enable profiling")
	flag.StringVar(&CmdLine.ProfilingOutputDir, "profiling-output-dir", "", "directory to store CPU and memory profile in")

	flag.Parse()

	if CmdLine.Config == "" && !CmdLine.Version {
		flag.PrintDefaults()
		return errors.New("No configuration file provided")
	}
	return nil
}
