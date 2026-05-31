// Package version exposes build-time version info. The Version variable
// is set via -ldflags at build time (see Makefile).
package version

// Version is the build version, set via -ldflags. Defaults to "dev" for
// local builds.
var Version = "dev"

// Commit is the git commit hash, set via -ldflags.
var Commit = "unknown"

// BuildDate is the build timestamp, set via -ldflags.
var BuildDate = "unknown"
