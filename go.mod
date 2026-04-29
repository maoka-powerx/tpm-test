// go.mod is like Python's pyproject.toml.
// It has two jobs:
//   1. Give this project a name (the "module" line)
//   2. Track which external libraries you depend on
//      (go get adds those automatically — you don't write them by hand)

module tpm-sidecar

// Minimum Go version required to compile this code.
go 1.22

require (
	github.com/google/go-tpm v0.9.8 // indirect
	golang.org/x/sys v0.8.0 // indirect
)
