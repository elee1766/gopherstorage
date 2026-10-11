//go:build linux

package importer

import (
	"os"
	"syscall"
)

func sameSourceVersion(a, b os.FileInfo) bool {
	if !os.SameFile(a, b) || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	left, okLeft := a.Sys().(*syscall.Stat_t)
	right, okRight := b.Sys().(*syscall.Stat_t)
	return okLeft && okRight && left.Ctim == right.Ctim
}
