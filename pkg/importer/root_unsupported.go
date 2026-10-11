//go:build !linux

package importer

import (
	"context"
	"errors"
	"os"
)

type importRoot struct{}

func openImportRoot(string) (*importRoot, error) { return nil, errUnsupportedPlatform }
func (*importRoot) close()                       {}
func (*importRoot) clone() (*importRoot, error)  { return nil, errUnsupportedPlatform }
func (*importRoot) stat() (os.FileInfo, error)   { return nil, errUnsupportedPlatform }
func (*importRoot) walk(context.Context, chan<- job, string, chan<- outcome) error {
	return errUnsupportedPlatform
}
func (*importRoot) openFile(string) (*os.File, os.FileInfo, error) {
	return nil, nil, errUnsupportedPlatform
}
func (*importRoot) statFile(string) (os.FileInfo, error) {
	return nil, errors.New("unsupported platform")
}
