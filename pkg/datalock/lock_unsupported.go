//go:build !linux

package datalock

import "errors"

// AcquireDataDirLock fails closed on platforms without a supported advisory lock.
func AcquireDataDirLock(string) (func() error, error) {
	return nil, errors.New("data directory locking is unsupported on this platform")
}
