//go:build !linux

package backup

import (
	"context"
	"errors"

	"github.com/elee1766/gopherstorage/internal/blob"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/meta"
)

// Create fails closed on platforms without the supported atomic no-overwrite rename.
func Create(context.Context, *config.Config, *meta.Store, blob.Store, string, bool) error {
	return errors.New("backup is unsupported on this platform")
}
