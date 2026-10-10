//go:build !linux

package backup

import (
	"context"
	"errors"

	"github.com/elee1766/gopherstorage/pkg/blob"
	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/meta"
)

// Create fails closed on platforms without the supported atomic no-overwrite rename.
func Create(context.Context, *config.Config, *meta.Store, blob.Store, string, bool) error {
	return errors.New("backup is unsupported on this platform")
}
