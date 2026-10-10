package backup

import "errors"

var ErrLocked = errors.New("data directory is already in use")
