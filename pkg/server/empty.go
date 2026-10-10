package server

import (
	"context"
	"io"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
)

// emptyStorage is the storage of a user that has never logged in. Writes
// are impossible because no token can exist for such a user.
type emptyStorage struct{}

func (emptyStorage) Get(_ context.Context, p string) (*rs.Document, *rs.FolderListing, error) {
	if rs.IsFolderPath(p) {
		return nil, rs.NewFolderListing(rs.Metadata{Path: p, IsFolder: true}), nil
	}
	return nil, nil, rs.ErrNotFound
}

func (emptyStorage) Head(_ context.Context, p string) (*rs.Metadata, error) {
	if rs.IsFolderPath(p) {
		return &rs.Metadata{Path: p, IsFolder: true}, nil
	}
	return nil, rs.ErrNotFound
}

func (emptyStorage) Put(context.Context, string, io.Reader, int64, string, rsserver.Condition) (*rsserver.PutResult, error) {
	return nil, rs.ErrNotFound
}

func (emptyStorage) Delete(context.Context, string, rsserver.Condition) (string, error) {
	return "", rs.ErrNotFound
}
