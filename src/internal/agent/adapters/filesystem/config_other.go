//go:build !linux

package filesystem

import (
	"io/fs"
	"os"
)

func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

func renameExchange(string, string) error {
	return ErrAtomicUnsupported
}

func renameNoReplace(left, right string) error {
	if err := os.Link(left, right); err != nil {
		if os.IsExist(err) {
			return ErrRevisionConflict
		}
		return err
	}
	// Hard-link creation is atomic and no-replace. The caller removes the
	// staging link after this function returns.
	return nil
}

func ownership(fs.FileInfo) (int, int) {
	return -1, -1
}
