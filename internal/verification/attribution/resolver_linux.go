//go:build linux

package attribution

import (
	"io/fs"
	"os"
)

type osProcFS struct{}

func (osProcFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (osProcFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(name)
}

func (osProcFS) Readlink(name string) (string, error) {
	return os.Readlink(name)
}

func ResolveLocalSourceOwner(flow Flow) (Result, error) {
	return NewResolver("/proc", osProcFS{}).ResolveLocalSourceOwner(flow)
}
