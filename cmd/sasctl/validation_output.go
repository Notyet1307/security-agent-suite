//go:build darwin || linux || windows

package main

import (
	"errors"
	"os"
)

func openValidationOutput(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("agent output must be a regular file")
	}

	file, err := openValidationOutputFile(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("agent output must be a regular file")
	}
	if !os.SameFile(before, info) {
		_ = file.Close()
		return nil, errors.New("agent output changed while opening")
	}
	return file, nil
}
