package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"io/fs"
	"os"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
)

// combinedFS is a filesystem that routes paths first by checking the local filesystem
// and then the coreruleset rootfs.
type combinedFS struct {
	corerulesetFS fs.FS // coreruleset rootfs
}

func (c *combinedFS) Open(name string) (fs.File, error) {
	// First try the local filesystem using os.Open directly
	file, localFileErr := os.Open(name)
	if localFileErr == nil {
		return file, nil
	}

	// Then try the coreruleset rootfs
	corerulesetFile, corerulesetErr := c.corerulesetFS.Open(name)
	if corerulesetErr == nil {
		return corerulesetFile, nil
	}

	return nil, localFileErr // return the local file error since the coreruleset fs is the last resort
}

var rootFS fs.FS

func init() {
	rootFS = &combinedFS{
		corerulesetFS: coreruleset.FS,
	}
}
