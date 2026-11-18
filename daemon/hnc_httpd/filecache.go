// Package output - filecache.go: Unified stat-stamped file cache (ino + size + mtime).
// Eliminates uncached per-tick os.ReadFile + json.Unmarshal churn in entity.go and
// auto_expand.go while preventing lock-drop ABA cache overwrites.
package main

import (
	"os"
	"sync"
	"syscall"
)

type fileStamp struct {
	ino   uint64
	size  int64
	mtime int64
}

type CachedFile[T any] struct {
	mu    sync.Mutex
	path  string
	parse func([]byte) (T, error)
	stamp fileStamp
	val   T
	valid bool
}

func NewCachedFile[T any](path string, parse func([]byte) (T, error)) *CachedFile[T] {
	return &CachedFile[T]{path: path, parse: parse}
}

func statOf(fi os.FileInfo) fileStamp {
	var ino uint64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		ino = uint64(st.Ino)
	}
	return fileStamp{ino: ino, size: fi.Size(), mtime: fi.ModTime().UnixNano()}
}

func (c *CachedFile[T]) Get() (T, error) {
	fi, err := os.Stat(c.path)
	if err != nil {
		var zero T
		return zero, err
	}
	cur := statOf(fi)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.valid && c.stamp == cur {
		return c.val, nil
	}
	raw, err := os.ReadFile(c.path)
	if err != nil {
		var zero T
		return zero, err
	}
	fiAfter, err := os.Stat(c.path)
	if err != nil {
		var zero T
		return zero, err
	}
	parsed, err := c.parse(raw)
	if err != nil {
		var zero T
		return zero, err
	}
	c.val = parsed
	c.stamp = statOf(fiAfter)
	c.valid = true
	return c.val, nil
}
