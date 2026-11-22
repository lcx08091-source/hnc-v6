//go:build !linux && !android

package main

func queryDirStatfsPlatform(path string) (quickStatfsInfo, error) {
	_ = path
	return quickStatfsInfo{Supported: false}, nil
}
