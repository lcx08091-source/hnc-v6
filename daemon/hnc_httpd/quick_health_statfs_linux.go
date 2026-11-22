//go:build linux || android

package main

import "syscall"

const linuxTmpfsMagic uint64 = 0x01021994

func queryDirStatfsPlatform(path string) (quickStatfsInfo, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return quickStatfsInfo{}, err
	}
	unit := int64(st.Frsize)
	if unit <= 0 {
		unit = int64(st.Bsize)
	}
	if unit <= 0 {
		unit = 4096
	}
	uUnit := uint64(unit)
	total := st.Blocks * uUnit
	avail := st.Bavail * uUnit
	if avail > total {
		avail = total
	}
	free := st.Bfree * uUnit
	if free > total {
		free = total
	}
	var used uint64
	if total >= free {
		used = total - free
	}
	fsMagic := uint64(uint32(st.Type))
	return quickStatfsInfo{
		Supported:  true,
		FSType:     fsMagic,
		IsTmpfs:    fsMagic == linuxTmpfsMagic,
		TotalBytes: total,
		FreeBytes:  avail,
		UsedBytes:  used,
	}, nil
}
