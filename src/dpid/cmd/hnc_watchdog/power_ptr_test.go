package main

import "unsafe"

func ptr(b []byte, off int) unsafe.Pointer { return unsafe.Pointer(&b[off]) }
