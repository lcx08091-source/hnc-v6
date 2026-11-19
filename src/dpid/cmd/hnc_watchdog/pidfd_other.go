//go:build !linux

package main

import "os"

func pidfdProcessAlive(p *os.Process) (alive bool, supported bool) {
	return false, false
}

func pidfdAlive(p *os.Process) (alive bool, supported bool) {
	return false, false
}
