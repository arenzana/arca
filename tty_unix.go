//go:build !windows

package main

import "os"

// openTTY opens the controlling terminal for an interactive approval prompt. On Unix a single
// /dev/tty handle (opened read-write) serves for both reading the answer and writing the prompt,
// so it works even when stdin/stdout are redirected. It's a var so tests can inject a fake terminal.
var openTTY = func() (in, out *os.File, err error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}
