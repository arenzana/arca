//go:build windows

package main

import "os"

// openTTY opens the Windows console for an interactive approval prompt. Unlike Unix there is no
// single /dev/tty, so input comes from CONIN$ and the prompt is written to CONOUT$; both bypass
// any stdin/stdout redirection, matching the Unix behavior. It's a var so tests can inject a fake.
var openTTY = func() (in, out *os.File, err error) {
	in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	out, err = os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		in.Close()
		return nil, nil, err
	}
	return in, out, nil
}
