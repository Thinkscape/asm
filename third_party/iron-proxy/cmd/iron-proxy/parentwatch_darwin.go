//go:build darwin

package main

import (
	"errors"
	"syscall"
)

// waitExitKqueue blocks until pid exits (kqueue EVFILT_PROC/NOTE_EXIT) and
// reports true; false when kqueue cannot watch it (the caller then polls).
func waitExitKqueue(pid int) bool {
	kq, err := syscall.Kqueue()
	if err != nil {
		return false
	}
	defer syscall.Close(kq)
	change := syscall.Kevent_t{
		Ident:  uint64(pid),
		Filter: syscall.EVFILT_PROC,
		Flags:  syscall.EV_ADD | syscall.EV_ONESHOT,
		Fflags: syscall.NOTE_EXIT,
	}
	if _, err := syscall.Kevent(kq, []syscall.Kevent_t{change}, nil, nil); err != nil {
		// ESRCH: the process is already gone.
		return errors.Is(err, syscall.ESRCH)
	}
	events := make([]syscall.Kevent_t, 1)
	for {
		n, err := syscall.Kevent(kq, nil, events, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return false
		}
		if n > 0 {
			return true
		}
	}
}
