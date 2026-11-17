//go:build !darwin

package main

// waitExitKqueue is darwin-only; elsewhere the caller polls getppid.
func waitExitKqueue(int) bool { return false }
