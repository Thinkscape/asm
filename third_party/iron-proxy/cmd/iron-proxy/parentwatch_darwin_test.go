//go:build darwin

package main

import (
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParentFromEnv(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    int
		wantErr bool
	}{
		{name: "unset", value: "", want: 0},
		{name: "pid", value: "4242", want: 4242},
		{name: "init is refused", value: "1", wantErr: true},
		{name: "garbage", value: "x1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parentFromEnv(mapEnv(map[string]string{parentPIDEnv: tc.value}))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestWatchParent_ClosesWhenProcessExits(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "0.3")
	require.NoError(t, cmd.Start())
	go func() { _ = cmd.Wait() }()

	done := watchParent(cmd.Process.Pid)
	select {
	case <-done:
		t.Fatal("closed while the process still runs")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("not closed after the process exited")
	}
}

func TestWatchParent_GoneProcessClosesAtOnce(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	require.NoError(t, cmd.Run())

	select {
	case <-watchParent(cmd.Process.Pid):
	case <-time.After(time.Second):
		t.Fatal("not closed for an exited process")
	}
}
