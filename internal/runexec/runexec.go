// Package runexec shells out to optional scanners.
package runexec

import (
	"bytes"
	"context"
	"os"
	"os/exec"
)

// Runner looks up a binary and runs it.
type Runner interface {
	LookPath(file string) (string, error)
	Run(ctx context.Context, name string, args []string, extraEnv []string) (stdout, stderr []byte, err error)
}

// Local runs commands on the machine.
type Local struct{}

func (Local) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (Local) Run(ctx context.Context, name string, args []string, extraEnv []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
