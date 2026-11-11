// Package runexec shells out to optional scanners.
package runexec

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
)

// Runner looks up a binary and runs it.
type Runner interface {
	LookPath(file string) (string, error)
	Run(ctx context.Context, name string, args []string, extraEnv []string) (stdout, stderr []byte, err error)
}

type stderrKey struct{}

// WithStderr copies a command's stderr to w while the command runs.
// Stdout stays captured so JSON output can still be parsed.
func WithStderr(ctx context.Context, w io.Writer) context.Context {
	return context.WithValue(ctx, stderrKey{}, w)
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
	if w, ok := ctx.Value(stderrKey{}).(io.Writer); ok && w != nil {
		cmd.Stderr = io.MultiWriter(&stderr, w)
	}
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
