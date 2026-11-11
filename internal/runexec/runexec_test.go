package runexec

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunCopiesStderr(t *testing.T) {
	var stderr bytes.Buffer
	ctx := WithStderr(context.Background(), &stderr)
	stdout, _, err := Local{}.Run(ctx, "sh", []string{"-c", "echo out; echo err >&2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stdout), "out") {
		t.Fatalf("stdout %q", stdout)
	}
	if !strings.Contains(stderr.String(), "err") {
		t.Fatalf("stderr %q", stderr.String())
	}
}
