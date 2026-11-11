package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestControlsPrintsCatalog(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRoot(&out, &out)
	cmd.SetArgs([]string{"controls"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"RBAC-001", "SEC-004", "https://kubernetes.io/docs/concepts/security/pod-security-standards/"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s\n%s", want, text)
		}
	}
}

func TestHelpDescribesScan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := NewRoot(&stdout, &stderr)
	cmd.SetArgs([]string{"help", "scan"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	text := stdout.String()
	for _, want := range []string{"--kubeconfig", "--fail-on", "--skip-tools", "report.json", "not assessable", "Examples:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("scan help missing %q\n%s", want, text)
		}
	}
}

func TestFailOnRejectsUnknownSeverity(t *testing.T) {
	cmd := NewRoot(&bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs([]string{"scan", "--fail-on", "low"})
	err := cmd.Execute()
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 2 {
		t.Fatalf("err = %v", err)
	}
}
