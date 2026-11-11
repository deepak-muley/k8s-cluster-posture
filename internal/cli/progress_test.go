package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrefixWriterShowsProgressLines(t *testing.T) {
	var buf bytes.Buffer
	w := &prefixWriter{dst: newLogger(&buf), prefix: "trivy"}
	if _, err := w.Write([]byte("scan 10%\rscan 20%\ndone\n")); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	for _, want := range []string{"trivy: scan 10%", "trivy: scan 20%", "trivy: done"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q\n%s", want, text)
		}
	}
}
