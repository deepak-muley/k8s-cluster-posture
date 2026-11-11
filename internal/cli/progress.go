package cli

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type logger struct {
	mu sync.Mutex
	w  io.Writer
}

func newLogger(w io.Writer) *logger {
	if w == nil {
		w = io.Discard
	}
	return &logger{w: w}
}

func (l *logger) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// prefixWriter turns tool stderr into timestamped lines. Carriage returns count
// as line breaks so progress bars show up instead of sitting in a buffer.
type prefixWriter struct {
	dst    *logger
	prefix string
	buf    []byte
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.buf = append(p.buf, b...)
	for {
		i := bytes.IndexAny(p.buf, "\n\r")
		if i < 0 {
			break
		}
		line := strings.TrimSpace(string(p.buf[:i]))
		p.buf = append([]byte(nil), p.buf[i+1:]...)
		if line == "" {
			continue
		}
		p.dst.printf("%s: %s", p.prefix, line)
	}
	return len(b), nil
}
