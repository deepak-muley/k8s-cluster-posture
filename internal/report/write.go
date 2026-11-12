package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

// WriteJSON and WriteMarkdown store the report under dir.
func Write(dir string, rep model.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(dir, "report.json"), raw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(rep)), 0o644); err != nil {
		return err
	}
	return nil
}

// Root is the directory that holds generated scan reports.
const Root = "reports"

// OutputDir is the default directory for a scan, under Root.
func OutputDir(contextName string, now time.Time) string {
	safe := sanitize(contextName)
	if safe == "" {
		safe = "cluster"
	}
	name := fmt.Sprintf("posture-report-%s-%s", safe, now.UTC().Format("20060102T150405Z"))
	return filepath.Join(Root, name)
}

func sanitize(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
