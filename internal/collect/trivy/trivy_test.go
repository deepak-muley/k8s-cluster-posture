package trivy

import (
	"context"
	"errors"
	"testing"

	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func TestParseClusterReport(t *testing.T) {
	raw := []byte(`{
	  "SchemaVersion": 2,
	  "ClusterName": "demo",
	  "Resources": [
	    {
	      "Namespace": "default",
	      "Kind": "Pod",
	      "Name": "web",
	      "Results": [
	        {
	          "Misconfigurations": [
	            {"ID": "KSV017", "Title": "Privileged", "Message": "container is privileged", "Severity": "CRITICAL", "Status": "FAIL"},
	            {"ID": "KSV001", "Title": "allowPrivilegeEscalation", "Severity": "HIGH", "Status": "PASS"},
	            {"ID": "KSV099", "Title": "Custom check", "Message": "example", "Severity": "LOW", "Status": "FAIL", "Resolution": "fix it"}
	          ],
	          "Vulnerabilities": [
	            {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "1.1.1", "Severity": "HIGH", "Title": "openssl"}
	          ],
	          "Secrets": [
	            {"RuleID": "aws-access-key", "Title": "AWS access key", "Severity": "CRITICAL", "Match": "should-not-appear"}
	          ]
	        }
	      ]
	    }
	  ]
	}`)
	findings, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]model.Finding{}
	for _, f := range findings {
		seen[f.ControlID] = f
	}
	if seen["PSS-001"].Resource != "default/Pod/web" || seen["PSS-001"].Source != model.SourceTrivy {
		t.Fatalf("privileged mapping = %+v", seen["PSS-001"])
	}
	if _, ok := seen["PSS-002"]; ok {
		t.Fatal("PASS misconfiguration was imported")
	}
	if seen["TRIVY-KSV099"].Domain != "ecosystem" || seen["TRIVY-KSV099"].Severity != model.SeverityLow {
		t.Fatalf("unmapped = %+v", seen["TRIVY-KSV099"])
	}
	if seen["TRIVY-VULN"].Evidence == "" || seen["TRIVY-SECRET"].Evidence == "" {
		t.Fatalf("aggregates = %#v %#v", seen["TRIVY-VULN"], seen["TRIVY-SECRET"])
	}
	if contains(seen["TRIVY-SECRET"].Evidence, "should-not-appear") {
		t.Fatal("secret match text leaked into the report")
	}
}

func TestParseRejectsUnknownJSON(t *testing.T) {
	if _, err := Parse([]byte(`{"hello":true}`)); err == nil {
		t.Fatal("expected schema error")
	}
}

func TestCollectSkipsMissingBinary(t *testing.T) {
	_, status := Collect(context.Background(), Options{Runner: fakeRunner{pathErr: errors.New("not found")}})
	if status.Status != "skipped" {
		t.Fatalf("status = %+v", status)
	}
}

func TestCommandOmitsContext(t *testing.T) {
	got := Command(Options{Namespace: "shop", Kubeconfig: "/tmp/my config"})
	for _, want := range []string{
		"trivy k8s ",
		"--disable-node-collector",
		"--scanners misconfig,secret,vuln",
		"--kubeconfig '/tmp/my config'",
		"--include-namespaces shop",
	} {
		if !contains(got, want) {
			t.Fatalf("command %q missing %q", got, want)
		}
	}
	if contains(got, "--context") || contains(got, "kind-") {
		t.Fatalf("command pins a context: %s", got)
	}
}

type fakeRunner struct {
	pathErr error
}

func (f fakeRunner) LookPath(string) (string, error) {
	if f.pathErr != nil {
		return "", f.pathErr
	}
	return "trivy", nil
}

func (f fakeRunner) Run(context.Context, string, []string, []string) ([]byte, []byte, error) {
	return nil, nil, nil
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
