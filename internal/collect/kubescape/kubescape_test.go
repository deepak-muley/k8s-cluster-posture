package kubescape

import (
	"testing"

	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func TestParseResults(t *testing.T) {
	raw := []byte(`{
	  "results": [
	    {
	      "resourceID": "default/Pod/web",
	      "controls": [
	        {"controlID": "C-0057", "name": "Privileged container", "status": {"status": "failed"}},
	        {"controlID": "C-0009", "name": "Resource limits", "status": {"status": "passed"}}
	      ]
	    },
	    {
	      "resourceID": "v1/kube-system/Pod/kube-proxy",
	      "controls": [
	        {"controlID": "C-0013", "name": "Non-root containers", "status": "failed"}
	      ]
	    }
	  ]
	}`)
	findings, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("len = %d %+v", len(findings), findings)
	}
	var privileged, nonroot model.Finding
	for _, f := range findings {
		switch f.Resource {
		case "default/Pod/web":
			privileged = f
		case "kube-system/Pod/kube-proxy":
			nonroot = f
		}
	}
	if privileged.ControlID != "PSS-001" || privileged.Source != model.SourceKubescape {
		t.Fatalf("privileged = %+v", privileged)
	}
	if nonroot.ControlID != "PSS-002" || nonroot.Scope != "" && nonroot.Resource != "kube-system/Pod/kube-proxy" {
		t.Fatalf("nonroot = %+v", nonroot)
	}
}

func TestParseSummaryWithNoFailures(t *testing.T) {
	findings, err := Parse([]byte(`{"summaryDetails":{"status":"passed"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %+v", findings)
	}
}

func TestParseRejectsUnknownJSON(t *testing.T) {
	if _, err := Parse([]byte(`{"hello":true}`)); err == nil {
		t.Fatal("expected schema error")
	}
}

func TestParseExtractsPrefixedLogs(t *testing.T) {
	raw := []byte("some log line\n{\"results\":[{\"resourceID\":\"default/Pod/web\",\"controlID\":\"C-0001\",\"name\":\"Wildcard RBAC\",\"status\":\"failed\"}]}\n")
	findings, err := Parse(extractJSON(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ControlID != "RBAC-002" {
		t.Fatalf("got %+v", findings)
	}
}
