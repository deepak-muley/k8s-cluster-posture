package kubescape

import (
	"testing"

	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func TestCommandUsesResolvedContext(t *testing.T) {
	got := Command(Options{Namespace: "shop"})
	want := "kubescape scan framework nsa,mitre,cis-v1.12.0,soc2 --format json --format-version v2 --include-namespaces shop"
	if got != want {
		t.Fatalf("got %s", got)
	}
}

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

func TestParseSkippedControlIsNotAssessable(t *testing.T) {
	raw := []byte(`{
	  "summaryDetails": {
	    "controls": {
	      "C-0092": {
	        "controlID": "C-0092",
	        "name": "CIS-1.1.1 Ensure that the API server pod specification file permissions are set to 600 or more restrictive",
	        "status": "skipped",
	        "severity": "Medium",
	        "statusInfo": {"status": "skipped", "subStatus": "notEvaluated", "info": "missing: hostdata.kubescape.cloud/v1beta0/ControlPlaneInfo"}
	      },
	      "C-0246": {
	        "controlID": "C-0246",
	        "name": "CIS-5.1.7 Avoid use of system:masters group",
	        "status": "skipped",
	        "severity": "High",
	        "statusInfo": {"status": "skipped", "subStatus": "manual review", "info": "Control type is manual-review"}
	      },
	      "C-0186": {
	        "controlID": "C-0186",
	        "name": "Minimize access to secrets",
	        "status": "failed",
	        "resourceIDs": {}
	      }
	    }
	  }
	}`)
	findings, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("len = %d %+v", len(findings), findings)
	}
	byID := map[string]model.Finding{}
	for _, f := range findings {
		byID[f.ControlID] = f
	}
	host := byID["KS-C-0092"]
	if host.Status != model.StatusNotAssessable || host.Scope != model.ScopeCluster {
		t.Fatalf("host = %+v", host)
	}
	if !contains(host.Evidence, "Control-plane files") || !contains(host.Remediation, "node-agent") {
		t.Fatalf("host evidence = %+v", host)
	}
	manual := byID["KS-C-0246"]
	if manual.Status != model.StatusNotAssessable || !contains(manual.Evidence, "manual review") {
		t.Fatalf("manual = %+v", manual)
	}
	if _, ok := byID["KS-C-0186"]; ok {
		t.Fatal("summary failure was imported without a resource")
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
