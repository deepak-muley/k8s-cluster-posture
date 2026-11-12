package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func TestMarkdownIncludesFailuresAndSummary(t *testing.T) {
	findings := []model.Finding{
		catalog.Fail("RBAC-001", "ClusterRoleBinding/admin", model.ScopeCluster, "alice is bound to cluster-admin"),
		catalog.Pass("RBAC-002", "no wildcard roles"),
		catalog.NotAssessable("AUTH-001", "not an API object"),
	}
	rep := model.Report{
		GeneratedAt: time.Date(2026, 11, 11, 17, 0, 0, 0, time.UTC),
		Cluster:     model.Cluster{Context: "dev", Server: "https://127.0.0.1:6443", Version: "v1.32.0", Nodes: 3, Namespaces: 4, CNI: "cilium", CNIEnforcesNetworkPolicy: "yes"},
		Collectors:  []model.Collector{{Name: "native", Status: "ran"}, {Name: "trivy", Status: "skipped", Detail: "trivy not found on PATH"}},
		Findings:    findings,
		Summary:     catalog.Summarize(findings),
	}
	md := Markdown(rep)
	for _, want := range []string{
		"# Kubernetes security posture",
		"Context: dev",
		"cilium",
		"trivy: skipped",
		"API access and RBAC",
		"RBAC-001",
		"ClusterRoleBinding/admin",
		"alice is bound to cluster-admin",
		"### Passed",
		"RBAC-002",
		"not_assessable",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n%s", want, md)
		}
	}
}

func TestOutputDirSanitizesContext(t *testing.T) {
	got := OutputDir("dev/cluster:1", time.Date(2026, 11, 11, 1, 2, 3, 0, time.UTC))
	if got != filepath.Join("reports", "posture-report-dev-cluster-1-20261111T010203Z") {
		t.Fatalf("got %s", got)
	}
}
