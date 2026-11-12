//go:build kind

package kindtest

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

const clusterName = "posture-fixture"

func TestKindFixture(t *testing.T) {
	requireBin(t, "kind")
	requireBin(t, "kubectl")
	requireBin(t, "go")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	deleteCluster()
	t.Cleanup(deleteCluster)

	create := exec.CommandContext(ctx, "kind", "create", "cluster",
		"--name", clusterName,
		"--kubeconfig", kubeconfig,
		"--wait", "5m",
	)
	if out, err := create.CombinedOutput(); err != nil {
		t.Fatalf("kind create cluster: %v\n%s", err, out)
	}

	root := moduleRoot(t)
	apply := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "apply", "-f",
		filepath.Join(root, "testdata", "kind", "vulnerable.yaml"))
	if out, err := apply.CombinedOutput(); err != nil {
		t.Fatalf("kubectl apply: %v\n%s", err, out)
	}

	report := scan(t, ctx, root, kubeconfig, true)
	if report.Cluster.ListErrors != "" {
		t.Fatalf("API list errors: %s", report.Cluster.ListErrors)
	}
	for _, finding := range report.Findings {
		if finding.Status == model.StatusError {
			t.Errorf("control %s errored: %s", finding.ControlID, finding.Evidence)
		}
	}

	mustFail(t, report.Findings, "PSS-001", "posture-lab/Pod/privileged")
	mustFail(t, report.Findings, "BYP-002", "posture-lab/Pod/host-share")
	mustFail(t, report.Findings, "BYP-001", "posture-lab/Pod/runtime-socket")
	mustFail(t, report.Findings, "RBAC-001", "ClusterRoleBinding/posture-cluster-admin")
	mustFail(t, report.Findings, "RBAC-002", "ClusterRoleBinding/posture-wildcard")
	mustFail(t, report.Findings, "RBAC-006", "ClusterRoleBinding/posture-wildcard")
	mustFail(t, report.Findings, "RBAC-003", "ClusterRoleBinding/posture-secrets")
	mustFail(t, report.Findings, "SEC-003", "posture-lab/Pod/leaky")
	mustFail(t, report.Findings, "IMG-002", "posture-lab/Pod/leaky")
	mustFail(t, report.Findings, "PSS-003", "posture-lab/Pod/leaky")
	mustFail(t, report.Findings, "NET-004", "posture-lab/Service/exposed")

	mustFail(t, report.Findings, "PSA-002", "Namespace/posture-lab")
	mustFail(t, report.Findings, "NET-001", "Namespace/posture-lab")
	mustFail(t, report.Findings, "NET-002", "Namespace/posture-lab")
	mustFail(t, report.Findings, "IMG-001", "posture-lab/Pod/old-nginx")
	mustFail(t, report.Findings, "SEC-002", "posture-lab/ServiceAccount/reader")
	if report.Cluster.CNI != "kindnet" {
		t.Errorf("CNI = %q, want kindnet", report.Cluster.CNI)
	}
	mustFail(t, report.Findings, "NET-003", "")

	if _, err := exec.LookPath("trivy"); err != nil {
		t.Log("trivy is not on PATH; image CVE assertion skipped")
		return
	}
	withTools := scan(t, ctx, root, kubeconfig, false)
	if !hasFail(withTools.Findings, "TRIVY-VULN", "posture-lab/Pod/old-nginx") {
		t.Fatalf("trivy did not report vulnerabilities for posture-lab/Pod/old-nginx")
	}
}

func scan(t *testing.T, ctx context.Context, root, kubeconfig string, skipTools bool) model.Report {
	t.Helper()
	out := t.TempDir()
	args := []string{"run", "./cmd/posture", "scan", "--kubeconfig", kubeconfig, "--context", "kind-" + clusterName, "--output", out}
	if skipTools {
		args = append(args, "--skip-tools")
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("posture scan: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report model.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func mustFail(t *testing.T, findings []model.Finding, id, resource string) {
	t.Helper()
	if !hasFail(findings, id, resource) {
		t.Errorf("missing fail %s on %s", id, resource)
	}
}

func hasFail(findings []model.Finding, id, resource string) bool {
	for _, finding := range findings {
		if finding.ControlID == id && finding.Status == model.StatusFail && finding.Resource == resource {
			return true
		}
	}
	return false
}

func requireBin(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Fatalf("%s is required for the kind integration test", name)
	}
}

func deleteCluster() {
	cmd := exec.Command("kind", "delete", "cluster", "--name", clusterName)
	_, _ = cmd.CombinedOutput()
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
