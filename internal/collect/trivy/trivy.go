// Package trivy runs the Trivy Kubernetes scanner when the binary is installed.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/collect"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
	"github.com/deepak-muley/k8s-cluster-posture/internal/runexec"
)

// Options configures one Trivy invocation.
// The kube context comes from the process environment, the same way kubectl does.
type Options struct {
	Kubeconfig string
	Namespace  string
	Runner     runexec.Runner
}

// Collect runs `trivy k8s` and converts failures into findings.
// A missing binary is a skipped collector, not a scan failure.
func Collect(ctx context.Context, opt Options) ([]model.Finding, model.Collector) {
	runner := opt.Runner
	if runner == nil {
		runner = runexec.Local{}
	}
	path, err := runner.LookPath("trivy")
	if err != nil {
		return nil, model.Collector{Name: "trivy", Status: "skipped", Detail: "trivy not found on PATH"}
	}
	stdout, stderr, runErr := runner.Run(ctx, path, args(opt), nil)
	findings, parseErr := Parse(extractJSON(stdout))
	if parseErr != nil {
		detail := parseErr.Error()
		if runErr != nil {
			detail = runErr.Error() + ": " + detail
		}
		if tail := tailText(stderr, 400); tail != "" {
			detail += ": " + tail
		}
		return nil, model.Collector{Name: "trivy", Status: "error", Detail: detail}
	}
	status := model.Collector{Name: "trivy", Status: "ran"}
	if runErr != nil {
		status.Detail = "trivy exited non-zero; JSON findings were parsed"
	}
	return findings, status
}

func args(opt Options) []string {
	// vuln runs in the same invocation as misconfig and secret. Image CVEs
	// land in the posture report as TRIVY-VULN. The node OS image is not
	// part of this scan.
	// --disable-node-collector skips the privileged node-collector Job.
	// That Job's active deadline is about five minutes and is not the
	// client --timeout. On kind it usually dies with DeadlineExceeded
	// while pulling ghcr.io/aquasecurity/node-collector, and Trivy then
	// exits with no JSON, dropping the misconfig, secret, and image
	// results. Node filesystem checks are host facts this scanner leaves
	// not_assessable.
	out := []string{
		"k8s",
		"--quiet",
		"--timeout", "12m",
		"--disable-node-collector",
		"--format", "json",
		"--report", "all",
		"--scanners", "misconfig,secret,vuln",
	}
	if opt.Kubeconfig != "" {
		out = append(out, "--kubeconfig", opt.Kubeconfig)
	}
	if opt.Namespace != "" {
		out = append(out, "--include-namespaces", opt.Namespace)
	}
	return out
}

// Command is the trivy invocation Collect will run.
func Command(opt Options) string {
	return runexec.Format("trivy", args(opt))
}

type report struct {
	SchemaVersion int        `json:"SchemaVersion"`
	ClusterName   string     `json:"ClusterName"`
	Resources     []resource `json:"Resources"`
	Results       []result   `json:"Results"`
}

type resource struct {
	Namespace string   `json:"Namespace"`
	Kind      string   `json:"Kind"`
	Name      string   `json:"Name"`
	Results   []result `json:"Results"`
}

type result struct {
	Target            string             `json:"Target"`
	Misconfigurations []misconfiguration `json:"Misconfigurations"`
	Vulnerabilities   []vulnerability    `json:"Vulnerabilities"`
	Secrets           []secretFinding    `json:"Secrets"`
}

type misconfiguration struct {
	ID         string `json:"ID"`
	Title      string `json:"Title"`
	Message    string `json:"Message"`
	Severity   string `json:"Severity"`
	PrimaryURL string `json:"PrimaryURL"`
	Status     string `json:"Status"`
	Resolution string `json:"Resolution"`
}

type vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

type secretFinding struct {
	RuleID   string `json:"RuleID"`
	Title    string `json:"Title"`
	Severity string `json:"Severity"`
	Category string `json:"Category"`
}

// Parse converts a Trivy cluster JSON report into findings.
func Parse(data []byte) ([]model.Finding, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("trivy returned empty output")
	}
	var rep report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("trivy JSON: %w", err)
	}
	if rep.Resources == nil && rep.Results == nil && rep.SchemaVersion == 0 && rep.ClusterName == "" {
		return nil, errors.New("trivy JSON did not match the cluster report schema")
	}
	var findings []model.Finding
	if len(rep.Resources) == 0 && len(rep.Results) > 0 {
		findings = append(findings, findingsFromResult("", "", "", rep.Results)...)
	}
	for _, res := range rep.Resources {
		findings = append(findings, findingsFromResult(res.Namespace, res.Kind, res.Name, res.Results)...)
	}
	return findings, nil
}

func findingsFromResult(namespace, kind, name string, results []result) []model.Finding {
	ref := resourceRef(namespace, kind, name)
	var out []model.Finding
	var vulns []vulnerability
	var secrets []secretFinding
	for _, result := range results {
		for _, mis := range result.Misconfigurations {
			if !strings.EqualFold(mis.Status, "FAIL") {
				continue
			}
			evidence := mis.Message
			if evidence == "" {
				evidence = mis.Title
			}
			finding := model.Finding{
				Title:       mis.Title,
				Status:      model.StatusFail,
				Severity:    collect.ParseSeverity(mis.Severity),
				Resource:    ref,
				Scope:       scopeOf(namespace),
				Evidence:    evidence,
				DocURL:      mis.PrimaryURL,
				Remediation: mis.Resolution,
				Source:      model.SourceTrivy,
			}
			id := mis.ID
			if id == "" {
				id = "MISCONFIG"
			}
			if mapped := trivyControlID(mis); mapped != "" {
				finding = collect.ApplyMappedControl(finding, "TRIVY-"+id, mapped)
			} else {
				finding = collect.ApplyMappedControl(finding, "TRIVY-"+id, mis.Title)
			}
			out = append(out, finding)
		}
		vulns = append(vulns, result.Vulnerabilities...)
		secrets = append(secrets, result.Secrets...)
	}
	if len(vulns) > 0 {
		out = append(out, vulnFinding(ref, namespace, vulns))
	}
	if len(secrets) > 0 {
		out = append(out, secretSummary(ref, namespace, secrets))
	}
	return out
}

func trivyControlID(mis misconfiguration) string {
	switch mis.ID {
	case "KSV001":
		return "privilege escalation"
	case "KSV003":
		return "capabilities"
	case "KSV009":
		return "host network"
	case "KSV012":
		return "run as non-root"
	case "KSV013":
		return "image tag latest"
	case "KSV016":
		return "memory limit"
	case "KSV017":
		return "privileged container"
	case "KSV023":
		text := strings.ToLower(mis.Title + " " + mis.Message)
		if strings.Contains(text, "docker.sock") || strings.Contains(text, "containerd.sock") {
			return "docker.sock host path"
		}
		return "host path"
	default:
		return ""
	}
}

func vulnFinding(ref, namespace string, vulns []vulnerability) model.Finding {
	counts := map[model.Severity]int{}
	var samples []string
	highest := model.SeverityInfo
	for _, vuln := range vulns {
		sev := collect.ParseSeverity(vuln.Severity)
		counts[sev]++
		if model.SeverityRank(sev) > model.SeverityRank(highest) {
			highest = sev
		}
		if len(samples) < 5 && vuln.VulnerabilityID != "" {
			samples = append(samples, vuln.VulnerabilityID+" "+vuln.PkgName)
		}
	}
	evidence := fmt.Sprintf("critical=%d high=%d medium=%d low=%d",
		counts[model.SeverityCritical], counts[model.SeverityHigh], counts[model.SeverityMedium], counts[model.SeverityLow])
	if len(samples) > 0 {
		evidence += "; examples: " + strings.Join(samples, ", ")
	}
	return model.Finding{
		ControlID:   "TRIVY-VULN",
		Domain:      catalog.DomainEcosystem,
		Title:       "Image vulnerabilities",
		Status:      model.StatusFail,
		Severity:    highest,
		Resource:    ref,
		Scope:       scopeOf(namespace),
		Evidence:    evidence,
		Remediation: "Rebuild the image with patched packages and pin it by digest.",
		Source:      model.SourceTrivy,
	}
}

func secretSummary(ref, namespace string, secrets []secretFinding) model.Finding {
	highest := model.SeverityInfo
	var parts []string
	for _, secret := range secrets {
		sev := collect.ParseSeverity(secret.Severity)
		if model.SeverityRank(sev) > model.SeverityRank(highest) {
			highest = sev
		}
		label := secret.RuleID
		if secret.Title != "" {
			if label != "" {
				label += ": " + secret.Title
			} else {
				label = secret.Title
			}
		}
		if label == "" {
			label = secret.Category
		}
		if label != "" {
			parts = append(parts, label)
		}
	}
	return model.Finding{
		ControlID:   "TRIVY-SECRET",
		Domain:      catalog.DomainEcosystem,
		Title:       "Secret material in scanned objects",
		Status:      model.StatusFail,
		Severity:    highest,
		Resource:    ref,
		Scope:       scopeOf(namespace),
		Evidence:    strings.Join(parts, ", "),
		Remediation: "Remove the credential from the image or manifest and rotate it.",
		Source:      model.SourceTrivy,
	}
}

func resourceRef(namespace, kind, name string) string {
	if kind == "" && name == "" {
		return ""
	}
	if namespace == "" {
		return kind + "/" + name
	}
	return namespace + "/" + kind + "/" + name
}

func scopeOf(namespace string) model.Scope {
	switch namespace {
	case "":
		return model.ScopeCluster
	case "kube-system", "kube-public", "kube-node-lease":
		return model.ScopePlatform
	default:
		return model.ScopeWorkload
	}
}

func extractJSON(raw []byte) []byte {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] == '{' || raw[0] == '[' {
		return raw
	}
	start := bytes.IndexByte(raw, '{')
	end := bytes.LastIndexByte(raw, '}')
	if start >= 0 && end > start {
		return raw[start : end+1]
	}
	return raw
}

func tailText(raw []byte, n int) string {
	s := strings.TrimSpace(string(raw))
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
