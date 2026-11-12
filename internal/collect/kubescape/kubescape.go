// Package kubescape runs Kubescape framework scans when the binary is installed.
package kubescape

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

// Options configures one Kubescape invocation.
// The kube context comes from the process environment, the same way kubectl does.
type Options struct {
	Kubeconfig string
	Namespace  string
	Runner     runexec.Runner
}

// frameworks is the set for a self-managed cluster such as kind or NKP.
// cis-v1.12.0 is the vanilla CIS Kubernetes benchmark. The EKS, AKS, and
// GKE benchmarks are different catalogs. soc2 adds ingress TLS and
// PersistentVolume encryption, which the native checks do not cover.
const frameworks = "nsa,mitre,cis-v1.12.0,soc2"

// Collect runs the NSA, MITRE, CIS, and SOC2 frameworks.
// A failed control becomes a finding. A skipped control, usually because
// the Kubescape node-agent is absent, becomes not assessable.
func Collect(ctx context.Context, opt Options) ([]model.Finding, model.Collector) {
	runner := opt.Runner
	if runner == nil {
		runner = runexec.Local{}
	}
	path, err := runner.LookPath("kubescape")
	if err != nil {
		return nil, model.Collector{Name: "kubescape", Status: "skipped", Detail: "kubescape not found on PATH"}
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
		return nil, model.Collector{Name: "kubescape", Status: "error", Detail: detail}
	}
	status := model.Collector{Name: "kubescape", Status: "ran"}
	if runErr != nil {
		status.Detail = "kubescape exited non-zero; JSON findings were parsed"
	}
	return findings, status
}

func args(opt Options) []string {
	out := []string{"scan", "framework", frameworks, "--format", "json", "--format-version", "v2"}
	if opt.Kubeconfig != "" {
		out = append(out, "--kubeconfig", opt.Kubeconfig)
	}
	if opt.Namespace != "" {
		out = append(out, "--include-namespaces", opt.Namespace)
	}
	return out
}

// Command is the kubescape invocation Collect will run.
func Command(opt Options) string {
	return runexec.Format("kubescape", args(opt))
}

// Parse converts Kubescape JSON into findings. Several output shapes are accepted.
func Parse(data []byte) ([]model.Finding, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("kubescape returned empty output")
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("kubescape JSON: %w", err)
	}
	if !knownShape(root) {
		return nil, errors.New("kubescape JSON did not match a results document")
	}
	seen := map[string]bool{}
	var raw []rawControl
	walk(root, "", &raw, seen)
	findings := make([]model.Finding, 0, len(raw))
	for _, item := range raw {
		externalID := "KS-" + item.id
		if item.id == "" {
			externalID = "KS-UNKNOWN"
		}
		finding := model.Finding{
			Title:    item.name,
			Status:   model.StatusFail,
			Severity: model.SeverityMedium,
			Resource: item.resource,
			Evidence: item.name,
			Source:   model.SourceKubescape,
			DocURL:   "https://kubescape.io/docs/frameworks-and-controls/",
		}
		if item.skipped {
			finding.Status = model.StatusNotAssessable
			finding.Severity = collect.ParseSeverity(item.severity)
			finding.Scope = model.ScopeCluster
			finding.Evidence = skipEvidence(item.reason)
			finding.Remediation = skipRemediation(item.reason)
		} else if item.name != "" {
			finding.Evidence = item.id + " " + item.name
		}
		finding = collect.ApplyMappedControl(finding, externalID, item.name)
		if item.skipped {
			finding.Status = model.StatusNotAssessable
		}
		if finding.Domain == catalog.DomainEcosystem && finding.Title == "" {
			finding.Title = item.name
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

type rawControl struct {
	id       string
	name     string
	resource string
	skipped  bool
	reason   string
	severity string
}

func knownShape(v any) bool {
	obj, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"results", "resources", "controls", "summaryDetails", "frameworkName", "type", "summary"} {
		if _, ok := obj[key]; ok {
			return true
		}
	}
	return false
}

func walk(v any, inherited string, out *[]rawControl, seen map[string]bool) {
	switch node := v.(type) {
	case map[string]any:
		resource := inherited
		if id := stringField(node, "resourceID", "resourceId"); id != "" {
			resource = collect.NormalizeResource(id)
		}
		if cid := stringField(node, "controlID", "controlId"); cid != "" {
			word := statusWord(node["status"])
			switch {
			case isFailWord(word):
				// summaryDetails repeats each failed control with an empty
				// resourceIDs map. The resource rows are under results.
				if _, summary := node["resourceIDs"]; summary {
					break
				}
				name := stringField(node, "name", "controlName")
				targets := resourceIDs(node["resources"])
				if len(targets) == 0 {
					if resource != "" {
						targets = []string{resource}
					} else {
						targets = []string{""}
					}
				}
				for _, target := range targets {
					key := cid + "\x00" + target
					if seen[key] {
						continue
					}
					seen[key] = true
					*out = append(*out, rawControl{id: cid, name: name, resource: target})
				}
			case word == "skipped":
				key := cid + "\x00skipped"
				if seen[key] {
					break
				}
				seen[key] = true
				*out = append(*out, rawControl{
					id:       cid,
					name:     stringField(node, "name", "controlName"),
					skipped:  true,
					reason:   skipInfo(node),
					severity: stringField(node, "severity"),
				})
			}
		}
		for _, child := range node {
			walk(child, resource, out, seen)
		}
	case []any:
		for _, child := range node {
			walk(child, inherited, out, seen)
		}
	}
}

func resourceIDs(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if id := stringField(obj, "resourceID", "resourceId"); id != "" {
			out = append(out, collect.NormalizeResource(id))
		}
	}
	return out
}

func statusWord(v any) string {
	switch status := v.(type) {
	case string:
		return strings.ToLower(strings.TrimSpace(status))
	case map[string]any:
		if inner, ok := status["status"]; ok {
			return statusWord(inner)
		}
	}
	return ""
}

func skipInfo(node map[string]any) string {
	switch raw := node["statusInfo"].(type) {
	case map[string]any:
		if info := stringField(raw, "info"); info != "" {
			return info
		}
		return stringField(raw, "subStatus")
	case string:
		return raw
	default:
		if m, ok := node["status"].(map[string]any); ok {
			if info := stringField(m, "info"); info != "" {
				return info
			}
			return stringField(m, "subStatus")
		}
		return ""
	}
}

func skipEvidence(info string) string {
	lower := strings.ToLower(info)
	switch {
	case strings.Contains(lower, "manual"):
		return "Kubescape marks this control as manual review."
	case strings.Contains(info, "ControlPlaneInfo"):
		return "Control-plane files are not visible from the API. Kubescape needs its node-agent for this check."
	case strings.Contains(info, "Kubelet"):
		return "Kubelet configuration is not visible from the API. Kubescape needs its node-agent for this check."
	case strings.Contains(info, "CNIInfo"):
		return "CNI configuration on the node is not visible from the API. Kubescape needs its node-agent for this check."
	case strings.Contains(info, "KubeProxyInfo"):
		return "kube-proxy configuration on the node is not visible from the API. Kubescape needs its node-agent for this check."
	case info != "":
		return info
	default:
		return "Kubescape did not evaluate this control."
	}
}

func skipRemediation(info string) string {
	if strings.Contains(strings.ToLower(info), "manual") {
		return "Review this control by hand. Kubescape does not evaluate it from the API."
	}
	return "Install the Kubescape node-agent so the scan can read control-plane, kubelet, and CNI files on the node."
}

func isFailWord(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "failed", "fail", "failure":
		return true
	default:
		return false
	}
}

func stringField(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := obj[key]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if ok && s != "" {
			return s
		}
	}
	return ""
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
