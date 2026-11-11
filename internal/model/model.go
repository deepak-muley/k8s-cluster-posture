// Package model holds the scan report types shared by collectors and writers.
package model

import "time"

// Status is the outcome of one control against one resource, or against the cluster.
type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusNotAssessable Status = "not_assessable"
	StatusError         Status = "error"
)

// Severity ranks a failing finding. Pass and not-assessable rows keep the
// control's severity so the catalog stays the source of truth.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Scope separates platform namespaces from workload namespaces.
type Scope string

const (
	ScopePlatform Scope = "platform"
	ScopeWorkload Scope = "workload"
	ScopeCluster  Scope = "cluster"
)

// Source names which collector produced a finding.
type Source string

const (
	SourceNative    Source = "native"
	SourceTrivy     Source = "trivy"
	SourceKubescape Source = "kubescape"
)

// Finding is one row in the report.
type Finding struct {
	ControlID   string   `json:"controlID"`
	Domain      string   `json:"domain"`
	Title       string   `json:"title"`
	DocURL      string   `json:"docURL,omitempty"`
	Status      Status   `json:"status"`
	Severity    Severity `json:"severity"`
	Resource    string   `json:"resource,omitempty"`
	Scope       Scope    `json:"scope,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Source      Source   `json:"source"`
	Agreements  []Source `json:"agreements,omitempty"`
}

// Collector records whether an external tool or the native checks ran.
type Collector struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Cluster is identity for the report header. It never includes credentials.
type Cluster struct {
	Context                  string `json:"context,omitempty"`
	Server                   string `json:"server,omitempty"`
	Version                  string `json:"version,omitempty"`
	Nodes                    int    `json:"nodes"`
	Namespaces               int    `json:"namespaces"`
	CNI                      string `json:"cni,omitempty"`
	CNIEnforcesNetworkPolicy string `json:"cniEnforcesNetworkPolicy,omitempty"`
	ListErrors               string `json:"listErrors,omitempty"`
}

// DomainCount is the summary row for one docs domain.
type DomainCount struct {
	Domain        string `json:"domain"`
	Title         string `json:"title"`
	Fail          int    `json:"fail"`
	Pass          int    `json:"pass"`
	NotAssessable int    `json:"notAssessable"`
	Error         int    `json:"error"`
}

// Report is the full scan result written to JSON and Markdown.
type Report struct {
	GeneratedAt time.Time     `json:"generatedAt"`
	Cluster     Cluster       `json:"cluster"`
	Collectors  []Collector   `json:"collectors"`
	Summary     []DomainCount `json:"summary"`
	Findings    []Finding     `json:"findings"`
}

// SeverityRank orders severities so --fail-on can compare them.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// FailsAtOrAbove reports whether any failing finding meets the threshold.
func FailsAtOrAbove(findings []Finding, threshold Severity) bool {
	min := SeverityRank(threshold)
	for _, f := range findings {
		if f.Status == StatusFail && SeverityRank(f.Severity) >= min {
			return true
		}
	}
	return false
}
