package collect

import (
	"strings"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

// NormalizeResource turns tool-specific ids into namespace/Kind/name when it can.
func NormalizeResource(id string) string {
	id = strings.Trim(id, "/")
	if id == "" {
		return ""
	}
	parts := strings.Split(id, "/")
	for i, part := range parts {
		if !isKind(part) {
			continue
		}
		if i >= 1 && i+1 < len(parts) && !isAPIVersion(parts[i-1]) {
			return parts[i-1] + "/" + part + "/" + parts[i+1]
		}
		if i+2 < len(parts) {
			return parts[i+1] + "/" + part + "/" + parts[i+2]
		}
		if i+1 < len(parts) {
			return part + "/" + parts[i+1]
		}
	}
	return id
}

func isKind(s string) bool {
	if s == "" {
		return false
	}
	return s[0] >= 'A' && s[0] <= 'Z'
}

func isAPIVersion(s string) bool {
	if strings.Contains(s, ".") {
		return true
	}
	return len(s) > 1 && (s[0] == 'v' || s[0] == 'V') && s[1] >= '0' && s[1] <= '9'
}

// MapTitle matches an external finding title to a native control id.
func MapTitle(title string) string {
	t := strings.ToLower(title)
	switch {
	case strings.Contains(t, "docker.sock") || strings.Contains(t, "containerd.sock") || strings.Contains(t, "runtime socket"):
		return "BYP-001"
	case strings.Contains(t, "privileged") && (strings.Contains(t, "host pid") || strings.Contains(t, "hostpid") || strings.Contains(t, "host network") || strings.Contains(t, "hostnetwork")):
		return "BYP-002"
	case strings.Contains(t, "privileged"):
		return "PSS-001"
	case strings.Contains(t, "hostpid"), strings.Contains(t, "host pid"), strings.Contains(t, "hostnetwork"),
		strings.Contains(t, "host network"), strings.Contains(t, "hostipc"), strings.Contains(t, "host ipc"),
		strings.Contains(t, "hostpath"), strings.Contains(t, "host path"):
		return "PSS-001"
	case strings.Contains(t, "allowprivilegeescalation"), strings.Contains(t, "privilege escalation"),
		strings.Contains(t, "run as non-root"), strings.Contains(t, "runasnonroot"), strings.Contains(t, "non-root"),
		strings.Contains(t, "seccomp"), strings.Contains(t, "capabilities"):
		return "PSS-002"
	case strings.Contains(t, "memory limit"), strings.Contains(t, "memory not limited"):
		return "PSS-003"
	case strings.Contains(t, "latest"):
		return "IMG-002"
	case strings.Contains(t, "digest"), strings.Contains(t, "image tag"):
		return "IMG-001"
	case strings.Contains(t, "automount"):
		return "SEC-002"
	case strings.Contains(t, "environment") && strings.Contains(t, "secret"):
		return "SEC-003"
	case strings.Contains(t, "cluster-admin"), strings.Contains(t, "cluster admin"):
		return "RBAC-001"
	case strings.Contains(t, "wildcard"):
		return "RBAC-002"
	default:
		return ""
	}
}

// ApplyMappedControl copies catalog fields when title or id maps to a native control.
// Unmapped findings stay in the ecosystem domain.
func ApplyMappedControl(f model.Finding, externalID, title string) model.Finding {
	controlID := MapTitle(title)
	if controlID == "" {
		f.ControlID = externalID
		f.Domain = catalog.DomainEcosystem
		if f.Title == "" {
			f.Title = title
		}
		return f
	}
	c, ok := catalog.ByID(controlID)
	if !ok {
		f.ControlID = externalID
		f.Domain = catalog.DomainEcosystem
		return f
	}
	f.ControlID = c.ID
	f.Domain = c.Domain
	f.Title = c.Title
	f.DocURL = c.DocURL
	f.Severity = c.Severity
	f.Remediation = c.Remediation
	return f
}

// ParseSeverity maps tool severities onto the report scale.
func ParseSeverity(raw string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	case "info", "informational", "none":
		return model.SeverityInfo
	default:
		return model.SeverityMedium
	}
}
