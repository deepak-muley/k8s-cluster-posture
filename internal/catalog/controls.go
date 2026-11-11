// Package catalog is the control list tied to the Kubernetes security docs.
package catalog

import (
	"fmt"
	"sort"

	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

// Control is one assessable statement in the report.
type Control struct {
	ID                string
	Domain            string
	Title             string
	DocURL            string
	Severity          model.Severity
	Summary           string
	NotAssessableNote string
	Remediation       string
}

const (
	DomainAccess       = "access"
	DomainSecrets      = "secrets"
	DomainWorkload     = "workload"
	DomainBypass       = "bypass"
	DomainNetwork      = "network"
	DomainAdmission    = "admission"
	DomainAudit        = "audit"
	DomainImages       = "images"
	DomainTenancy      = "tenancy"
	DomainWindows      = "windows"
	DomainControlPlane = "controlplane"
	DomainEcosystem    = "ecosystem"
)

// DomainOrder is the report section order, following the security docs.
var DomainOrder = []string{
	DomainAccess,
	DomainSecrets,
	DomainWorkload,
	DomainBypass,
	DomainNetwork,
	DomainAdmission,
	DomainAudit,
	DomainImages,
	DomainTenancy,
	DomainWindows,
	DomainControlPlane,
	DomainEcosystem,
}

// DomainTitle is the human heading for a domain id.
var DomainTitle = map[string]string{
	DomainAccess:       "API access and RBAC",
	DomainSecrets:      "Service accounts and secrets",
	DomainWorkload:     "Workload protection",
	DomainBypass:       "API server bypass",
	DomainNetwork:      "Network",
	DomainAdmission:    "Admission and policy",
	DomainAudit:        "Audit",
	DomainImages:       "Images",
	DomainTenancy:      "Multi-tenancy and placement",
	DomainWindows:      "Windows nodes",
	DomainControlPlane: "Control plane arguments",
	DomainEcosystem:    "Ecosystem scanners",
}

const (
	docAccess    = "https://kubernetes.io/docs/concepts/security/controlling-access/"
	docRBAC      = "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"
	docSecrets   = "https://kubernetes.io/docs/concepts/security/secrets-good-practices/"
	docPSS       = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
	docPSA       = "https://kubernetes.io/docs/concepts/security/pod-security-admission/"
	docBypass    = "https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/"
	docChecklist = "https://kubernetes.io/docs/concepts/security/security-checklist/"
	docAudit     = "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/"
	docTenancy   = "https://kubernetes.io/docs/concepts/security/multi-tenancy/"
	docWindows   = "https://kubernetes.io/docs/concepts/security/windows-security/"
	docEncrypt   = "https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"
	docPolicies  = "https://kubernetes.io/docs/concepts/security/"
)

// All returns the native control catalog in stable order.
func All() []Control {
	out := make([]Control, len(controls))
	copy(out, controls)
	return out
}

// ByID returns a control and whether it exists.
func ByID(id string) (Control, bool) {
	c, ok := byID[id]
	return c, ok
}

// Fail builds a failing finding filled from the catalog.
func Fail(id, resource string, scope model.Scope, evidence string) model.Finding {
	return decorate(id, model.StatusFail, resource, scope, evidence)
}

// Pass builds a passing finding for a control with no violating resources.
func Pass(id, evidence string) model.Finding {
	return decorate(id, model.StatusPass, "", "", evidence)
}

// NotAssessable builds a finding for a fact the API cannot show.
func NotAssessable(id, evidence string) model.Finding {
	return decorate(id, model.StatusNotAssessable, "", model.ScopeCluster, evidence)
}

// Error builds a finding for a list that was forbidden or failed.
func Error(id, evidence string) model.Finding {
	return decorate(id, model.StatusError, "", model.ScopeCluster, evidence)
}

func decorate(id string, status model.Status, resource string, scope model.Scope, evidence string) model.Finding {
	c, ok := byID[id]
	f := model.Finding{
		ControlID: id,
		Status:    status,
		Resource:  resource,
		Scope:     scope,
		Evidence:  evidence,
		Source:    model.SourceNative,
	}
	if !ok {
		f.Domain = DomainEcosystem
		f.Title = id
		f.Severity = model.SeverityInfo
		return f
	}
	f.Domain = c.Domain
	f.Title = c.Title
	f.DocURL = c.DocURL
	f.Severity = c.Severity
	f.Remediation = c.Remediation
	return f
}

// DomainIndex returns the sort position of a domain. Unknown domains sort last.
func DomainIndex(domain string) int {
	for i, d := range DomainOrder {
		if d == domain {
			return i
		}
	}
	return len(DomainOrder)
}

// SortFindings orders findings for a stable report.
func SortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if di, dj := DomainIndex(a.Domain), DomainIndex(b.Domain); di != dj {
			return di < dj
		}
		if a.ControlID != b.ControlID {
			return a.ControlID < b.ControlID
		}
		if ra, rb := statusRank(a.Status), statusRank(b.Status); ra != rb {
			return ra < rb
		}
		return a.Resource < b.Resource
	})
}

func statusRank(s model.Status) int {
	switch s {
	case model.StatusFail:
		return 0
	case model.StatusError:
		return 1
	case model.StatusNotAssessable:
		return 2
	default:
		return 3
	}
}

// Summarize counts findings by domain in catalog order.
func Summarize(findings []model.Finding) []model.DomainCount {
	counts := map[string]*model.DomainCount{}
	for _, domain := range DomainOrder {
		counts[domain] = &model.DomainCount{Domain: domain, Title: DomainTitle[domain]}
	}
	for _, f := range findings {
		row, ok := counts[f.Domain]
		if !ok {
			row = &model.DomainCount{Domain: f.Domain, Title: DomainTitle[f.Domain]}
			if row.Title == "" {
				row.Title = f.Domain
			}
			counts[f.Domain] = row
		}
		switch f.Status {
		case model.StatusFail:
			row.Fail++
		case model.StatusPass:
			row.Pass++
		case model.StatusNotAssessable:
			row.NotAssessable++
		case model.StatusError:
			row.Error++
		}
	}
	out := make([]model.DomainCount, 0, len(DomainOrder))
	seen := map[string]bool{}
	for _, domain := range DomainOrder {
		out = append(out, *counts[domain])
		seen[domain] = true
	}
	var extra []string
	for domain := range counts {
		if !seen[domain] {
			extra = append(extra, domain)
		}
	}
	sort.Strings(extra)
	for _, domain := range extra {
		out = append(out, *counts[domain])
	}
	return out
}

// FormatControls renders the catalog for `posture controls`.
func FormatControls() string {
	var b []byte
	for _, c := range controls {
		b = fmt.Appendf(b, "%-12s %-14s %-10s %s\n    %s\n    %s\n",
			c.ID, c.Domain, c.Severity, c.Title, c.DocURL, c.Summary)
		if c.NotAssessableNote != "" {
			b = fmt.Appendf(b, "    not assessable when: %s\n", c.NotAssessableNote)
		}
		b = append(b, '\n')
	}
	return string(b)
}

var controls = []Control{
	{
		ID: "RBAC-001", Domain: DomainAccess, Severity: model.SeverityHigh,
		Title: "Cluster-admin bindings", DocURL: docRBAC,
		Summary:     "Cluster-admin, or an equivalent wildcard ClusterRole, is bound to a subject outside the platform.",
		Remediation: "Bind cluster-admin only to break-glass groups. Give users a namespaced Role instead.",
	},
	{
		ID: "RBAC-002", Domain: DomainAccess, Severity: model.SeverityHigh,
		Title: "Wildcard verbs or resources", DocURL: docRBAC,
		Summary:     "A Role or ClusterRole granted to a non-platform subject uses a wildcard verb or resource.",
		Remediation: "Replace * verbs and * resources with the API objects the subject actually needs.",
	},
	{
		ID: "RBAC-003", Domain: DomainAccess, Severity: model.SeverityHigh,
		Title: "Secrets list or watch", DocURL: docSecrets,
		Summary:     "A non-platform subject can list or watch Secrets, which returns Secret data.",
		Remediation: "Grant get on named Secrets only when a controller must read them. Do not grant list or watch.",
	},
	{
		ID: "RBAC-004", Domain: DomainAccess, Severity: model.SeverityCritical,
		Title: "nodes/proxy access", DocURL: docBypass,
		Summary:     "A non-platform subject can reach nodes/proxy, which can bypass the API server.",
		Remediation: "Remove nodes/proxy, nodes/*, and wildcard grants from workload identities.",
	},
	{
		ID: "RBAC-005", Domain: DomainAccess, Severity: model.SeverityHigh,
		Title: "Impersonate, escalate, or bind", DocURL: docRBAC,
		Summary:     "A non-platform subject can impersonate users, escalate Roles, or bind ClusterRoles.",
		Remediation: "Drop impersonate, escalate, and bind except for controllers that must grant access.",
	},
	{
		ID: "RBAC-006", Domain: DomainAccess, Severity: model.SeverityHigh,
		Title: "Cluster-wide workload mutation", DocURL: docRBAC,
		Summary:     "A non-platform subject can create or update workloads in every namespace.",
		Remediation: "Move workload verbs into a RoleBinding in the namespace that needs them.",
	},
	{
		ID: "AUTH-001", Domain: DomainAccess, Severity: model.SeverityInfo,
		Title: "system:masters membership", DocURL: docChecklist,
		Summary:           "Membership of system:masters is not stored as an API object the scanner can list.",
		NotAssessableNote: "Group membership lives in the authenticator, not in RBAC objects.",
		Remediation:       "Review the identity provider and client certificates. system:masters bypasses RBAC.",
	},
	{
		ID: "SEC-001", Domain: DomainSecrets, Severity: model.SeverityHigh,
		Title: "Long-lived service account tokens", DocURL: docSecrets,
		Summary:     "A Secret of type kubernetes.io/service-account-token is a non-expiring credential.",
		Remediation: "Delete legacy service account token Secrets and use projected bound tokens.",
	},
	{
		ID: "SEC-002", Domain: DomainSecrets, Severity: model.SeverityMedium,
		Title: "Service account token automount", DocURL: docSecrets,
		Summary:     "A workload ServiceAccount leaves automountServiceAccountToken unset or true.",
		Remediation: "Set automountServiceAccountToken: false on ServiceAccounts that do not call the API.",
	},
	{
		ID: "SEC-003", Domain: DomainSecrets, Severity: model.SeverityMedium,
		Title: "Secrets as environment variables", DocURL: docSecrets,
		Summary:     "A container reads a Secret through env or envFrom, which leaks into logs and crash dumps more easily than a file.",
		Remediation: "Mount Secrets as files, preferably from an emptyDir memory volume or the Secrets Store CSI driver.",
	},
	{
		ID: "SEC-004", Domain: DomainSecrets, Severity: model.SeverityHigh,
		Title: "Encryption at rest for Secrets", DocURL: docEncrypt,
		Summary:           "kube-apiserver is started with --encryption-provider-config.",
		NotAssessableNote: "Managed control planes hide the kube-apiserver Pod spec.",
		Remediation:       "Point kube-apiserver at an EncryptionConfiguration that uses a KMS v2 provider for secrets.",
	},
	{
		ID: "PSA-001", Domain: DomainWorkload, Severity: model.SeverityHigh,
		Title: "Namespace missing Pod Security enforce", DocURL: docPSA,
		Summary:     "The namespace has no pod-security.kubernetes.io/enforce label.",
		Remediation: "Set pod-security.kubernetes.io/enforce to baseline or restricted.",
	},
	{
		ID: "PSA-002", Domain: DomainWorkload, Severity: model.SeverityHigh,
		Title: "Pod Security enforce is privileged", DocURL: docPSA,
		Summary:     "The namespace enforce label is privileged, which allows known privilege escalations.",
		Remediation: "Enforce baseline or restricted. Keep privileged only on namespaces that run trusted host workloads.",
	},
	{
		ID: "PSS-001", Domain: DomainWorkload, Severity: model.SeverityHigh,
		Title: "Pod fails the baseline Pod Security Standard", DocURL: docPSS,
		Summary:     "The Pod uses privileged containers, host namespaces, hostPath, host ports, or disallowed capabilities.",
		Remediation: "Drop privileged, hostPID, hostIPC, hostNetwork, hostPath, and capabilities outside the baseline set.",
	},
	{
		ID: "PSS-002", Domain: DomainWorkload, Severity: model.SeverityMedium,
		Title: "Pod fails the restricted Pod Security Standard", DocURL: docPSS,
		Summary:     "The Pod meets baseline but is missing restricted hardening such as non-root, seccomp, or dropped capabilities.",
		Remediation: "Set runAsNonRoot, seccomp RuntimeDefault, allowPrivilegeEscalation: false, and drop ALL capabilities.",
	},
	{
		ID: "PSS-003", Domain: DomainWorkload, Severity: model.SeverityMedium,
		Title: "Container missing a memory limit", DocURL: docChecklist,
		Summary:     "A container has no memory limit, so it can exhaust the node.",
		Remediation: "Set resources.limits.memory on every container. A LimitRange can force the default.",
	},
	{
		ID: "BYP-001", Domain: DomainBypass, Severity: model.SeverityCritical,
		Title: "hostPath exposes the node or runtime socket", DocURL: docBypass,
		Summary:     "A hostPath mount is /, a container runtime socket, or a parent directory of that socket.",
		Remediation: "Remove hostPath mounts of /, /var, /run, and runtime sockets. Prefer a CSI driver.",
	},
	{
		ID: "BYP-002", Domain: DomainBypass, Severity: model.SeverityCritical,
		Title: "Privileged Pod shares host PID or network", DocURL: docBypass,
		Summary:     "A privileged container also sets hostPID or hostNetwork.",
		Remediation: "Drop privileged and host namespaces. Only node agents should combine them, and they should be platform-scoped.",
	},
	{
		ID: "BYP-003", Domain: DomainBypass, Severity: model.SeverityInfo,
		Title: "Kubelet port and runtime socket file permissions", DocURL: docBypass,
		Summary:           "The kubelet read-only port and socket ownership are node-local settings.",
		NotAssessableNote: "Those settings are not exposed as Kubernetes API objects.",
		Remediation:       "Disable the kubelet read-only port and restrict the runtime socket to root.",
	},
	{
		ID: "NET-001", Domain: DomainNetwork, Severity: model.SeverityHigh,
		Title: "Namespace missing default-deny ingress", DocURL: docChecklist,
		Summary:     "No NetworkPolicy selects all Pods and denies ingress.",
		Remediation: "Add a NetworkPolicy with an empty podSelector, policyTypes Ingress, and no ingress rules.",
	},
	{
		ID: "NET-002", Domain: DomainNetwork, Severity: model.SeverityHigh,
		Title: "Namespace missing default-deny egress", DocURL: docChecklist,
		Summary:     "No NetworkPolicy selects all Pods and denies egress.",
		Remediation: "Add a NetworkPolicy with an empty podSelector, policyTypes Egress, and no egress rules.",
	},
	{
		ID: "NET-003", Domain: DomainNetwork, Severity: model.SeverityMedium,
		Title: "CNI NetworkPolicy enforcement", DocURL: docChecklist,
		Summary:           "The CNI inferred from kube-system is known to enforce NetworkPolicy.",
		NotAssessableNote: "The CNI could not be inferred, or it enforces NetworkPolicy only when a feature flag is on.",
		Remediation:       "Install a CNI that enforces NetworkPolicy, such as Cilium, Calico, or Antrea.",
	},
	{
		ID: "NET-004", Domain: DomainNetwork, Severity: model.SeverityHigh,
		Title: "Service externalIPs", DocURL: docChecklist,
		Summary:     "A Service sets externalIPs, which can intercept traffic (CVE-2020-8554).",
		Remediation: "Remove spec.externalIPs and enable the DenyServiceExternalIPs admission plugin.",
	},
	{
		ID: "NET-005", Domain: DomainNetwork, Severity: model.SeverityInfo,
		Title: "LoadBalancer Services", DocURL: docChecklist,
		Summary:     "LoadBalancer Services expose workloads outside the cluster.",
		Remediation: "Restrict who can create LoadBalancer Services and prefer an internal load balancer annotation where the cloud supports it.",
	},
	{
		ID: "NET-006", Domain: DomainNetwork, Severity: model.SeverityInfo,
		Title: "Control plane network exposure", DocURL: docChecklist,
		Summary:           "Public reachability of the API, etcd, kubelet, and the cloud metadata address is outside the API.",
		NotAssessableNote: "Exposure depends on cloud security groups, node firewalls, and the CNI, not on listed objects.",
		Remediation:       "Keep the API, etcd, and kubelet off the public internet and block Pod access to 169.254.169.254 when workloads do not need it.",
	},
	{
		ID: "ADM-001", Domain: DomainAdmission, Severity: model.SeverityInfo,
		Title: "Validating admission policy or webhook", DocURL: docPolicies,
		Summary:     "At least one ValidatingAdmissionPolicy or ValidatingWebhookConfiguration exists.",
		Remediation: "Add a ValidatingAdmissionPolicy or a validating webhook for the rules Pod Security does not cover.",
	},
	{
		ID: "ADM-002", Domain: DomainAdmission, Severity: model.SeverityMedium,
		Title: "Admission webhook failurePolicy Ignore", DocURL: docChecklist,
		Summary:     "A validating or mutating webhook fails open when the webhook is unreachable.",
		Remediation: "Set failurePolicy: Fail on security webhooks so an outage cannot skip the check.",
	},
	{
		ID: "ADM-003", Domain: DomainAdmission, Severity: model.SeverityInfo,
		Title: "Policy engine presence", DocURL: docPolicies,
		Summary:     "Kyverno or Gatekeeper is an optional ecosystem policy engine, not a requirement.",
		Remediation: "Install a policy engine only if ValidatingAdmissionPolicy does not cover the rules you need.",
	},
	{
		ID: "AUD-001", Domain: DomainAudit, Severity: model.SeverityHigh,
		Title: "API audit logging", DocURL: docAudit,
		Summary:           "kube-apiserver is started with an audit policy file or an audit webhook.",
		NotAssessableNote: "Managed control planes hide the kube-apiserver Pod spec.",
		Remediation:       "Set --audit-policy-file and a log or webhook backend. Protect the audit files from general read access.",
	},
	{
		ID: "IMG-001", Domain: DomainImages, Severity: model.SeverityMedium,
		Title: "Image referenced by tag", DocURL: docChecklist,
		Summary:     "A container image uses a tag instead of an immutable digest.",
		Remediation: "Pin images by sha256 digest, or verify signatures in admission.",
	},
	{
		ID: "IMG-002", Domain: DomainImages, Severity: model.SeverityHigh,
		Title: "Image tag is latest or empty", DocURL: docChecklist,
		Summary:     "A container image uses the latest tag or omits the tag, which means latest.",
		Remediation: "Replace :latest and untagged images with a digest or a specific version tag.",
	},
	{
		ID: "TEN-001", Domain: DomainTenancy, Severity: model.SeverityMedium,
		Title: "Namespace missing ResourceQuota", DocURL: docTenancy,
		Summary:     "A workload namespace has no ResourceQuota.",
		Remediation: "Add a ResourceQuota so one tenant cannot consume the whole cluster.",
	},
	{
		ID: "TEN-002", Domain: DomainTenancy, Severity: model.SeverityMedium,
		Title: "Namespace missing LimitRange", DocURL: docTenancy,
		Summary:     "A workload namespace has no LimitRange.",
		Remediation: "Add a LimitRange so containers receive default requests and limits.",
	},
	{
		ID: "TEN-003", Domain: DomainTenancy, Severity: model.SeverityInfo,
		Title: "RuntimeClass inventory", DocURL: docChecklist,
		Summary:     "RuntimeClasses available for sandboxed placement. Absence is informational.",
		Remediation: "Use a RuntimeClass such as gVisor or Kata for workloads that need a stronger isolation boundary.",
	},
	{
		ID: "WIN-001", Domain: DomainWindows, Severity: model.SeverityInfo,
		Title: "Windows node Secret storage", DocURL: docWindows,
		Summary:           "Windows nodes write Secret files to disk instead of a memory filesystem.",
		NotAssessableNote: "File ACLs and BitLocker state are not visible through the Kubernetes API.",
		Remediation:       "On Windows nodes, ACL the Secret file path and enable volume encryption.",
	},
	{
		ID: "CP-001", Domain: DomainControlPlane, Severity: model.SeverityHigh,
		Title: "Anonymous API authentication", DocURL: docAccess,
		Summary:           "kube-apiserver sets --anonymous-auth=false.",
		NotAssessableNote: "Managed control planes hide the kube-apiserver Pod spec.",
		Remediation:       "Set --anonymous-auth=false unless an unauthenticated health check must stay open.",
	},
	{
		ID: "CP-002", Domain: DomainControlPlane, Severity: model.SeverityCritical,
		Title: "Authorization mode includes RBAC", DocURL: docAccess,
		Summary:           "kube-apiserver --authorization-mode includes RBAC.",
		NotAssessableNote: "Managed control planes hide the kube-apiserver Pod spec.",
		Remediation:       "Set --authorization-mode=Node,RBAC.",
	},
	{
		ID: "CP-003", Domain: DomainControlPlane, Severity: model.SeverityHigh,
		Title: "Insecure API port", DocURL: docAccess,
		Summary:           "kube-apiserver --insecure-port is unset or 0.",
		NotAssessableNote: "Managed control planes hide the kube-apiserver Pod spec.",
		Remediation:       "Set --insecure-port=0. The insecure port serves the API without authentication.",
	},
}

var byID = indexControls(controls)

func indexControls(list []Control) map[string]Control {
	m := make(map[string]Control, len(list))
	for _, c := range list {
		m[c.ID] = c
	}
	return m
}
