package native

import (
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func checkRBAC(snap *cluster.Snapshot) []model.Finding {
	keys := []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"}
	if msg := blocked(snap, keys...); msg != "" {
		return []model.Finding{
			catalog.Error("RBAC-001", msg),
			catalog.Error("RBAC-002", msg),
			catalog.Error("RBAC-003", msg),
			catalog.Error("RBAC-004", msg),
			catalog.Error("RBAC-005", msg),
			catalog.Error("RBAC-006", msg),
			catalog.NotAssessable("AUTH-001", "Group membership is not an API object."),
		}
	}

	roles := map[string][]rbacv1.PolicyRule{}
	for _, role := range snap.Roles {
		roles[role.Namespace+"/"+role.Name] = role.Rules
	}
	clusterRoles := map[string][]rbacv1.PolicyRule{}
	for _, role := range snap.ClusterRoles {
		clusterRoles[role.Name] = role.Rules
	}

	type grant struct {
		binding  string
		scope    model.Scope
		subject  string
		rules    []rbacv1.PolicyRule
		roleName string
		cluster  bool
	}
	var grants []grant
	for _, binding := range snap.ClusterRoleBindings {
		rules, ok := clusterRoles[binding.RoleRef.Name]
		if !ok {
			continue
		}
		for _, subject := range binding.Subjects {
			if platformSubject(subject) {
				continue
			}
			grants = append(grants, grant{
				binding:  "ClusterRoleBinding/" + binding.Name,
				scope:    model.ScopeCluster,
				subject:  subjectKey(subject),
				rules:    rules,
				roleName: binding.RoleRef.Name,
				cluster:  true,
			})
		}
	}
	for _, binding := range snap.RoleBindings {
		var rules []rbacv1.PolicyRule
		var ok bool
		if binding.RoleRef.Kind == "ClusterRole" {
			rules, ok = clusterRoles[binding.RoleRef.Name]
		} else {
			rules, ok = roles[binding.Namespace+"/"+binding.RoleRef.Name]
		}
		if !ok {
			continue
		}
		for _, subject := range binding.Subjects {
			if platformSubject(subject) {
				continue
			}
			grants = append(grants, grant{
				binding:  namespacedRef(binding.Namespace, "RoleBinding", binding.Name),
				scope:    scopeForNamespace(binding.Namespace),
				subject:  subjectKey(subject),
				rules:    rules,
				roleName: binding.RoleRef.Name,
				cluster:  false,
			})
		}
	}

	var admin, wild, secrets, proxy, escalate, workload []model.Finding
	for _, g := range grants {
		if isClusterAdmin(g.roleName, g.rules) {
			admin = append(admin, catalog.Fail("RBAC-001", g.binding, g.scope,
				g.subject+" is bound to "+g.roleName))
			continue
		}
		if rulesWildcard(g.rules) {
			wild = append(wild, catalog.Fail("RBAC-002", g.binding, g.scope,
				g.subject+" is bound to "+g.roleName+", which uses a wildcard verb or resource"))
		}
		if rulesGrant(g.rules, "", "secrets", "list", "watch") {
			secrets = append(secrets, catalog.Fail("RBAC-003", g.binding, g.scope,
				g.subject+" can list or watch secrets via "+g.roleName))
		}
		if rulesGrant(g.rules, "", "nodes/proxy", "get", "create", "update", "patch", "*") ||
			rulesGrant(g.rules, "", "nodes/*", "get", "create", "*") {
			proxy = append(proxy, catalog.Fail("RBAC-004", g.binding, g.scope,
				g.subject+" can access nodes/proxy via "+g.roleName))
		}
		if rulesGrant(g.rules, "", "users", "impersonate") ||
			rulesGrant(g.rules, "", "groups", "impersonate") ||
			rulesGrant(g.rules, "", "serviceaccounts", "impersonate") ||
			rulesGrant(g.rules, "rbac.authorization.k8s.io", "roles", "bind", "escalate") ||
			rulesGrant(g.rules, "rbac.authorization.k8s.io", "clusterroles", "bind", "escalate") {
			escalate = append(escalate, catalog.Fail("RBAC-005", g.binding, g.scope,
				g.subject+" can impersonate, escalate, or bind via "+g.roleName))
		}
		if g.cluster && grantsWorkloadMutation(g.rules) {
			workload = append(workload, catalog.Fail("RBAC-006", g.binding, g.scope,
				g.subject+" can mutate workloads cluster-wide via "+g.roleName))
		}
	}

	return concat(
		finish("RBAC-001", admin, "no non-platform cluster-admin bindings"),
		finish("RBAC-002", wild, "no wildcard Roles granted to non-platform subjects"),
		finish("RBAC-003", secrets, "no non-platform subject can list or watch secrets"),
		finish("RBAC-004", proxy, "no non-platform subject can access nodes/proxy"),
		finish("RBAC-005", escalate, "no non-platform subject can impersonate, escalate, or bind"),
		finish("RBAC-006", workload, "no non-platform subject can mutate workloads cluster-wide"),
		[]model.Finding{catalog.NotAssessable("AUTH-001", "system:masters membership is held by the authenticator, not by a listable API object.")},
	)
}

func finish(id string, fails []model.Finding, passEvidence string) []model.Finding {
	if len(fails) == 0 {
		return []model.Finding{catalog.Pass(id, passEvidence)}
	}
	return fails
}

func concat(groups ...[]model.Finding) []model.Finding {
	var out []model.Finding
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

func isClusterAdmin(name string, rules []rbacv1.PolicyRule) bool {
	if name == "cluster-admin" {
		return true
	}
	for _, rule := range rules {
		if matchToken(rule.APIGroups, "*") && matchToken(rule.Resources, "*") && matchToken(rule.Verbs, "*") {
			return true
		}
	}
	return false
}

func rulesWildcard(rules []rbacv1.PolicyRule) bool {
	for _, rule := range rules {
		if matchToken(rule.Verbs, "*") || matchToken(rule.Resources, "*") {
			return true
		}
	}
	return false
}

func rulesGrant(rules []rbacv1.PolicyRule, group, resource string, verbs ...string) bool {
	for _, rule := range rules {
		if len(rule.Resources) == 0 {
			continue
		}
		if !matchToken(rule.APIGroups, group) && !matchToken(rule.APIGroups, "*") {
			continue
		}
		if !resourceMatch(rule.Resources, resource) {
			continue
		}
		for _, verb := range verbs {
			if matchToken(rule.Verbs, verb) {
				return true
			}
		}
	}
	return false
}

func grantsWorkloadMutation(rules []rbacv1.PolicyRule) bool {
	resources := []struct {
		group    string
		resource string
	}{
		{"", "pods"},
		{"apps", "deployments"},
		{"apps", "statefulsets"},
		{"apps", "daemonsets"},
		{"apps", "replicasets"},
		{"batch", "jobs"},
		{"batch", "cronjobs"},
	}
	for _, r := range resources {
		if rulesGrant(rules, r.group, r.resource, "create", "update", "patch", "delete", "*") {
			return true
		}
	}
	return false
}

func matchToken(have []string, want string) bool {
	for _, h := range have {
		if h == want || h == "*" {
			return true
		}
	}
	return false
}

func resourceMatch(have []string, want string) bool {
	base, sub, hasSub := strings.Cut(want, "/")
	for _, h := range have {
		if h == "*" || h == want {
			return true
		}
		if hasSub && (h == base+"/*" || h == "*/"+sub) {
			return true
		}
	}
	return false
}
