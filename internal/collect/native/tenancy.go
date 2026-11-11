package native

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func checkTenancy(snap *cluster.Snapshot) []model.Finding {
	var out []model.Finding
	if msg := blocked(snap, "namespaces", "resourcequotas"); msg != "" {
		out = append(out, catalog.Error("TEN-001", msg))
	} else {
		out = append(out, missingPerNamespace(snap, "TEN-001", quotaNamespaces(snap), "ResourceQuota", "every workload namespace has a ResourceQuota")...)
	}
	if msg := blocked(snap, "namespaces", "limitranges"); msg != "" {
		out = append(out, catalog.Error("TEN-002", msg))
	} else {
		out = append(out, missingPerNamespace(snap, "TEN-002", limitNamespaces(snap), "LimitRange", "every workload namespace has a LimitRange")...)
	}
	if msg := blocked(snap, "runtimeclasses"); msg != "" {
		out = append(out, catalog.Error("TEN-003", msg))
	} else if len(snap.RuntimeClasses) == 0 {
		out = append(out, catalog.Pass("TEN-003", "no RuntimeClass is defined"))
	} else {
		names := make([]string, 0, len(snap.RuntimeClasses))
		for _, rc := range snap.RuntimeClasses {
			names = append(names, rc.Name)
		}
		out = append(out, catalog.Pass("TEN-003", "RuntimeClasses: "+strings.Join(names, ", ")))
	}
	out = append(out, checkWindows(snap)...)
	return out
}

func checkWindows(snap *cluster.Snapshot) []model.Finding {
	if msg := blocked(snap, "nodes"); msg != "" {
		return []model.Finding{catalog.Error("WIN-001", msg)}
	}
	var windows []string
	for _, node := range snap.Nodes {
		if isWindows(node) {
			windows = append(windows, node.Name)
		}
	}
	if len(windows) == 0 {
		return []model.Finding{catalog.Pass("WIN-001", "no Windows nodes")}
	}
	return []model.Finding{catalog.NotAssessable("WIN-001",
		"Windows nodes "+strings.Join(windows, ", ")+" store Secret files on disk; ACLs and BitLocker are not visible in the API")}
}

func isWindows(node corev1.Node) bool {
	if strings.EqualFold(node.Status.NodeInfo.OperatingSystem, "windows") {
		return true
	}
	return strings.EqualFold(node.Labels["kubernetes.io/os"], "windows")
}

func quotaNamespaces(snap *cluster.Snapshot) map[string]bool {
	got := map[string]bool{}
	for _, q := range snap.ResourceQuotas {
		got[q.Namespace] = true
	}
	return got
}

func limitNamespaces(snap *cluster.Snapshot) map[string]bool {
	got := map[string]bool{}
	for _, lr := range snap.LimitRanges {
		got[lr.Namespace] = true
	}
	return got
}

func missingPerNamespace(snap *cluster.Snapshot, id string, have map[string]bool, kind, pass string) []model.Finding {
	var fails []model.Finding
	workload := 0
	for _, ns := range snap.Namespaces {
		if platformNamespace(ns.Name) || ns.DeletionTimestamp != nil {
			continue
		}
		workload++
		if have[ns.Name] {
			continue
		}
		fails = append(fails, catalog.Fail(id, "Namespace/"+ns.Name, model.ScopeWorkload, "no "+kind))
	}
	if workload == 0 && len(fails) == 0 {
		return []model.Finding{catalog.Pass(id, "no workload namespaces")}
	}
	return finish(id, fails, pass)
}
