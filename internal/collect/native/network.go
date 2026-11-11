package native

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func checkNetwork(snap *cluster.Snapshot) []model.Finding {
	var out []model.Finding
	if msg := blocked(snap, "namespaces", "networkpolicies"); msg != "" {
		out = append(out, catalog.Error("NET-001", msg), catalog.Error("NET-002", msg))
	} else {
		denyIn := map[string]bool{}
		denyEg := map[string]bool{}
		for _, pol := range snap.NetworkPolicies {
			if !selectsAllPods(pol.Spec.PodSelector) {
				continue
			}
			if deniesIngress(pol) {
				denyIn[pol.Namespace] = true
			}
			if deniesEgress(pol) {
				denyEg[pol.Namespace] = true
			}
		}
		var missingIn, missingEg []model.Finding
		for _, ns := range snap.Namespaces {
			if ns.Name == "kube-node-lease" || ns.Name == "kube-public" || ns.DeletionTimestamp != nil {
				continue
			}
			ref := "Namespace/" + ns.Name
			scope := scopeForNamespace(ns.Name)
			if !denyIn[ns.Name] {
				missingIn = append(missingIn, catalog.Fail("NET-001", ref, scope, "no default-deny ingress NetworkPolicy"))
			}
			if !denyEg[ns.Name] {
				missingEg = append(missingEg, catalog.Fail("NET-002", ref, scope, "no default-deny egress NetworkPolicy"))
			}
		}
		out = append(out, finish("NET-001", missingIn, "every namespace has a default-deny ingress NetworkPolicy")...)
		out = append(out, finish("NET-002", missingEg, "every namespace has a default-deny egress NetworkPolicy")...)
	}

	if msg := blocked(snap, "pods"); msg != "" {
		out = append(out, catalog.Error("NET-003", msg))
	} else {
		out = append(out, checkCNI(snap)...)
	}

	if msg := blocked(snap, "services"); msg != "" {
		out = append(out, catalog.Error("NET-004", msg), catalog.Error("NET-005", msg))
	} else {
		var external []model.Finding
		var balancers []string
		for _, svc := range snap.Services {
			if len(svc.Spec.ExternalIPs) > 0 {
				external = append(external, catalog.Fail("NET-004",
					namespacedRef(svc.Namespace, "Service", svc.Name),
					scopeForNamespace(svc.Namespace),
					"externalIPs "+strings.Join(svc.Spec.ExternalIPs, ", ")))
			}
			if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
				balancers = append(balancers, namespacedRef(svc.Namespace, "Service", svc.Name))
			}
		}
		out = append(out, finish("NET-004", external, "no Service sets externalIPs")...)
		if len(balancers) == 0 {
			out = append(out, catalog.Pass("NET-005", "no LoadBalancer Services"))
		} else {
			out = append(out, catalog.Fail("NET-005", "", model.ScopeCluster, capList(balancers, 40)))
		}
	}
	out = append(out, catalog.NotAssessable("NET-006", "public exposure of the API, etcd, kubelet, and the cloud metadata address is not visible from listed objects"))
	return out
}

func checkCNI(snap *cluster.Snapshot) []model.Finding {
	switch snap.CNIEnforces {
	case "yes":
		return []model.Finding{catalog.Pass("NET-003", "inferred CNI "+snap.CNI+" enforces NetworkPolicy")}
	case "no":
		return []model.Finding{catalog.Fail("NET-003", "", model.ScopeCluster, "inferred CNI "+snap.CNI+" does not enforce NetworkPolicy")}
	default:
		evidence := "CNI could not be inferred from kube-system Pods"
		if snap.CNI != "" && snap.CNI != "unknown" {
			evidence = fmt.Sprintf("inferred CNI %s does not show whether NetworkPolicy is enforced", snap.CNI)
		}
		return []model.Finding{catalog.NotAssessable("NET-003", evidence)}
	}
}

func selectsAllPods(sel metav1.LabelSelector) bool {
	return len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0
}

func deniesIngress(pol networkingv1.NetworkPolicy) bool {
	if !hasPolicyType(pol, networkingv1.PolicyTypeIngress) {
		return false
	}
	return len(pol.Spec.Ingress) == 0
}

func deniesEgress(pol networkingv1.NetworkPolicy) bool {
	if !hasPolicyType(pol, networkingv1.PolicyTypeEgress) {
		return false
	}
	return len(pol.Spec.Egress) == 0
}

func hasPolicyType(pol networkingv1.NetworkPolicy, want networkingv1.PolicyType) bool {
	if len(pol.Spec.PolicyTypes) == 0 {
		return want == networkingv1.PolicyTypeIngress && len(pol.Spec.Egress) == 0
	}
	for _, t := range pol.Spec.PolicyTypes {
		if t == want {
			return true
		}
	}
	return false
}

func capList(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(items[:max], ", "), len(items)-max)
}
