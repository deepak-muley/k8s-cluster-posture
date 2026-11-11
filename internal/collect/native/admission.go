package native

import (
	"fmt"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func checkAdmission(snap *cluster.Snapshot) []model.Finding {
	var out []model.Finding
	if msg := blocked(snap, "validatingwebhookconfigurations", "validatingadmissionpolicies"); msg != "" {
		out = append(out, catalog.Error("ADM-001", msg))
	} else {
		policies := len(snap.ValidatingAdmissionPolicies)
		hooks := len(snap.ValidatingWebhooks)
		if policies == 0 && hooks == 0 {
			out = append(out, catalog.Fail("ADM-001", "", model.ScopeCluster, "no ValidatingAdmissionPolicy and no ValidatingWebhookConfiguration"))
		} else {
			out = append(out, catalog.Pass("ADM-001",
				fmt.Sprintf("%d ValidatingAdmissionPolicy and %d ValidatingWebhookConfiguration", policies, hooks)))
		}
	}

	if msg := blocked(snap, "validatingwebhookconfigurations", "mutatingwebhookconfigurations"); msg != "" {
		out = append(out, catalog.Error("ADM-002", msg))
	} else {
		var fails []model.Finding
		for _, cfg := range snap.ValidatingWebhooks {
			fails = append(fails, ignoreWebhooks("ValidatingWebhookConfiguration", cfg.Name, cfg.Webhooks)...)
		}
		for _, cfg := range snap.MutatingWebhooks {
			fails = append(fails, ignoreMutating("MutatingWebhookConfiguration", cfg.Name, cfg.Webhooks)...)
		}
		out = append(out, finish("ADM-002", fails, "no admission webhook sets failurePolicy Ignore")...)
	}

	if msg := blocked(snap, "namespaces", "pods"); msg != "" {
		out = append(out, catalog.Error("ADM-003", msg))
	} else {
		found := policyEngines(snap)
		if len(found) == 0 {
			out = append(out, catalog.Pass("ADM-003", "no Kyverno or Gatekeeper namespace or Pod detected"))
		} else {
			out = append(out, catalog.Pass("ADM-003", "detected "+strings.Join(found, ", ")))
		}
	}
	return out
}

func ignoreWebhooks(kind, name string, hooks []admissionregistrationv1.ValidatingWebhook) []model.Finding {
	var out []model.Finding
	for _, hook := range hooks {
		if hook.FailurePolicy != nil && *hook.FailurePolicy == admissionregistrationv1.Ignore {
			out = append(out, catalog.Fail("ADM-002", kind+"/"+name, model.ScopeCluster, "webhook "+hook.Name+" failurePolicy Ignore"))
		}
	}
	return out
}

func ignoreMutating(kind, name string, hooks []admissionregistrationv1.MutatingWebhook) []model.Finding {
	var out []model.Finding
	for _, hook := range hooks {
		if hook.FailurePolicy != nil && *hook.FailurePolicy == admissionregistrationv1.Ignore {
			out = append(out, catalog.Fail("ADM-002", kind+"/"+name, model.ScopeCluster, "webhook "+hook.Name+" failurePolicy Ignore"))
		}
	}
	return out
}

func policyEngines(snap *cluster.Snapshot) []string {
	var found []string
	seen := map[string]bool{}
	add := func(ref string) {
		if ref == "" || seen[ref] {
			return
		}
		seen[ref] = true
		found = append(found, ref)
	}
	for _, ns := range snap.Namespaces {
		low := strings.ToLower(ns.Name)
		if strings.Contains(low, "kyverno") || strings.Contains(low, "gatekeeper") {
			add("Namespace/" + ns.Name)
		}
	}
	for _, pod := range snap.Pods {
		low := strings.ToLower(pod.Name + " " + pod.Labels["app.kubernetes.io/name"] + " " + pod.Labels["app"])
		if strings.Contains(low, "kyverno") || strings.Contains(low, "gatekeeper") {
			add(podRef(pod))
		}
	}
	return found
}
