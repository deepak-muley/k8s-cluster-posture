package native

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func checkSecrets(snap *cluster.Snapshot) []model.Finding {
	var out []model.Finding
	if msg := blocked(snap, "secrets"); msg != "" {
		out = append(out, catalog.Error("SEC-001", msg))
	} else {
		var fails []model.Finding
		for _, secret := range snap.Secrets {
			if secret.Type != corev1.SecretTypeServiceAccountToken {
				continue
			}
			fails = append(fails, catalog.Fail("SEC-001",
				namespacedRef(secret.Namespace, "Secret", secret.Name),
				scopeForNamespace(secret.Namespace),
				"type kubernetes.io/service-account-token"))
		}
		out = append(out, finish("SEC-001", fails, "no legacy service-account token Secrets")...)
	}

	if msg := blocked(snap, "serviceaccounts", "pods"); msg != "" {
		out = append(out, catalog.Error("SEC-002", msg))
	} else {
		out = append(out, checkAutomount(snap)...)
	}

	if msg := blocked(snap, "pods"); msg != "" {
		out = append(out, catalog.Error("SEC-003", msg))
	} else {
		var fails []model.Finding
		for _, pod := range snap.Pods {
			var via []string
			eachContainer(pod.Spec, func(c containerView) {
				for _, env := range c.env {
					if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
						via = append(via, c.name+" env "+env.Name)
					}
				}
				for _, from := range c.envFrom {
					if from.SecretRef != nil {
						via = append(via, c.name+" envFrom "+from.SecretRef.Name)
					}
				}
			})
			if len(via) == 0 {
				continue
			}
			fails = append(fails, catalog.Fail("SEC-003", podRef(pod), scopeForNamespace(pod.Namespace), strings.Join(via, ", ")))
		}
		out = append(out, finish("SEC-003", fails, "no container reads a Secret from the environment")...)
	}

	out = append(out, checkEncryption(snap)...)
	return out
}

func checkAutomount(snap *cluster.Snapshot) []model.Finding {
	type saState struct {
		automount *bool
		scope     model.Scope
	}
	accounts := map[string]saState{}
	var fails []model.Finding
	for _, sa := range snap.ServiceAccounts {
		accounts[sa.Namespace+"/"+sa.Name] = saState{automount: sa.AutomountServiceAccountToken, scope: scopeForNamespace(sa.Namespace)}
		if platformNamespace(sa.Namespace) {
			continue
		}
		enabled, set := boolVal(sa.AutomountServiceAccountToken)
		if !set || enabled {
			fails = append(fails, catalog.Fail("SEC-002",
				namespacedRef(sa.Namespace, "ServiceAccount", sa.Name),
				model.ScopeWorkload,
				"automountServiceAccountToken is not false"))
		}
	}
	for _, pod := range snap.Pods {
		if platformNamespace(pod.Namespace) {
			continue
		}
		enabled, set := boolVal(pod.Spec.AutomountServiceAccountToken)
		if !set || !enabled {
			continue
		}
		name := pod.Spec.ServiceAccountName
		if name == "" {
			name = "default"
		}
		state, ok := accounts[pod.Namespace+"/"+name]
		saExplicitOff := ok && state.automount != nil && !*state.automount
		if !saExplicitOff {
			continue
		}
		fails = append(fails, catalog.Fail("SEC-002", podRef(pod), model.ScopeWorkload,
			fmt.Sprintf("Pod sets automountServiceAccountToken true, overriding ServiceAccount %s", name)))
	}
	return finish("SEC-002", fails, "workload ServiceAccounts set automountServiceAccountToken: false")
}

func checkEncryption(snap *cluster.Snapshot) []model.Finding {
	if msg := blocked(snap, "pods"); msg != "" {
		return []model.Finding{catalog.Error("SEC-004", msg)}
	}
	servers := apiServerFlags(snap)
	if len(servers) == 0 {
		return []model.Finding{catalog.NotAssessable("SEC-004", "no kube-apiserver Pod spec is visible, so encryption at rest cannot be confirmed")}
	}
	var bad []string
	for _, srv := range servers {
		if _, ok := srv.flags["encryption-provider-config"]; !ok {
			bad = append(bad, srv.ref+" has no --encryption-provider-config")
		}
	}
	if len(bad) == 0 {
		return []model.Finding{catalog.Pass("SEC-004", "kube-apiserver sets --encryption-provider-config")}
	}
	return []model.Finding{catalog.Fail("SEC-004", "", model.ScopeCluster, strings.Join(bad, "; "))}
}
