package native

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func platformNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	default:
		return false
	}
}

func scopeForNamespace(ns string) model.Scope {
	if ns == "" {
		return model.ScopeCluster
	}
	if platformNamespace(ns) {
		return model.ScopePlatform
	}
	return model.ScopeWorkload
}

func namespacedRef(namespace, kind, name string) string {
	if namespace == "" {
		return kind + "/" + name
	}
	return namespace + "/" + kind + "/" + name
}

func subjectKey(s rbacv1.Subject) string {
	switch s.Kind {
	case rbacv1.ServiceAccountKind:
		return "ServiceAccount/" + s.Namespace + "/" + s.Name
	default:
		if s.Kind == "" {
			return s.Name
		}
		return s.Kind + "/" + s.Name
	}
}

func platformSubject(s rbacv1.Subject) bool {
	switch s.Kind {
	case rbacv1.ServiceAccountKind:
		return platformNamespace(s.Namespace)
	case rbacv1.UserKind:
		return strings.HasPrefix(s.Name, "system:")
	case rbacv1.GroupKind:
		if s.Name == "system:authenticated" || s.Name == "system:unauthenticated" {
			return false
		}
		return strings.HasPrefix(s.Name, "system:")
	default:
		return false
	}
}

func blocked(snap *cluster.Snapshot, keys ...string) string {
	return cluster.ListError(snap, keys...)
}

func joinReasons(reasons []string) string {
	return strings.Join(reasons, "; ")
}

func podRef(pod corev1.Pod) string {
	return namespacedRef(pod.Namespace, "Pod", pod.Name)
}

type containerView struct {
	name      string
	sc        *corev1.SecurityContext
	image     string
	ports     []corev1.ContainerPort
	env       []corev1.EnvVar
	envFrom   []corev1.EnvFromSource
	resources corev1.ResourceRequirements
}

func eachContainer(spec corev1.PodSpec, fn func(containerView)) {
	for _, c := range spec.Containers {
		fn(containerView{c.Name, c.SecurityContext, c.Image, c.Ports, c.Env, c.EnvFrom, c.Resources})
	}
	for _, c := range spec.InitContainers {
		fn(containerView{c.Name, c.SecurityContext, c.Image, c.Ports, c.Env, c.EnvFrom, c.Resources})
	}
	for _, c := range spec.EphemeralContainers {
		fn(containerView{c.Name, c.SecurityContext, c.Image, c.Ports, c.Env, c.EnvFrom, c.Resources})
	}
}

func boolVal(v *bool) (value, set bool) {
	if v == nil {
		return false, false
	}
	return *v, true
}
