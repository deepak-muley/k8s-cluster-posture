package native

import (
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

var runtimeSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/containerd/containerd.sock",
	"/run/containerd/containerd.sock",
	"/var/run/crio/crio.sock",
	"/run/crio/crio.sock",
	"/var/run/cri-dockerd.sock",
	"/run/cri-dockerd.sock",
}

func checkBypass(snap *cluster.Snapshot) []model.Finding {
	out := []model.Finding{catalog.NotAssessable("BYP-003", "kubelet read-only port and runtime socket ownership are node-local and not visible in the API")}
	if msg := blocked(snap, "pods"); msg != "" {
		return append([]model.Finding{catalog.Error("BYP-001", msg), catalog.Error("BYP-002", msg)}, out...)
	}
	var paths, combo []model.Finding
	for _, pod := range snap.Pods {
		var dangerous []string
		for _, vol := range pod.Spec.Volumes {
			if vol.HostPath == nil {
				continue
			}
			if dangerousHostPath(vol.HostPath.Path) {
				dangerous = append(dangerous, vol.Name+" path "+vol.HostPath.Path)
			}
		}
		if len(dangerous) > 0 {
			paths = append(paths, catalog.Fail("BYP-001", podRef(pod), scopeForNamespace(pod.Namespace), strings.Join(dangerous, ", ")))
		}
		if podSharesHost(pod) && podPrivileged(pod) {
			combo = append(combo, catalog.Fail("BYP-002", podRef(pod), scopeForNamespace(pod.Namespace), "privileged container with hostPID or hostNetwork"))
		}
	}
	return concat(
		finish("BYP-001", paths, "no hostPath mounts the node root or a runtime socket"),
		finish("BYP-002", combo, "no privileged Pod shares host PID or host network"),
		out,
	)
}

func dangerousHostPath(raw string) bool {
	cleaned := path.Clean(raw)
	if cleaned == "/" {
		return true
	}
	for _, sock := range runtimeSockets {
		if cleaned == sock || strings.HasPrefix(sock, cleaned+"/") {
			return true
		}
	}
	return false
}

func podPrivileged(pod corev1.Pod) bool {
	found := false
	eachContainer(pod.Spec, func(c containerView) {
		if c.sc != nil && c.sc.Privileged != nil && *c.sc.Privileged {
			found = true
		}
	})
	return found
}

func podSharesHost(pod corev1.Pod) bool {
	return pod.Spec.HostPID || pod.Spec.HostNetwork
}
