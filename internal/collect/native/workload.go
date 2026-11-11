package native

import (
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

const psaEnforceLabel = "pod-security.kubernetes.io/enforce"

var baselineCaps = map[string]bool{
	"AUDIT_WRITE": true, "CHOWN": true, "DAC_OVERRIDE": true, "FOWNER": true,
	"FSETID": true, "KILL": true, "MKNOD": true, "NET_BIND_SERVICE": true,
	"SETFCAP": true, "SETGID": true, "SETPCAP": true, "SETUID": true, "SYS_CHROOT": true,
}

var allowedSELinuxTypes = map[string]bool{
	"": true, "container_t": true, "container_init_t": true, "container_kvm_t": true,
}

func checkWorkload(snap *cluster.Snapshot) []model.Finding {
	var out []model.Finding
	if msg := blocked(snap, "namespaces"); msg != "" {
		out = append(out, catalog.Error("PSA-001", msg), catalog.Error("PSA-002", msg))
	} else {
		out = append(out, checkPSA(snap)...)
	}
	if msg := blocked(snap, "pods"); msg != "" {
		out = append(out, catalog.Error("PSS-001", msg), catalog.Error("PSS-002", msg), catalog.Error("PSS-003", msg))
		return out
	}
	var baseline, restricted, memory []model.Finding
	for _, pod := range snap.Pods {
		if pod.DeletionTimestamp != nil {
			continue
		}
		base := baselineReasons(pod)
		if len(base) > 0 {
			baseline = append(baseline, catalog.Fail("PSS-001", podRef(pod), scopeForNamespace(pod.Namespace), joinReasons(base)))
		} else if extra := restrictedReasons(pod); len(extra) > 0 {
			restricted = append(restricted, catalog.Fail("PSS-002", podRef(pod), scopeForNamespace(pod.Namespace), joinReasons(extra)))
		}
		if missing := missingMemory(pod); len(missing) > 0 {
			memory = append(memory, catalog.Fail("PSS-003", podRef(pod), scopeForNamespace(pod.Namespace), "no memory limit: "+strings.Join(missing, ", ")))
		}
	}
	out = append(out,
		finish("PSS-001", baseline, "no Pod fails the baseline Pod Security Standard")...,
	)
	out = append(out,
		finish("PSS-002", restricted, "no Pod that meets baseline fails the restricted standard")...,
	)
	out = append(out, finish("PSS-003", memory, "every container sets a memory limit")...)
	return out
}

func checkPSA(snap *cluster.Snapshot) []model.Finding {
	var missing, privileged []model.Finding
	for _, ns := range snap.Namespaces {
		if ns.Name == "kube-node-lease" || ns.DeletionTimestamp != nil {
			continue
		}
		level := strings.ToLower(ns.Labels[psaEnforceLabel])
		ref := "Namespace/" + ns.Name
		scope := scopeForNamespace(ns.Name)
		switch level {
		case "":
			missing = append(missing, catalog.Fail("PSA-001", ref, scope, "pod-security.kubernetes.io/enforce is unset"))
		case "privileged":
			privileged = append(privileged, catalog.Fail("PSA-002", ref, scope, "enforce=privileged"))
		}
	}
	return concat(
		finish("PSA-001", missing, "every namespace sets pod-security.kubernetes.io/enforce"),
		finish("PSA-002", privileged, "no namespace enforces the privileged Pod Security level"),
	)
}

func baselineReasons(pod corev1.Pod) []string {
	var reasons []string
	if pod.Spec.HostNetwork {
		reasons = append(reasons, "hostNetwork")
	}
	if pod.Spec.HostPID {
		reasons = append(reasons, "hostPID")
	}
	if pod.Spec.HostIPC {
		reasons = append(reasons, "hostIPC")
	}
	for _, vol := range pod.Spec.Volumes {
		if vol.HostPath != nil {
			reasons = append(reasons, "hostPath "+vol.HostPath.Path)
		}
	}
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SELinuxOptions != nil {
		if reason := selinuxReason(pod.Spec.SecurityContext.SELinuxOptions); reason != "" {
			reasons = append(reasons, "pod "+reason)
		}
	}
	eachContainer(pod.Spec, func(c containerView) {
		if c.sc != nil && c.sc.Privileged != nil && *c.sc.Privileged {
			reasons = append(reasons, c.name+" privileged")
		}
		for _, port := range c.ports {
			if port.HostPort != 0 {
				reasons = append(reasons, c.name+" hostPort")
				break
			}
		}
		if c.sc != nil && c.sc.Capabilities != nil {
			for _, cap := range c.sc.Capabilities.Add {
				name := strings.ToUpper(string(cap))
				if !baselineCaps[name] {
					reasons = append(reasons, c.name+" adds "+name)
				}
			}
		}
		if c.sc != nil && c.sc.ProcMount != nil && *c.sc.ProcMount == corev1.UnmaskedProcMount {
			reasons = append(reasons, c.name+" procMount unmasked")
		}
		if c.sc != nil && c.sc.SELinuxOptions != nil {
			if reason := selinuxReason(c.sc.SELinuxOptions); reason != "" {
				reasons = append(reasons, c.name+" "+reason)
			}
		}
	})
	return reasons
}

func selinuxReason(opt *corev1.SELinuxOptions) string {
	if opt.User != "" || opt.Role != "" {
		return "seLinux user or role is set"
	}
	if !allowedSELinuxTypes[opt.Type] {
		return "seLinux type " + opt.Type
	}
	return ""
}

func restrictedReasons(pod corev1.Pod) []string {
	var reasons []string
	for _, vol := range pod.Spec.Volumes {
		if vol.HostPath != nil {
			continue
		}
		if !restrictedVolumeAllowed(vol) {
			reasons = append(reasons, "volume "+vol.Name+" type is outside the restricted set")
		}
	}
	eachContainer(pod.Spec, func(c containerView) {
		escalation, set := false, false
		if c.sc != nil {
			escalation, set = boolVal(c.sc.AllowPrivilegeEscalation)
		}
		if !set || escalation {
			reasons = append(reasons, c.name+" allowPrivilegeEscalation is not false")
		}
		nonRoot, nonRootSet := false, false
		if c.sc != nil {
			nonRoot, nonRootSet = boolVal(c.sc.RunAsNonRoot)
		}
		if !nonRootSet && pod.Spec.SecurityContext != nil {
			nonRoot, nonRootSet = boolVal(pod.Spec.SecurityContext.RunAsNonRoot)
		}
		if !nonRootSet || !nonRoot {
			reasons = append(reasons, c.name+" runAsNonRoot is not true")
		}
		if user, ok := runAsUser(pod.Spec, c.sc); ok && user == 0 {
			reasons = append(reasons, c.name+" runAsUser is 0")
		}
		profile := effectiveSeccomp(pod.Spec, c.sc)
		if profile == nil || (profile.Type != corev1.SeccompProfileTypeRuntimeDefault && profile.Type != corev1.SeccompProfileTypeLocalhost) {
			reasons = append(reasons, c.name+" seccomp is not RuntimeDefault or Localhost")
		}
		if c.sc == nil || c.sc.Capabilities == nil || !dropsAll(c.sc.Capabilities.Drop) {
			reasons = append(reasons, c.name+" does not drop ALL capabilities")
		}
		if c.sc != nil && c.sc.Capabilities != nil {
			for _, cap := range c.sc.Capabilities.Add {
				if strings.ToUpper(string(cap)) != "NET_BIND_SERVICE" {
					reasons = append(reasons, c.name+" adds "+string(cap)+" under restricted")
				}
			}
		}
	})
	return reasons
}

func restrictedVolumeAllowed(vol corev1.Volume) bool {
	switch {
	case vol.ConfigMap != nil, vol.DownwardAPI != nil, vol.EmptyDir != nil, vol.Projected != nil,
		vol.Secret != nil, vol.CSI != nil, vol.Ephemeral != nil, vol.PersistentVolumeClaim != nil:
		return true
	default:
		return false
	}
}

func dropsAll(drop []corev1.Capability) bool {
	for _, cap := range drop {
		if strings.EqualFold(string(cap), "ALL") {
			return true
		}
	}
	return false
}

func runAsUser(spec corev1.PodSpec, sc *corev1.SecurityContext) (int64, bool) {
	if sc != nil && sc.RunAsUser != nil {
		return *sc.RunAsUser, true
	}
	if spec.SecurityContext != nil && spec.SecurityContext.RunAsUser != nil {
		return *spec.SecurityContext.RunAsUser, true
	}
	return 0, false
}

func effectiveSeccomp(spec corev1.PodSpec, sc *corev1.SecurityContext) *corev1.SeccompProfile {
	if sc != nil && sc.SeccompProfile != nil {
		return sc.SeccompProfile
	}
	if spec.SecurityContext != nil {
		return spec.SecurityContext.SeccompProfile
	}
	return nil
}

func missingMemory(pod corev1.Pod) []string {
	var names []string
	eachContainer(pod.Spec, func(c containerView) {
		qty, ok := c.resources.Limits[corev1.ResourceMemory]
		if !ok || qty.IsZero() {
			names = append(names, c.name)
		}
	})
	return names
}
