package native

import (
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func TestHardenedClusterPassesWorkloadControls(t *testing.T) {
	snap := hardened()
	findings := Run(snap)
	for _, id := range []string{"PSS-001", "PSS-002", "PSS-003", "PSA-001", "PSA-002", "IMG-001", "IMG-002", "NET-001", "NET-002", "NET-004", "SEC-001", "SEC-002", "SEC-003", "SEC-004", "CP-001", "CP-002", "AUD-001", "RBAC-001"} {
		if got := firstStatus(findings, id); got != model.StatusPass {
			t.Errorf("%s status = %s, evidence %q", id, got, firstEvidence(findings, id))
		}
	}
	if got := firstStatus(findings, "AUTH-001"); got != model.StatusNotAssessable {
		t.Errorf("AUTH-001 = %s", got)
	}
	if got := firstStatus(findings, "NET-006"); got != model.StatusNotAssessable {
		t.Errorf("NET-006 = %s", got)
	}
}

func TestRiskyClusterFindings(t *testing.T) {
	mem := resource.MustParse("32Mi")
	nonRoot := true
	noEsc := false
	user := int64(1000)
	auto := true
	ignore := admissionregistrationv1.Ignore
	snap := &cluster.Snapshot{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "app", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "privileged"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "payments"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		},
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "priv", Namespace: "app"},
				Spec: corev1.PodSpec{
					HostPID:     true,
					HostNetwork: true,
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "nginx:latest",
						SecurityContext: &corev1.SecurityContext{
							Privileged: boolPtr(true),
						},
						Env: []corev1.EnvVar{{
							Name: "TOKEN",
							ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{Name: "db"},
								Key:                  "password",
							}},
						}},
					}},
					Volumes: []corev1.Volume{{
						Name:         "sock",
						VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}},
					}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "payments"},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "app",
						Image: "registry.example/payments:1.2.3",
						Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
							corev1.ResourceMemory: mem,
						}},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &noEsc,
							RunAsNonRoot:             &nonRoot,
							RunAsUser:                &user,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						},
					}},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-master", Namespace: "kube-system"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name:    "kube-apiserver",
					Command: []string{"kube-apiserver", "--authorization-mode=AlwaysAllow", "--anonymous-auth=true", "--insecure-port=8080"},
				}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-flannel-ds", Namespace: "kube-system"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "kube-flannel", Image: "flannel:v0.25.0"}}},
			},
		},
		ServiceAccounts: []corev1.ServiceAccount{
			{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "payments"}, AutomountServiceAccountToken: &auto},
		},
		Secrets: []cluster.SecretRef{
			{Namespace: "payments", Name: "legacy", Type: corev1.SecretTypeServiceAccountToken},
		},
		Services: []corev1.Service{
			{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "app"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ExternalIPs: []string{"1.2.3.4"}}},
		},
		ClusterRoles: []rbacv1.ClusterRole{
			{ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "secret-reader"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list", "watch"}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "node-proxy"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"nodes/proxy"}, Verbs: []string{"get"}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "impersonator"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate"}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "deployer"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "wildcard"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			bind("admin", "cluster-admin", rbacv1.Subject{Kind: rbacv1.UserKind, Name: "alice"}),
			bind("secrets", "secret-reader", rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "builder", Namespace: "payments"}),
			bind("proxy", "node-proxy", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "devs"}),
			bind("imp", "impersonator", rbacv1.Subject{Kind: rbacv1.UserKind, Name: "bob"}),
			bind("dep", "deployer", rbacv1.Subject{Kind: rbacv1.UserKind, Name: "carol"}),
			bind("wild", "wildcard", rbacv1.Subject{Kind: rbacv1.UserKind, Name: "dave"}),
			bind("system", "cluster-admin", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:masters"}),
		},
		ValidatingWebhooks: []admissionregistrationv1.ValidatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "open"},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{{
				Name:          "open.example.com",
				FailurePolicy: &ignore,
			}},
		}},
		Nodes: []corev1.Node{{
			ObjectMeta: metav1.ObjectMeta{Name: "win", Labels: map[string]string{"kubernetes.io/os": "windows"}},
			Status:     corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "windows"}},
		}},
	}
	snap.CNI, snap.CNIEnforces = cluster.InferCNI(snap.Pods)
	findings := Run(snap)

	expects := map[string]model.Status{
		"RBAC-001": model.StatusFail,
		"RBAC-002": model.StatusFail,
		"RBAC-003": model.StatusFail,
		"RBAC-004": model.StatusFail,
		"RBAC-005": model.StatusFail,
		"RBAC-006": model.StatusFail,
		"SEC-001":  model.StatusFail,
		"SEC-002":  model.StatusFail,
		"SEC-003":  model.StatusFail,
		"SEC-004":  model.StatusFail,
		"PSA-001":  model.StatusFail,
		"PSA-002":  model.StatusFail,
		"PSS-001":  model.StatusFail,
		"PSS-003":  model.StatusFail,
		"BYP-001":  model.StatusFail,
		"BYP-002":  model.StatusFail,
		"NET-003":  model.StatusFail,
		"NET-004":  model.StatusFail,
		"NET-005":  model.StatusFail,
		"IMG-001":  model.StatusFail,
		"IMG-002":  model.StatusFail,
		"TEN-001":  model.StatusFail,
		"TEN-002":  model.StatusFail,
		"ADM-002":  model.StatusFail,
		"CP-001":   model.StatusFail,
		"CP-002":   model.StatusFail,
		"CP-003":   model.StatusFail,
		"AUD-001":  model.StatusFail,
		"WIN-001":  model.StatusNotAssessable,
	}
	for id, want := range expects {
		if got := firstStatus(findings, id); got != want {
			t.Errorf("%s = %s, want %s (%s)", id, got, want, firstEvidence(findings, id))
		}
	}
	if got := firstStatus(findings, "PSS-002"); got != model.StatusFail {
		t.Fatalf("PSS-002 = %s, want a restricted failure from the unhardened apiserver", got)
	}
	for _, f := range failsFor(findings, "PSS-002") {
		if f.Resource == "app/Pod/priv" {
			t.Fatalf("privileged pod also recorded as restricted: %s", f.Evidence)
		}
	}
	admin := failsFor(findings, "RBAC-001")
	if len(admin) != 1 || admin[0].Resource != "ClusterRoleBinding/admin" {
		t.Fatalf("RBAC-001 resources = %+v", admin)
	}
}

func TestManagedControlPlaneIsNotAssessable(t *testing.T) {
	findings := Run(&cluster.Snapshot{
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "default", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}},
	})
	for _, id := range []string{"SEC-004", "CP-001", "CP-002", "CP-003", "AUD-001", "BYP-003", "NET-006"} {
		if got := firstStatus(findings, id); got != model.StatusNotAssessable {
			t.Errorf("%s = %s, want not_assessable", id, got)
		}
	}
}

func TestListErrorsAreNotPasses(t *testing.T) {
	snap := &cluster.Snapshot{Errors: map[string]string{"pods": "pods is forbidden"}}
	findings := Run(snap)
	if got := firstStatus(findings, "PSS-001"); got != model.StatusError {
		t.Fatalf("PSS-001 = %s", got)
	}
	if got := firstStatus(findings, "AUTH-001"); got != model.StatusNotAssessable {
		t.Fatalf("AUTH-001 = %s", got)
	}
}

func TestDangerousHostPathParents(t *testing.T) {
	if !dangerousHostPath("/var") || !dangerousHostPath("/var/run/docker.sock") || !dangerousHostPath("/") {
		t.Fatal("expected dangerous host paths")
	}
	if dangerousHostPath("/var/lib/kubelet") || dangerousHostPath("/data") {
		t.Fatal("unrelated hostPath should not match the runtime socket")
	}
}

func TestImageRef(t *testing.T) {
	digest, tag := imageRef("ghcr.io/org/app@sha256:abc")
	if !digest || tag != "" {
		t.Fatalf("digest parse = %v %q", digest, tag)
	}
	digest, tag = imageRef("registry.example:5000/app")
	if digest || tag != "latest" {
		t.Fatalf("untagged = %v %q", digest, tag)
	}
	digest, tag = imageRef("nginx:1.25")
	if digest || tag != "1.25" {
		t.Fatalf("tag = %v %q", digest, tag)
	}
}

func hardened() *cluster.Snapshot {
	off := false
	ns := "shop"
	digest := "ghcr.io/example/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	snap := &cluster.Snapshot{
		Namespaces: []corev1.Namespace{{
			ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}},
		}},
		Pods: []corev1.Pod{
			restrictedPod(ns, "api", "api", digest, nil),
			restrictedPod("kube-system", "kube-apiserver", "kube-apiserver", digest, []string{
				"kube-apiserver",
				"--anonymous-auth=false",
				"--authorization-mode=Node,RBAC",
				"--encryption-provider-config=/etc/kubernetes/enc.yaml",
				"--audit-policy-file=/etc/kubernetes/audit.yaml",
				"--insecure-port=0",
			}),
			restrictedPod("kube-system", "cilium", "cilium-agent", digest, nil),
		},
		ServiceAccounts: []corev1.ServiceAccount{{
			ObjectMeta:                   metav1.ObjectMeta{Name: "default", Namespace: ns},
			AutomountServiceAccountToken: &off,
		}},
		NetworkPolicies: []networkingv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: ns},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			},
		}},
		ResourceQuotas: []corev1.ResourceQuota{{ObjectMeta: metav1.ObjectMeta{Name: "quota", Namespace: ns}}},
		LimitRanges:    []corev1.LimitRange{{ObjectMeta: metav1.ObjectMeta{Name: "limits", Namespace: ns}}},
		RuntimeClasses: nil,
		ClusterRoles: []rbacv1.ClusterRole{{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		}},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			bind("cluster-admin", "cluster-admin", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:masters"}),
		},
	}
	snap.CNI, snap.CNIEnforces = cluster.InferCNI(snap.Pods)
	return snap
}

func restrictedPod(namespace, podName, containerName, image string, command []string) corev1.Pod {
	nonRoot := true
	noEsc := false
	user := int64(1000)
	off := false
	mem := resource.MustParse("64Mi")
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: namespace},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: &off,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   &nonRoot,
				RunAsUser:      &user,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:    containerName,
				Image:   image,
				Command: command,
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &noEsc,
					RunAsNonRoot:             &nonRoot,
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
				Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: mem}},
			}},
		},
	}
}

func bind(name, role string, subject rbacv1.Subject) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: role},
		Subjects:   []rbacv1.Subject{subject},
	}
}

func boolPtr(v bool) *bool { return &v }

func firstStatus(findings []model.Finding, id string) model.Status {
	for _, f := range findings {
		if f.ControlID == id {
			return f.Status
		}
	}
	return ""
}

func firstEvidence(findings []model.Finding, id string) string {
	for _, f := range findings {
		if f.ControlID == id {
			return f.Evidence
		}
	}
	return ""
}

func failsFor(findings []model.Finding, id string) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if f.ControlID == id && f.Status == model.StatusFail {
			out = append(out, f)
		}
	}
	return out
}
