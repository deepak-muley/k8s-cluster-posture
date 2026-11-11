package cluster

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func TestTakeStripsSecretDataAndReadsVersion(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "shop"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"password": []byte("super-secret")},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium", Namespace: "kube-system"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "cilium-agent", Image: "cilium:v1"}}},
	}
	client := fake.NewSimpleClientset(secret, ns, pod)
	client.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{GitVersion: "v1.32.1"}

	snap, err := Take(context.Background(), client, Options{Context: "dev", Server: "https://user:pass@127.0.0.1:6443"})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Version != "v1.32.1" {
		t.Fatalf("version %s", snap.Version)
	}
	if snap.Server != "https://127.0.0.1:6443" {
		t.Fatalf("server %s", snap.Server)
	}
	if len(snap.Secrets) != 1 || snap.Secrets[0].Name != "db" || snap.Secrets[0].Type != corev1.SecretTypeOpaque {
		t.Fatalf("secrets %+v", snap.Secrets)
	}
	if snap.CNI != "cilium" || snap.CNIEnforces != "yes" {
		t.Fatalf("cni %s %s", snap.CNI, snap.CNIEnforces)
	}
}

func TestSanitizeServerDropsUserinfo(t *testing.T) {
	if got := SanitizeServer("https://admin:hunter2@example.com:6443"); got != "https://example.com:6443" {
		t.Fatalf("got %s", got)
	}
}

func TestScopeConstant(t *testing.T) {
	if model.ScopeWorkload != "workload" {
		t.Fatal(model.ScopeWorkload)
	}
}
