package cluster

import "testing"

func TestReadCommand(t *testing.T) {
	all := ReadCommand(Options{}, "pods")
	if all != "kubectl get pods -A" {
		t.Fatalf("all = %s", all)
	}
	one := ReadCommand(Options{Namespace: "shop", Kubeconfig: "/tmp/my config"}, "secrets")
	if one != "kubectl --kubeconfig '/tmp/my config' get secrets -n shop" {
		t.Fatalf("namespace = %s", one)
	}
	nodes := ReadCommand(Options{}, "nodes")
	if nodes != "kubectl get nodes" {
		t.Fatalf("nodes = %s", nodes)
	}
	version := VersionCommand(Options{})
	if version != "kubectl version" {
		t.Fatalf("version = %s", version)
	}
}
