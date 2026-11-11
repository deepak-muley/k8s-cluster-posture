package cluster

import "github.com/deepak-muley/k8s-cluster-posture/internal/runexec"

// VersionCommand is the kubectl equivalent of the API version read.
func VersionCommand(opt Options) string {
	return runexec.Format("kubectl", append(kubectlPrefix(opt), "version"))
}

// ReadCommand is the kubectl equivalent of one native list.
// Namespaced resources use -A, or -n when a namespace filter is set.
func ReadCommand(opt Options, key string) string {
	args := append(kubectlPrefix(opt), "get", key)
	if namespacedRead(key) {
		if opt.Namespace != "" {
			args = append(args, "-n", opt.Namespace)
		} else {
			args = append(args, "-A")
		}
	}
	return runexec.Format("kubectl", args)
}

func kubectlPrefix(opt Options) []string {
	var args []string
	if opt.Kubeconfig != "" {
		args = append(args, "--kubeconfig", opt.Kubeconfig)
	}
	return args
}

func namespacedRead(key string) bool {
	switch key {
	case "pods", "services", "serviceaccounts", "secrets", "roles", "rolebindings",
		"networkpolicies", "resourcequotas", "limitranges":
		return true
	default:
		return false
	}
}
