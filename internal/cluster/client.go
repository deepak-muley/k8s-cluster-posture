package cluster

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Connect loads a kubeconfig and returns a read-only client. The caller must
// not use the client to create or update objects.
func Connect(kubeconfigPath, contextName string) (kubernetes.Interface, *rest.Config, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	// An empty ExplicitPath disables the default search, including KUBECONFIG.
	// Kubie and kubectl both select the cluster through that variable.
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	loading := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules,
		&clientcmd.ConfigOverrides{CurrentContext: contextName},
	)
	raw, err := loading.RawConfig()
	if err != nil {
		return nil, nil, "", fmt.Errorf("read kubeconfig: %w", err)
	}
	restCfg, err := loading.ClientConfig()
	if err != nil {
		return nil, nil, "", fmt.Errorf("build rest config: %w", err)
	}
	restCfg.QPS = 50
	restCfg.Burst = 100
	// The scanner only lists objects.
	restCfg.WarningHandler = rest.NoWarnings{}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create kubernetes client: %w", err)
	}
	current := contextName
	if current == "" {
		current = raw.CurrentContext
	}
	return client, restCfg, current, nil
}
