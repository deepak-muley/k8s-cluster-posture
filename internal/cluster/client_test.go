package cluster

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConnectUsesKubeconfigEnv(t *testing.T) {
	path := writeKubeconfig(t, "demo", "https://127.0.0.1:6443")
	t.Setenv("KUBECONFIG", path)

	_, cfg, current, err := Connect("", "")
	if err != nil {
		t.Fatal(err)
	}
	if current != "demo" {
		t.Fatalf("context = %q", current)
	}
	if cfg.Host != "https://127.0.0.1:6443" {
		t.Fatalf("host = %q", cfg.Host)
	}
}

func TestConnectExplicitPathOverridesEnv(t *testing.T) {
	envPath := writeKubeconfig(t, "from-env", "https://env.example:6443")
	flagPath := writeKubeconfig(t, "from-flag", "https://flag.example:6443")
	t.Setenv("KUBECONFIG", envPath)

	_, cfg, current, err := Connect(flagPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if current != "from-flag" || cfg.Host != "https://flag.example:6443" {
		t.Fatalf("context %q host %q", current, cfg.Host)
	}
}

func writeKubeconfig(t *testing.T, contextName, server string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	content := `apiVersion: v1
kind: Config
current-context: ` + contextName + `
contexts:
- name: ` + contextName + `
  context:
    cluster: c
    user: u
clusters:
- name: c
  cluster:
    server: ` + server + `
users:
- name: u
  user:
    token: fixture
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
