package native

import (
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

type apiServer struct {
	ref   string
	flags map[string][]string
}

func checkControlPlane(snap *cluster.Snapshot) []model.Finding {
	if msg := blocked(snap, "pods"); msg != "" {
		return []model.Finding{
			catalog.Error("CP-001", msg),
			catalog.Error("CP-002", msg),
			catalog.Error("CP-003", msg),
			catalog.Error("AUD-001", msg),
		}
	}
	servers := apiServerFlags(snap)
	if len(servers) == 0 {
		note := "no kube-apiserver Pod spec is visible"
		return []model.Finding{
			catalog.NotAssessable("CP-001", note),
			catalog.NotAssessable("CP-002", note),
			catalog.NotAssessable("CP-003", note),
			catalog.NotAssessable("AUD-001", note),
		}
	}
	return concat(
		evalFlag(servers, "CP-001", func(s apiServer) string {
			vals := s.flags["anonymous-auth"]
			if len(vals) == 0 || !strings.EqualFold(vals[len(vals)-1], "false") {
				return s.ref + " allows anonymous authentication"
			}
			return ""
		}, "kube-apiserver sets --anonymous-auth=false"),
		evalFlag(servers, "CP-002", func(s apiServer) string {
			vals := s.flags["authorization-mode"]
			if len(vals) == 0 || !hasMode(vals[len(vals)-1], "RBAC") {
				return s.ref + " authorization-mode does not include RBAC"
			}
			return ""
		}, "kube-apiserver --authorization-mode includes RBAC"),
		evalFlag(servers, "CP-003", func(s apiServer) string {
			vals := s.flags["insecure-port"]
			if len(vals) == 0 {
				return ""
			}
			port, err := strconv.Atoi(vals[len(vals)-1])
			if err != nil || port != 0 {
				return s.ref + " --insecure-port=" + vals[len(vals)-1]
			}
			return ""
		}, "kube-apiserver insecure port is disabled"),
		evalFlag(servers, "AUD-001", func(s apiServer) string {
			_, policy := s.flags["audit-policy-file"]
			_, webhook := s.flags["audit-webhook-config-file"]
			if !policy && !webhook {
				return s.ref + " has no --audit-policy-file or --audit-webhook-config-file"
			}
			return ""
		}, "kube-apiserver sets an audit policy file or audit webhook"),
	)
}

func evalFlag(servers []apiServer, id string, bad func(apiServer) string, pass string) []model.Finding {
	var notes []string
	for _, srv := range servers {
		if note := bad(srv); note != "" {
			notes = append(notes, note)
		}
	}
	if len(notes) == 0 {
		return []model.Finding{catalog.Pass(id, pass)}
	}
	return []model.Finding{catalog.Fail(id, "", model.ScopeCluster, strings.Join(notes, "; "))}
}

func apiServerFlags(snap *cluster.Snapshot) []apiServer {
	var out []apiServer
	for _, pod := range snap.Pods {
		for _, c := range pod.Spec.Containers {
			if !isAPIServer(c) {
				continue
			}
			out = append(out, apiServer{
				ref:   podRef(pod) + "/" + c.Name,
				flags: parseFlags(append(append([]string{}, c.Command...), c.Args...)),
			})
		}
	}
	return out
}

func isAPIServer(c corev1.Container) bool {
	if c.Name == "kube-apiserver" {
		return true
	}
	for _, part := range append(append([]string{}, c.Command...), c.Args...) {
		if strings.HasPrefix(part, "-") {
			continue
		}
		base := part
		if i := strings.LastIndex(part, "/"); i >= 0 {
			base = part[i+1:]
		}
		if base == "kube-apiserver" {
			return true
		}
	}
	return false
}

func parseFlags(args []string) map[string][]string {
	flags := map[string][]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			continue
		}
		body := strings.TrimPrefix(arg, "--")
		key, val, ok := strings.Cut(body, "=")
		if !ok {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				val = args[i]
			} else {
				val = "true"
			}
		}
		flags[key] = append(flags[key], val)
	}
	return flags
}

func hasMode(raw, want string) bool {
	for _, part := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}
