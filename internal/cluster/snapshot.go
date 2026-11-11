// Package cluster loads a read-only view of the API objects the checks need.
package cluster

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	nodev1 "k8s.io/api/node/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// SecretRef is a Secret without its data. The scanner never keeps Secret bytes.
type SecretRef struct {
	Namespace string
	Name      string
	Type      corev1.SecretType
}

// Snapshot is one consistent-enough read of the cluster.
type Snapshot struct {
	Context                     string
	Server                      string
	Version                     string
	Namespace                   string
	Namespaces                  []corev1.Namespace
	Nodes                       []corev1.Node
	Pods                        []corev1.Pod
	Services                    []corev1.Service
	ServiceAccounts             []corev1.ServiceAccount
	Secrets                     []SecretRef
	Roles                       []rbacv1.Role
	RoleBindings                []rbacv1.RoleBinding
	ClusterRoles                []rbacv1.ClusterRole
	ClusterRoleBindings         []rbacv1.ClusterRoleBinding
	NetworkPolicies             []networkingv1.NetworkPolicy
	ValidatingWebhooks          []admissionregistrationv1.ValidatingWebhookConfiguration
	MutatingWebhooks            []admissionregistrationv1.MutatingWebhookConfiguration
	ValidatingAdmissionPolicies []admissionregistrationv1.ValidatingAdmissionPolicy
	ResourceQuotas              []corev1.ResourceQuota
	LimitRanges                 []corev1.LimitRange
	RuntimeClasses              []nodev1.RuntimeClass
	Errors                      map[string]string
	Unsupported                 map[string]bool
	CNI                         string
	CNIEnforces                 string
}

// Options selects the kube context label and an optional namespace filter.
type Options struct {
	Context   string
	Server    string
	Namespace string
}

// Take lists the API objects used by native checks. A failure to reach the
// API returns an error. A forbidden list is stored on Snapshot.Errors.
func Take(ctx context.Context, client kubernetes.Interface, opt Options) (*Snapshot, error) {
	snap := &Snapshot{
		Context:     opt.Context,
		Server:      SanitizeServer(opt.Server),
		Namespace:   opt.Namespace,
		Errors:      map[string]string{},
		Unsupported: map[string]bool{},
	}
	version, err := client.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("kubernetes API is unreachable: %w", err)
	}
	snap.Version = version.GitVersion

	ns := opt.Namespace
	listNS := func() error {
		var cont string
		for {
			page, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Continue: cont})
			if err != nil {
				return err
			}
			for i := range page.Items {
				dropManaged(&page.Items[i].ObjectMeta)
				snap.Namespaces = append(snap.Namespaces, page.Items[i])
			}
			cont = page.Continue
			if cont == "" {
				return nil
			}
		}
	}
	record(snap, "namespaces", listNS())

	record(snap, "nodes", eachPage(func(cont string) (string, error) {
		page, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		for i := range page.Items {
			dropManaged(&page.Items[i].ObjectMeta)
			snap.Nodes = append(snap.Nodes, page.Items[i])
		}
		return page.Continue, nil
	}))

	record(snap, "pods", eachPage(func(cont string) (string, error) {
		page, err := client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		for i := range page.Items {
			dropManaged(&page.Items[i].ObjectMeta)
			snap.Pods = append(snap.Pods, page.Items[i])
		}
		return page.Continue, nil
	}))

	record(snap, "services", eachPage(func(cont string) (string, error) {
		page, err := client.CoreV1().Services(ns).List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		for i := range page.Items {
			dropManaged(&page.Items[i].ObjectMeta)
			snap.Services = append(snap.Services, page.Items[i])
		}
		return page.Continue, nil
	}))

	record(snap, "serviceaccounts", eachPage(func(cont string) (string, error) {
		page, err := client.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		for i := range page.Items {
			dropManaged(&page.Items[i].ObjectMeta)
			page.Items[i].Secrets = nil
			snap.ServiceAccounts = append(snap.ServiceAccounts, page.Items[i])
		}
		return page.Continue, nil
	}))

	record(snap, "secrets", eachPage(func(cont string) (string, error) {
		page, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		for i := range page.Items {
			snap.Secrets = append(snap.Secrets, SecretRef{
				Namespace: page.Items[i].Namespace,
				Name:      page.Items[i].Name,
				Type:      page.Items[i].Type,
			})
			page.Items[i].Data = nil
			page.Items[i].StringData = nil
		}
		return page.Continue, nil
	}))

	record(snap, "roles", eachPage(func(cont string) (string, error) {
		page, err := client.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.Roles = append(snap.Roles, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "rolebindings", eachPage(func(cont string) (string, error) {
		page, err := client.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.RoleBindings = append(snap.RoleBindings, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "clusterroles", eachPage(func(cont string) (string, error) {
		page, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.ClusterRoles = append(snap.ClusterRoles, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "clusterrolebindings", eachPage(func(cont string) (string, error) {
		page, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.ClusterRoleBindings = append(snap.ClusterRoleBindings, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "networkpolicies", eachPage(func(cont string) (string, error) {
		page, err := client.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.NetworkPolicies = append(snap.NetworkPolicies, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "validatingwebhookconfigurations", eachPage(func(cont string) (string, error) {
		page, err := client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.ValidatingWebhooks = append(snap.ValidatingWebhooks, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "mutatingwebhookconfigurations", eachPage(func(cont string) (string, error) {
		page, err := client.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.MutatingWebhooks = append(snap.MutatingWebhooks, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "validatingadmissionpolicies", eachPage(func(cont string) (string, error) {
		page, err := client.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.ValidatingAdmissionPolicies = append(snap.ValidatingAdmissionPolicies, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "resourcequotas", eachPage(func(cont string) (string, error) {
		page, err := client.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.ResourceQuotas = append(snap.ResourceQuotas, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "limitranges", eachPage(func(cont string) (string, error) {
		page, err := client.CoreV1().LimitRanges(ns).List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.LimitRanges = append(snap.LimitRanges, page.Items...)
		return page.Continue, nil
	}))

	record(snap, "runtimeclasses", eachPage(func(cont string) (string, error) {
		page, err := client.NodeV1().RuntimeClasses().List(ctx, metav1.ListOptions{Continue: cont})
		if err != nil {
			return "", err
		}
		snap.RuntimeClasses = append(snap.RuntimeClasses, page.Items...)
		return page.Continue, nil
	}))

	snap.CNI, snap.CNIEnforces = InferCNI(snap.Pods)
	return snap, nil
}

// ErrorSummary is a stable, single-line description of list failures.
func ErrorSummary(snap *Snapshot) string {
	if snap == nil || len(snap.Errors) == 0 {
		return ""
	}
	keys := make([]string, 0, len(snap.Errors))
	for key := range snap.Errors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+": "+snap.Errors[key])
	}
	return strings.Join(parts, "; ")
}

// ListError joins stored list errors for the given keys.
func ListError(snap *Snapshot, keys ...string) string {
	if snap == nil {
		return "no snapshot"
	}
	var parts []string
	for _, key := range keys {
		if msg := snap.Errors[key]; msg != "" {
			parts = append(parts, key+": "+msg)
		}
	}
	return strings.Join(parts, "; ")
}

// SanitizeServer drops userinfo from an API server URL.
func SanitizeServer(host string) string {
	u, err := url.Parse(host)
	if err != nil || u.Host == "" {
		return host
	}
	u.User = nil
	return u.String()
}

func record(snap *Snapshot, key string, err error) {
	if err == nil {
		return
	}
	if apierrors.IsNotFound(err) {
		snap.Unsupported[key] = true
		return
	}
	snap.Errors[key] = err.Error()
}

func eachPage(fn func(cont string) (string, error)) error {
	var cont string
	for {
		next, err := fn(cont)
		if err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		cont = next
	}
}

func dropManaged(meta *metav1.ObjectMeta) {
	meta.ManagedFields = nil
}

// InferCNI guesses the CNI from kube-system Pod names and whether it enforces NetworkPolicy.
// enforces is "yes", "no", or "unknown".
func InferCNI(pods []corev1.Pod) (name, enforces string) {
	type sig struct {
		match    string
		name     string
		enforces string
	}
	// Earlier entries win when several match.
	known := []sig{
		{"cilium", "cilium", "yes"},
		{"calico-node", "calico", "yes"},
		{"calico", "calico", "yes"},
		{"antrea-agent", "antrea", "yes"},
		{"antrea", "antrea", "yes"},
		{"weave-net", "weave", "yes"},
		{"kube-router", "kube-router", "yes"},
		{"kube-ovn", "ovn-kubernetes", "yes"},
		{"ovn-kubernetes", "ovn-kubernetes", "yes"},
		{"canal", "canal", "yes"},
		{"azure-npm", "azure-npm", "yes"},
		{"flannel", "flannel", "no"},
		{"kindnet", "kindnet", "no"},
		{"aws-node", "aws-vpc-cni", "unknown"},
		{"azure-cni", "azure-cni", "unknown"},
	}
	for _, pod := range pods {
		if pod.Namespace != "" && pod.Namespace != "kube-system" {
			continue
		}
		hay := strings.ToLower(pod.Name)
		for _, c := range pod.Spec.Containers {
			hay += " " + strings.ToLower(c.Image) + " " + strings.ToLower(c.Name)
		}
		for k, v := range pod.Labels {
			hay += " " + strings.ToLower(k) + "=" + strings.ToLower(v)
		}
		for _, s := range known {
			if strings.Contains(hay, s.match) {
				return s.name, s.enforces
			}
		}
	}
	return "unknown", "unknown"
}
