// Package native evaluates the docs-backed controls against an API snapshot.
package native

import (
	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

// Run evaluates every native control. It does not contact the API.
func Run(snap *cluster.Snapshot) []model.Finding {
	findings := concat(
		checkRBAC(snap),
		checkSecrets(snap),
		checkWorkload(snap),
		checkBypass(snap),
		checkNetwork(snap),
		checkAdmission(snap),
		checkImages(snap),
		checkTenancy(snap),
		checkControlPlane(snap),
	)
	catalog.SortFindings(findings)
	return findings
}
