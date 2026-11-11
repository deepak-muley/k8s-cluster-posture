package native

import (
	"strings"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func checkImages(snap *cluster.Snapshot) []model.Finding {
	if msg := blocked(snap, "pods"); msg != "" {
		return []model.Finding{catalog.Error("IMG-001", msg), catalog.Error("IMG-002", msg)}
	}
	var tagged, latest []model.Finding
	for _, pod := range snap.Pods {
		var tags, floats []string
		eachContainer(pod.Spec, func(c containerView) {
			if c.image == "" {
				return
			}
			digest, tag := imageRef(c.image)
			if digest {
				return
			}
			tags = append(tags, c.name+" "+c.image)
			if tag == "" || tag == "latest" {
				floats = append(floats, c.name+" "+c.image)
			}
		})
		if len(tags) > 0 {
			tagged = append(tagged, catalog.Fail("IMG-001", podRef(pod), scopeForNamespace(pod.Namespace), strings.Join(tags, ", ")))
		}
		if len(floats) > 0 {
			latest = append(latest, catalog.Fail("IMG-002", podRef(pod), scopeForNamespace(pod.Namespace), strings.Join(floats, ", ")))
		}
	}
	return concat(
		finish("IMG-001", tagged, "every container image is pinned by digest"),
		finish("IMG-002", latest, "no container image uses the latest tag or an empty tag"),
	)
}

// imageRef reports whether the reference is a digest and, if not, the tag.
// An empty tag means the reference omitted one, which Kubernetes treats as latest.
func imageRef(image string) (digest bool, tag string) {
	last := image
	if i := strings.LastIndex(image, "/"); i >= 0 {
		last = image[i+1:]
	}
	if at := strings.LastIndex(last, "@"); at >= 0 {
		return true, ""
	}
	if colon := strings.LastIndex(last, ":"); colon >= 0 {
		return false, last[colon+1:]
	}
	return false, "latest"
}
