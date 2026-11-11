package collect

import (
	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

// Merge keeps native findings as the primary record. A tool failure for the
// same control and resource is stored as agreement instead of a second row.
func Merge(groups ...[]model.Finding) []model.Finding {
	type key struct {
		control  string
		resource string
	}
	var out []model.Finding
	index := map[key]int{}
	for _, group := range groups {
		for _, finding := range group {
			if finding.Source != model.SourceNative && finding.Status != model.StatusFail {
				continue
			}
			k := key{finding.ControlID, finding.Resource}
			if i, ok := index[k]; ok {
				if finding.Source == model.SourceNative && out[i].Source != model.SourceNative {
					agreements := out[i].Agreements
					if out[i].Status == model.StatusFail && finding.Status == model.StatusFail {
						agreements = appendSource(agreements, out[i].Source)
					}
					finding.Agreements = agreements
					out[i] = finding
					continue
				}
				if out[i].Source == model.SourceNative && out[i].Status == model.StatusFail && finding.Status == model.StatusFail && finding.Source != model.SourceNative {
					out[i].Agreements = appendSource(out[i].Agreements, finding.Source)
				}
				continue
			}
			index[k] = len(out)
			out = append(out, finding)
		}
	}
	catalog.SortFindings(out)
	return out
}

func appendSource(have []model.Source, src model.Source) []model.Source {
	for _, existing := range have {
		if existing == src {
			return have
		}
	}
	return append(have, src)
}
