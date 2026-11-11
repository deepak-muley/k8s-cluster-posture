package collect

import (
	"testing"

	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

func TestMergeKeepsNativeAndRecordsAgreement(t *testing.T) {
	native := []model.Finding{{
		ControlID: "PSS-001",
		Domain:    "workload",
		Title:     "baseline",
		Status:    model.StatusFail,
		Resource:  "default/Pod/web",
		Source:    model.SourceNative,
		Severity:  model.SeverityHigh,
	}, {
		ControlID: "PSS-002",
		Status:    model.StatusPass,
		Source:    model.SourceNative,
	}}
	trivy := []model.Finding{{
		ControlID: "PSS-001",
		Status:    model.StatusFail,
		Resource:  "default/Pod/web",
		Source:    model.SourceTrivy,
	}, {
		ControlID: "TRIVY-KSV099",
		Domain:    "ecosystem",
		Title:     "other",
		Status:    model.StatusFail,
		Resource:  "default/Pod/web",
		Source:    model.SourceTrivy,
	}, {
		ControlID: "PSS-002",
		Status:    model.StatusPass,
		Source:    model.SourceTrivy,
	}}
	got := Merge(trivy, native)
	if len(got) != 3 {
		t.Fatalf("len = %d, findings %+v", len(got), got)
	}
	var agreed bool
	for _, f := range got {
		if f.ControlID == "PSS-001" {
			if f.Source != model.SourceNative {
				t.Fatalf("primary source = %s", f.Source)
			}
			if len(f.Agreements) != 1 || f.Agreements[0] != model.SourceTrivy {
				t.Fatalf("agreements = %+v", f.Agreements)
			}
			agreed = true
		}
		if f.ControlID == "PSS-002" && f.Status != model.StatusPass {
			t.Fatalf("pass was replaced: %+v", f)
		}
	}
	if !agreed {
		t.Fatal("missing PSS-001")
	}
}

func TestNormalizeResource(t *testing.T) {
	if got := NormalizeResource("v1/kube-system/Pod/kube-proxy"); got != "kube-system/Pod/kube-proxy" {
		t.Fatalf("got %s", got)
	}
	if got := NormalizeResource("default/Pod/web"); got != "default/Pod/web" {
		t.Fatalf("got %s", got)
	}
}
