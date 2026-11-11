package report

import (
	"fmt"
	"strings"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
)

// Markdown renders the human report.
func Markdown(rep model.Report) string {
	var b strings.Builder
	b.WriteString("# Kubernetes security posture\n\n")
	b.WriteString("Point-in-time read-only scan. `not assessable` means the API does not show the fact. It is neither a pass nor a failure.\n\n")
	fmt.Fprintf(&b, "Generated: %s\n\n", rep.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))

	b.WriteString("## Cluster\n\n")
	fmt.Fprintf(&b, "- Context: %s\n", dash(rep.Cluster.Context))
	fmt.Fprintf(&b, "- Server: %s\n", dash(rep.Cluster.Server))
	fmt.Fprintf(&b, "- Version: %s\n", dash(rep.Cluster.Version))
	fmt.Fprintf(&b, "- Nodes: %d\n", rep.Cluster.Nodes)
	fmt.Fprintf(&b, "- Namespaces: %d\n", rep.Cluster.Namespaces)
	cni := dash(rep.Cluster.CNI)
	if rep.Cluster.CNIEnforcesNetworkPolicy != "" {
		cni += " (NetworkPolicy enforcement: " + rep.Cluster.CNIEnforcesNetworkPolicy + ")"
	}
	fmt.Fprintf(&b, "- CNI: %s\n", cni)
	if rep.Cluster.ListErrors != "" {
		fmt.Fprintf(&b, "- List errors: %s\n", rep.Cluster.ListErrors)
	}
	b.WriteString("\n## Collectors\n\n")
	if len(rep.Collectors) == 0 {
		b.WriteString("No collectors recorded.\n")
	}
	for _, c := range rep.Collectors {
		line := "- " + c.Name + ": " + c.Status
		if c.Detail != "" {
			line += " — " + c.Detail
		}
		b.WriteString(line + "\n")
	}

	b.WriteString("\n## Summary\n\n")
	b.WriteString("| Domain | Fail | Pass | Not assessable | Error |\n")
	b.WriteString("| --- | ---: | ---: | ---: | ---: |\n")
	var fail, pass, na, errs int
	for _, row := range rep.Summary {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", row.Title, row.Fail, row.Pass, row.NotAssessable, row.Error)
		fail += row.Fail
		pass += row.Pass
		na += row.NotAssessable
		errs += row.Error
	}
	fmt.Fprintf(&b, "| Total | %d | %d | %d | %d |\n", fail, pass, na, errs)

	grouped := groupFindings(rep.Findings)
	for _, domain := range domainSequence(grouped) {
		title := catalog.DomainTitle[domain]
		if title == "" {
			title = domain
		}
		fmt.Fprintf(&b, "\n## %s\n\n", title)
		writeDomain(&b, grouped[domain])
	}
	if len(rep.Findings) == 0 {
		b.WriteString("\nNo findings.\n")
	}
	return b.String()
}

func writeDomain(b *strings.Builder, findings []model.Finding) {
	byControl := map[string][]model.Finding{}
	var order []string
	for _, f := range findings {
		if _, ok := byControl[f.ControlID]; !ok {
			order = append(order, f.ControlID)
		}
		byControl[f.ControlID] = append(byControl[f.ControlID], f)
	}
	for _, id := range order {
		rows := byControl[id]
		var fails, others, passes []model.Finding
		for _, f := range rows {
			switch f.Status {
			case model.StatusFail:
				fails = append(fails, f)
			case model.StatusPass:
				passes = append(passes, f)
			default:
				others = append(others, f)
			}
		}
		if len(fails) == 0 && len(others) == 0 {
			continue
		}
		title := rows[0].Title
		fmt.Fprintf(b, "### %s %s\n\n", id, title)
		for _, f := range append(fails, others...) {
			fmt.Fprintf(b, "- **%s** (%s", f.Status, f.Severity)
			if f.Resource != "" {
				fmt.Fprintf(b, ", `%s`", f.Resource)
			}
			if f.Scope != "" {
				fmt.Fprintf(b, ", %s", f.Scope)
			}
			b.WriteString(")\n")
			if f.Evidence != "" {
				fmt.Fprintf(b, "  - Evidence: %s\n", f.Evidence)
			}
			if f.Remediation != "" {
				fmt.Fprintf(b, "  - Remediation: %s\n", f.Remediation)
			}
			if f.DocURL != "" {
				fmt.Fprintf(b, "  - Docs: %s\n", f.DocURL)
			}
			fmt.Fprintf(b, "  - Source: %s", f.Source)
			if len(f.Agreements) > 0 {
				parts := make([]string, len(f.Agreements))
				for i, src := range f.Agreements {
					parts[i] = string(src)
				}
				fmt.Fprintf(b, " (also reported by %s)", strings.Join(parts, ", "))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
		_ = passes
	}
	var passed []string
	for _, id := range order {
		onlyPass := true
		evidence := ""
		for _, f := range byControl[id] {
			if f.Status != model.StatusPass {
				onlyPass = false
				break
			}
			if evidence == "" {
				evidence = f.Evidence
			}
		}
		if onlyPass {
			title := byControl[id][0].Title
			if evidence != "" {
				passed = append(passed, fmt.Sprintf("- %s %s — %s", id, title, evidence))
			} else {
				passed = append(passed, fmt.Sprintf("- %s %s", id, title))
			}
		}
	}
	if len(passed) > 0 {
		b.WriteString("### Passed\n\n")
		b.WriteString(strings.Join(passed, "\n"))
		b.WriteString("\n")
	}
}

func groupFindings(findings []model.Finding) map[string][]model.Finding {
	out := map[string][]model.Finding{}
	for _, f := range findings {
		out[f.Domain] = append(out[f.Domain], f)
	}
	return out
}

func domainSequence(grouped map[string][]model.Finding) []string {
	var out []string
	seen := map[string]bool{}
	for _, domain := range catalog.DomainOrder {
		if len(grouped[domain]) > 0 {
			out = append(out, domain)
			seen[domain] = true
		}
	}
	for domain := range grouped {
		if !seen[domain] {
			out = append(out, domain)
		}
	}
	return out
}

func dash(value string) string {
	if value == "" {
		return "—"
	}
	return value
}
