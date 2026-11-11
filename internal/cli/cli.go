// Package cli is the posture command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/deepak-muley/k8s-cluster-posture/internal/catalog"
	"github.com/deepak-muley/k8s-cluster-posture/internal/cluster"
	"github.com/deepak-muley/k8s-cluster-posture/internal/collect"
	"github.com/deepak-muley/k8s-cluster-posture/internal/collect/kubescape"
	native "github.com/deepak-muley/k8s-cluster-posture/internal/collect/native"
	"github.com/deepak-muley/k8s-cluster-posture/internal/collect/trivy"
	"github.com/deepak-muley/k8s-cluster-posture/internal/model"
	"github.com/deepak-muley/k8s-cluster-posture/internal/report"
	"github.com/deepak-muley/k8s-cluster-posture/internal/runexec"
)

// ExitError is a process status with a message.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// Execute runs the CLI against os.Args.
func Execute() error {
	return NewRoot(os.Stdout, os.Stderr).Execute()
}

// NewRoot builds the cobra command. stdout receives normal output.
func NewRoot(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "posture",
		Short: "Read-only Kubernetes security posture scanner",
		Long: `posture scans a live Kubernetes cluster and writes a security report.

The scan is read-only. It uses the current kubeconfig, checks the Kubernetes
security topics that the API can show, and runs trivy and kubescape when those
binaries are on PATH. A missing tool is skipped. The report is report.json and
report.md.

Findings use four statuses. pass and fail are assessed results. not_assessable
means the API cannot show the fact, which is common on managed control planes.
error means a list was forbidden or failed. not_assessable is neither a pass
nor a failure.

Exit status:
  0  the scan finished
  1  --fail-on matched a failing finding
  2  the API was unreachable, the arguments were invalid, or the report was not written`,
		Example: `  posture scan
  posture scan --context dev --namespace shop --fail-on high
  posture scan --skip-tools --output ./out
  posture controls
  posture help scan`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)

	var kubeconfig, contextName, namespace, output, failOn string
	var skipTools, scanImages bool

	scan := &cobra.Command{
		Use:   "scan",
		Short: "Scan the current kubeconfig cluster and write a report",
		Long: `Scan the cluster selected by kubeconfig and write report.json and report.md.

Native checks cover RBAC, service accounts, Secrets, Pod Security, network
policy, admission, images, quotas, and control-plane arguments when the
kube-apiserver Pod spec is visible. Trivy misconfiguration and secret scans
run when trivy is installed. Kubescape runs the NSA and MITRE frameworks when
kubescape is installed. --scan-images adds Trivy vulnerability scanning.

The default output directory is posture-report-<context>-<UTC timestamp>/.
Progress is written to stderr while the scan runs. Platform namespaces are tagged
platform in the report. A control the API cannot answer is reported as not assessable.

Apply deploy/rbac/readonly-clusterrole.yaml to the identity that runs the scan.
Listing Secrets returns their data. The scanner keeps only name, namespace, and type.`,
		Example: `  posture scan
  posture scan --kubeconfig ~/.kube/config --context dev
  posture scan --namespace shop --output ./out --skip-tools
  posture scan --scan-images --fail-on critical`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			threshold, err := parseFailOn(failOn)
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Minute)
			defer cancel()
			return runScan(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr(), scanConfig{
				Kubeconfig: kubeconfig,
				Context:    contextName,
				Namespace:  namespace,
				Output:     output,
				SkipTools:  skipTools,
				ScanImages: scanImages,
				FailOn:     threshold,
				Now:        time.Now(),
			})
		},
	}
	scan.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig file (default: KUBECONFIG, then ~/.kube/config)")
	scan.Flags().StringVar(&contextName, "context", "", "kubeconfig context (default: the current context)")
	scan.Flags().StringVar(&namespace, "namespace", "", "limit namespaced objects to this namespace; cluster-scoped checks still run")
	scan.Flags().StringVar(&output, "output", "", "directory for report.json and report.md (default: posture-report-<context>-<timestamp>)")
	scan.Flags().BoolVar(&skipTools, "skip-tools", false, "do not run trivy or kubescape")
	scan.Flags().BoolVar(&scanImages, "scan-images", false, "also ask trivy to scan running images for vulnerabilities (slow, needs registry access)")
	scan.Flags().StringVar(&failOn, "fail-on", "", "exit 1 when a failing finding is at this severity or above: high or critical")

	controls := &cobra.Command{
		Use:   "controls",
		Short: "Print the native control catalog",
		Long: `Print every native control: id, domain, severity, title, documentation URL, and what the check looks for.

Controls that the API often cannot answer include a "not assessable when" line.
Trivy and Kubescape add extra findings at scan time. Those ids are not part of this catalog.`,
		Example:      `  posture controls`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := io.WriteString(cmd.OutOrStdout(), catalog.FormatControls())
			return err
		},
	}
	root.AddCommand(scan, controls)
	return root
}

type scanConfig struct {
	Kubeconfig string
	Context    string
	Namespace  string
	Output     string
	SkipTools  bool
	ScanImages bool
	FailOn     model.Severity
	Now        time.Time
}

func parseFailOn(raw string) (model.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "none":
		return "", nil
	case string(model.SeverityHigh):
		return model.SeverityHigh, nil
	case string(model.SeverityCritical):
		return model.SeverityCritical, nil
	default:
		return "", fmt.Errorf("--fail-on must be high or critical")
	}
}

func runScan(ctx context.Context, stdout, stderr io.Writer, cfg scanConfig) error {
	log := newLogger(stderr)
	log.printf("reading kubeconfig")
	client, restCfg, contextName, err := cluster.Connect(cfg.Kubeconfig, cfg.Context)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	log.printf("context %s, server %s", contextName, restCfg.Host)
	log.printf("listing API objects")
	snap, err := cluster.Take(ctx, client, cluster.Options{
		Context:   contextName,
		Server:    restCfg.Host,
		Namespace: cfg.Namespace,
		Progress:  func(msg string) { log.printf("%s", msg) },
	})
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	log.printf("kubernetes %s, %d nodes, %d namespaces, %d pods, cni %s", snap.Version, len(snap.Nodes), len(snap.Namespaces), len(snap.Pods), snap.CNI)
	if msg := cluster.ErrorSummary(snap); msg != "" {
		log.printf("some lists failed: %s", msg)
	}

	var (
		nativeFindings []model.Finding
		trivyFindings  []model.Finding
		ksFindings     []model.Finding
		trivyStatus    model.Collector
		ksStatus       model.Collector
	)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		started := time.Now()
		log.printf("native checks started")
		nativeFindings = native.Run(snap)
		log.printf("native checks finished in %s, %d findings", time.Since(started).Round(time.Millisecond), len(nativeFindings))
	}()
	if cfg.SkipTools {
		trivyStatus = model.Collector{Name: "trivy", Status: "skipped", Detail: "disabled with --skip-tools"}
		ksStatus = model.Collector{Name: "kubescape", Status: "skipped", Detail: "disabled with --skip-tools"}
		log.printf("trivy skipped")
		log.printf("kubescape skipped")
	} else {
		wg.Add(2)
		go func() {
			defer wg.Done()
			tctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
			defer cancel()
			what := "misconfig and secret checks"
			if cfg.ScanImages {
				what = "misconfig, secret, and image vulnerability checks"
			}
			log.printf("trivy started (%s)", what)
			tctx = runexec.WithStderr(tctx, &prefixWriter{dst: log, prefix: "trivy"})
			stop := heartbeat(tctx, log, "trivy")
			defer stop()
			trivyFindings, trivyStatus = trivy.Collect(tctx, trivy.Options{
				Kubeconfig: cfg.Kubeconfig,
				Context:    contextName,
				Namespace:  cfg.Namespace,
				ScanImages: cfg.ScanImages,
			})
			log.printf("trivy %s, %d findings", collectorDetail(trivyStatus), len(trivyFindings))
		}()
		go func() {
			defer wg.Done()
			tctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
			defer cancel()
			log.printf("kubescape started (nsa, mitre)")
			tctx = runexec.WithStderr(tctx, &prefixWriter{dst: log, prefix: "kubescape"})
			stop := heartbeat(tctx, log, "kubescape")
			defer stop()
			ksFindings, ksStatus = kubescape.Collect(tctx, kubescape.Options{
				Kubeconfig: cfg.Kubeconfig,
				Context:    contextName,
				Namespace:  cfg.Namespace,
			})
			log.printf("kubescape %s, %d findings", collectorDetail(ksStatus), len(ksFindings))
		}()
	}
	wg.Wait()

	log.printf("writing report")

	findings := collect.Merge(nativeFindings, trivyFindings, ksFindings)
	rep := model.Report{
		GeneratedAt: cfg.Now.UTC(),
		Cluster: model.Cluster{
			Context:                  snap.Context,
			Server:                   snap.Server,
			Version:                  snap.Version,
			Nodes:                    len(snap.Nodes),
			Namespaces:               len(snap.Namespaces),
			CNI:                      snap.CNI,
			CNIEnforcesNetworkPolicy: snap.CNIEnforces,
			ListErrors:               cluster.ErrorSummary(snap),
		},
		Collectors: []model.Collector{
			{Name: "native", Status: "ran"},
			trivyStatus,
			ksStatus,
		},
		Findings: findings,
	}
	rep.Summary = catalog.Summarize(findings)

	dir := cfg.Output
	if dir == "" {
		dir = report.OutputDir(contextName, cfg.Now)
	}
	if err := report.Write(dir, rep); err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	fmt.Fprintf(stdout, "wrote %s\n", dir)
	fmt.Fprintf(stdout, "%s\n", countLine(rep.Summary))
	if cfg.FailOn != "" && model.FailsAtOrAbove(findings, cfg.FailOn) {
		return &ExitError{Code: 1, Err: errors.New("findings at or above " + string(cfg.FailOn))}
	}
	return nil
}

func countLine(rows []model.DomainCount) string {
	var fail, na, errs int
	for _, row := range rows {
		fail += row.Fail
		na += row.NotAssessable
		errs += row.Error
	}
	return fmt.Sprintf("failures: %d, not assessable: %d, errors: %d", fail, na, errs)
}

func collectorDetail(status model.Collector) string {
	if status.Detail == "" {
		return status.Status
	}
	return status.Status + ": " + status.Detail
}

func heartbeat(ctx context.Context, log *logger, name string) func() {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		started := time.Now()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.printf("%s still running (%s)", name, time.Since(started).Round(time.Second))
			}
		}
	}()
	return func() { close(stop) }
}
