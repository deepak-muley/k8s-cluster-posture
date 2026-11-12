# Kubernetes cluster posture

`posture` is a read-only scanner for a live Kubernetes cluster. It checks the topics in the [Kubernetes security documentation](https://kubernetes.io/docs/concepts/security/) that are visible from the API, optionally runs [Trivy](https://github.com/aquasecurity/trivy) and [Kubescape](https://github.com/kubescape/kubescape), and writes one JSON report and one Markdown report.

Host-only facts, such as kubelet ports, etcd exposure, and control-plane flags on a managed cluster, are marked `not_assessable`. That status is neither a pass nor a failure.

## Run

```bash
go run ./cmd/posture scan
go run ./cmd/posture controls
```

`scan` uses the current kubeconfig. Useful flags:

```bash
go run ./cmd/posture scan \
  --context dev \
  --namespace shop \
  --output ./out \
  --fail-on high
```

- `--skip-tools` skips Trivy and Kubescape.
- `--fail-on high` or `--fail-on critical` exits 1 when a failing finding is at this severity or above.
- Exit 2 means the API could not be reached, the arguments were invalid, or the report could not be written.
- Exit 0 means the scan finished. Findings alone do not change the exit code unless `--fail-on` is set.

The default directory is `posture-report-<context>-<timestamp>/` and contains `report.json` and `report.md`.

Trivy and Kubescape are optional. `posture` runs them only when the `trivy` and `kubescape` binaries are on `PATH`. A missing binary is skipped and the native report is still written. A tool that prints unexpected JSON is recorded as a collector error.

Check what is already installed:

```bash
command -v trivy && trivy --version
command -v kubescape && kubescape version
```

On macOS or Linux with Homebrew:

```bash
brew install trivy kubescape
```

The Homebrew Kubescape formula is enough for this scanner. It runs `kubescape scan framework nsa,mitre`. The kubectl plugin from `kubectl krew install kubescape` is named `kubectl-kubescape`, and `posture` does not look for that name.

Without Homebrew, the upstream installers place the binaries on `PATH`. Read each script before running it.

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash
```

The Kubescape script installs into `~/.kubescape/bin` when it is not run as root. Open a new shell if that directory was just added to `PATH`. Other packages are listed in the [Trivy installation docs](https://trivy.dev/docs/latest/getting-started/installation/) and the [Kubescape install docs](https://kubescape.io/docs/install-cli/).

The scan log prints the command for each collector. kubectl, Trivy, and Kubescape use the current context from the environment. The commands do not pass `--context`.

Native checks do not shell out. They list the API with client-go. The log prints the kubectl command for each list:

```bash
kubectl version
kubectl get namespaces
kubectl get nodes
kubectl get pods -A
kubectl get services -A
kubectl get serviceaccounts -A
kubectl get secrets -A
kubectl get roles -A
kubectl get rolebindings -A
kubectl get clusterroles
kubectl get clusterrolebindings
kubectl get networkpolicies -A
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations
kubectl get validatingadmissionpolicies
kubectl get resourcequotas -A
kubectl get limitranges -A
kubectl get runtimeclasses
```

`--namespace shop` changes the namespaced gets from `-A` to `-n shop`. `kubectl get secrets` prints Secret data; the scanner keeps only the name, namespace, and type.

Trivy and Kubescape:

```bash
trivy k8s --quiet --timeout 12m --disable-node-collector \
  --format json --report all --scanners misconfig,secret,vuln
kubescape scan framework nsa,mitre --format json --format-version v2
```

`--scanners misconfig,secret,vuln` is one Trivy run. Misconfigurations and secrets are findings in the same report as image CVEs (`TRIVY-VULN`). `--kubeconfig` and `--include-namespaces` are added only when those flags are set. Image scanning needs registry access and is the slow part of the run. It does not scan the node OS image.

Drop `--quiet` and `--format json` to read the same scan in a terminal. Kubescape then prints the compliance score and the control table. Trivy prints a table instead of the JSON report:

```bash
trivy k8s --timeout 12m --disable-node-collector \
  --report summary --scanners misconfig,secret,vuln
kubescape scan framework nsa,mitre
```

Each `TRIVY-VULN` finding in `report.md` is one workload: a severity count and five example CVE ids. A reading copy of every CVE from `kind-global-chat` is [docs/kind-global-chat-cves.md](docs/kind-global-chat-cves.md). How a hit maps to a node image versus a container image is in [docs/november-2026-critical-cves.md](docs/november-2026-critical-cves.md).

`--disable-node-collector` is required. Trivy otherwise creates a privileged `node-collector` Job whose own deadline is about five minutes. On kind that Job stays up while the node pulls `ghcr.io/aquasecurity/node-collector`, then fails with `DeadlineExceeded`. Trivy exits with no JSON, so the misconfig, secret, and image results are discarded with it. Those node filesystem checks are host facts this scanner leaves `not_assessable`.

## Permissions

The scanner only calls get, list, and discovery. Apply the ClusterRole in [deploy/rbac/readonly-clusterrole.yaml](deploy/rbac/readonly-clusterrole.yaml) and bind it to the identity that runs the scan.

Listing Secrets returns their data. The scanner keeps only the Secret name, namespace, and type. Do not share a report if resource names or RBAC subjects are sensitive. The report does not include Secret bytes or kubeconfig credentials.

## What the report covers

Native checks are the spine. Each control id maps to a Kubernetes documentation page (`posture controls` prints the catalog).

- API access and RBAC, including cluster-admin, wildcards, secret list/watch, `nodes/proxy`, impersonate/escalate/bind, and cluster-wide workload mutation
- Service account token automount, legacy token Secrets, Secrets in environment variables, and encryption at rest when the apiserver Pod spec is visible
- Pod Security admission labels and baseline / restricted Pod Security Standards, plus memory limits
- hostPath mounts of the node root or a runtime socket, and privileged Pods that share host PID or network
- Default-deny NetworkPolicy, CNI enforcement, `externalIPs`, and LoadBalancer Services
- Validating admission policies and webhooks, including `failurePolicy: Ignore`
- Audit logging and anonymous auth, RBAC authorization mode, and the insecure port, when the apiserver arguments are visible
- Image tags versus digests
- ResourceQuota, LimitRange, and RuntimeClass inventory
- A Windows node caveat when Secret files cannot be kept on a memory filesystem

Trivy and Kubescape findings that describe the same control on the same resource are recorded as agreement on the native finding. Other tool findings are listed under ecosystem scanners.

Platform namespaces (`kube-system`, `kube-public`, `kube-node-lease`) are scanned and tagged `platform`.

## Tests

`make test` does not need a cluster. `make test-kind` creates a disposable [kind](https://kind.sigs.k8s.io/) cluster named `posture-fixture`, applies [testdata/kind/vulnerable.yaml](testdata/kind/vulnerable.yaml), runs a scan, and deletes the cluster. That target needs Docker, `kind`, and `kubectl`. Do not apply the fixture to any other cluster.

### Already covered by unit tests

| Area | What the test checks |
| --- | --- |
| Hardened snapshot | A restricted Pod, digest image, default-deny NetworkPolicy, quota, LimitRange, and safe apiserver flags pass. `system:masters` and public API exposure stay not assessable. |
| Risky snapshot | Failures for cluster-admin, wildcard RBAC, secret list/watch, `nodes/proxy`, impersonate, cluster-wide workload mutation, legacy service-account tokens, automount, Secrets in env, missing encryption and audit flags, Pod Security enforce missing and set to privileged, baseline Pod failure, memory limits, runtime-socket hostPath, privileged host PID or network, flannel with no NetworkPolicy support, `externalIPs`, LoadBalancer Services, tag and `latest` images, missing quota and LimitRange, webhook `failurePolicy: Ignore`, anonymous auth, missing RBAC, and the insecure port. A Windows node stays not assessable. |
| Managed control plane | Encryption, audit, anonymous auth, authorization mode, the insecure port, kubelet settings, and public API exposure are not assessable when no apiserver Pod exists. |
| List errors | A forbidden Pod list is an error, not a pass. |
| Snapshot | Secret bytes are dropped, the API server URL loses userinfo, and Cilium is inferred from a kube-system Pod. |
| Trivy and Kubescape | Saved JSON is parsed. A privileged Trivy result maps to the native Pod control. Unmapped checks stay in the ecosystem section. Secret match text is not copied into the report. Kubescape failures map the same way. Unknown JSON is rejected. |
| Merge | A tool failure on the same control and resource is agreement on the native finding. |
| Report and CLI | Markdown contains the failing resource and the pass list. `--fail-on low` is rejected. `posture help scan` documents the flags. |

These controls are unit-tested and are not planted again in the kind fixture: `nodes/proxy`, impersonate, legacy service-account tokens, control-plane flags, audit, Windows nodes, and webhook `failurePolicy`.

### Kind fixture

The fixture namespace is `pod-security.kubernetes.io/enforce: privileged` so the API accepts the pods. The scan is expected to fail these:

| # | Planted issue | Control | Resource |
| --- | --- | --- | --- |
| 1 | Privileged container | `PSS-001` | `posture-lab/Pod/privileged` |
| 2 | Privileged container sharing host PID and network | `BYP-002` | `posture-lab/Pod/host-share` |
| 3 | hostPath of the containerd socket | `BYP-001` | `posture-lab/Pod/runtime-socket` |
| 4 | `cluster-admin` bound to a user | `RBAC-001` | `ClusterRoleBinding/posture-cluster-admin` |
| 5 | Wildcard verb on pods | `RBAC-002` | `ClusterRoleBinding/posture-wildcard` |
| 6 | `list` and `watch` on Secrets | `RBAC-003` | `ClusterRoleBinding/posture-secrets` |
| 7 | Secret injected as an environment variable | `SEC-003` | `posture-lab/Pod/leaky` |
| 8 | Image tag `latest` | `IMG-002` | `posture-lab/Pod/leaky` |
| 9 | Container with no memory limit | `PSS-003` | `posture-lab/Pod/leaky` |
| 10 | Service `externalIPs` | `NET-004` | `posture-lab/Service/exposed` |

The same scan also expects the privileged Pod Security label (`PSA-002`), missing default-deny policies (`NET-001`, `NET-002`), kindnet (`NET-003`), the unpinned `nginx:1.14.2` tag (`IMG-001`), the reader ServiceAccount automount (`SEC-002`), and cluster-wide pod mutation from the wildcard binding (`RBAC-006`). `nginx:1.14.2` is an old image with known CVEs. When `trivy` is on `PATH`, the kind test runs again without `--skip-tools` and expects `TRIVY-VULN` on `posture-lab/Pod/old-nginx`.

## This version does not

kube-bench, privileged node jobs, Falco runtime events, a continuous in-cluster controller, and an HTML report are out of scope. Controls that need node or cloud configuration stay `not_assessable` instead of being reported as a pass.
# k8s-cluster-posture
