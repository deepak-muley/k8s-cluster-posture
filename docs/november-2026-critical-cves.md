# November 2026 critical CVEs: OS images and container images

Status date: 11 November 2026.

This note covers the vulnerabilities that matter for a Kubernetes node this month, and the artifact you have to open to see whether you are affected. Patching the node image does not change packages inside a container. Scanning a container image does not see the kernel the container is running on.

`posture scan` asks Trivy to scan **running container images** in the same run as misconfigurations, secrets, and RBAC (`--scanners vuln,misconfig,secret,rbac`) and records hits as `TRIVY-VULN` in that report (`CVE-…` plus package name). It does not scan the node OS image. A clean container report says nothing about the node kernel.

## Where the detail lives

| Question | OS / node image | Container image |
| --- | --- | --- |
| What you scan | VM image, cloud VHD, or the node root filesystem (`trivy vm`, `trivy rootfs`) | The image digest (`trivy image`), or the running image via `posture scan` |
| Package database | `/var/lib/dpkg/status` (Debian/Ubuntu), RPM database (Azure Linux, RHEL), `/lib/apk/db/installed` (Alpine) | The same files, in an image layer. The distro in the layer can differ from the node. An Ubuntu node often runs an Azure Linux or Alpine container. |
| Trivy result class | `os-pkgs`. `Target` looks like `node (ubuntu 24.04)`. | `os-pkgs` for distro packages. `lang-pkgs` for pip, npm, jars, Go binaries, and bundled runtimes. `PkgPath` is the file inside the image. |
| Advisory to trust | The **source package the image actually installed**, on that distro's tracker. Scanners often print a generic name such as `linux` when the node has `linux-azure`. | The advisory for the **image's** distro, not the node's. A backport fix keeps the upstream version string and changes the package revision (`1.1.0-2ubuntu0.1`, `3.3.7-4.azl3`). |
| What this scan cannot see | Packages copied into container layers, and language runtimes the app vendors. | The host kernel, the host sshd, and anything not in the image layers. |

Two checks fail if you read the wrong string:

- `uname -r` is the **running** kernel. `dpkg -l 'linux-image*'` is the **installed** package. They differ until the node reboots.
- `openssl version` and Node's `process.versions.brotli` print the upstream version. The distro revision, or the runtime's own release, is what the advisory names.

## CVE-2026-98432 — Linux kernel, OS image only

Use-after-free in IPv4 TCP connection setup (`tcp_v4_syn_recv_sock` / `inet_opt`). An unauthenticated remote attacker can reach code execution on a host that accepts IPv4 TCP. Ubuntu scores it 9.8. It is present in kernel 4.4 and later. IPv6 is not affected by the first bug. Containers share the node kernel, so a container image scan will not report this CVE.

Ubuntu's tracker, updated 11 November 2026, lists these generic `linux` fixes. Flavor kernels have their own rows; do not close the finding from the generic package.

| Ubuntu | Source package | Fixed version |
| --- | --- | --- |
| 22.04 | `linux` | 5.15.0-203.213 |
| 24.04 | `linux` | 6.8.0-149.149 |
| 26.04 | `linux` | 7.0.0-43.43 |
| 26.10 | `linux` | 7.3.0-10.10 |
| 22.04 | `linux-azure` | 5.15.0-1126.135 |
| 24.04 | `linux-azure` | 6.8.0-1073.82 |
| 22.04 | `linux-aws` | 5.15.0-1120.127 |
| 24.04 | `linux-aws` | 6.8.0-1069.74 |
| 22.04 | `linux-gcp` | 5.15.0-1121.131 |
| 24.04 | `linux-gcp` | 6.8.0-1073.81 |

Ubuntu 20.04 and older are still "fix pending" on the generic `linux` package. 20.04 `linux-hwe-5.15` is fixed in `5.15.0-203.213~20.04.1` for Ubuntu Pro. Some HWE and FIPS flavors on 22.04 and 24.04 are still in progress (`linux-hwe-6.8` on 22.04, `linux-hwe-7.0` on 24.04, `linux-azure-7.0` on 24.04). Read the row that matches `dpkg -l 'linux-image*'`.

Azure Linux node images earlier than VHD `202610.23.0` are affected. The fix is kernel `6.6.159.1-1` in that VHD. On 2 November, AKS said Ubuntu node VHDs were still waiting on a build that contains the archive fix, tentatively after 15 November, with FIPS and Kata guest kernels excluded from the interim build. The Ubuntu **archive** and the cloud **VHD** are different artifacts. Check both.

Where to look:

- Node: `uname -r`, then `dpkg -l 'linux-image*' | grep ^ii`. On Azure Linux, the kernel RPM.
- Tracker: [ubuntu.com/security/CVE-2026-98432](https://ubuntu.com/security/CVE-2026-98432), search for the source package name (`linux-azure`, not `linux`).
- Cloud image: the node pool's VHD or image version, in [AKS-2026-0007](https://learn.microsoft.com/en-us/azure/aks/security-bulletins/overview).
- Container image: no package row. Absence here is not a pass.

The package update takes effect only after reboot.

## CVE-2026-99999 — Linux kernel, OS image only

AKS bulletin AKS-2026-0007 (2 November 2026) pairs this with CVE-2026-98432. A local attacker, or an untrusted guest VM, can send packets with malformed checksum metadata and reach code execution on the host, crash it, or read memory. It is a node-image bug. It does not appear in container image package scans.

Microsoft's published fix for Azure Linux is the same VHD as above: kernel `6.6.159.1-1` in `202610.23.0`. Confirm the Ubuntu status on the vendor tracker for the installed kernel source package before treating a generic `linux` row as authoritative. The bulletin is the write-up Microsoft has published: [AKS security bulletins](https://learn.microsoft.com/en-us/azure/aks/security-bulletins/overview).

## CVE-2026-123158 — OpenSSH on musl, OS image and some container images

CISA added this to the Known Exploited Vulnerabilities catalog on 9 November 2026. OpenSSH before 10.6p2, built against musl without PAM, can accept a long password for an account whose `/etc/shadow` password field is `*`. Alpine's default `openssh-server` is built that way. glibc distributions (Debian, Ubuntu, RHEL, Azure Linux) and any build that authenticates through PAM are not affected. Dropbear is not affected.

The upstream fix is OpenSSH 10.6p2 (5 November 2026). Alpine backported the fix onto each branch, so the upstream version string is the wrong thing to compare. Alpine's release post lists the package versions:

| Alpine branch | Fixed `openssh` package | Point release |
| --- | --- | --- |
| edge | 10.6_p2-r0 | — |
| 3.24 | 10.3_p1-r2 | 3.24.4 |
| 3.23 | 10.2_p1-r1 | 3.23.8 |
| 3.22 | 10.0_p1-r11 | 3.22.8 |
| 3.21 | 9.9_p2-r1 | 3.21.10 |
| 3.20 | 9.7_p1-r6 | package only |
| 3.16–3.19 | branch package, see the advisory | package only |

Confirm the row against [Alpine 3.21.10 / 3.22.8 / 3.23.8 / 3.24.4](https://www.alpinelinux.org/posts/alpine-3.21.10-3.22.8-3.23.8-3.24.4-released/) before you close a finding. The German BSI advisory says the same thing: the distro package revision is what matters, not "10.6p2" alone.

Where to look:

- Alpine node or cloud image: `apk info -e openssh openssh-server` and the version in `/lib/apk/db/installed`. Restart sshd after the upgrade. The running daemon keeps the old binary.
- Container image: only if the image is musl-based **and** it installs `openssh-server` (or `openssh-server-pam` with PAM turned off) **and** sshd is actually run with password authentication. A container that merely contains the client package, or that never runs sshd, is not exposed. Trivy reports it as `os-pkgs` / `alpine`, package `openssh`. Rebuild the image and replace the running container. Upgrading the node does not change the image.
- Ubuntu or Debian node: this CVE is not in the `openssh` package. A scanner hit on those images for this CVE is a mismatch.

CISA: [alert, 9 November 2026](https://www.cisa.gov/news-events/alerts/2026/11/09/cisa-adds-four-known-exploited-vulnerabilities-catalog).

## CVE-2026-111497 — Brotli, OS package in both places, plus copies the OS package scan misses

Buffer overflow in the Brotli decoder (`c/dec/decode.c`) in versions 1.0.3 through 1.2.0. A crafted stream can disclose memory, crash the process, or run code. NVD published it 22 October 2026. Ubuntu scores CVSS 9.8 and marks it CISA KEV. Upstream fixes are 1.0.10, 1.1.1, and 1.2.1. Distros backport, so a package can still announce "1.1.0" or "1.2.0" after it is fixed.

It shows up in three different inventories:

| Copy | Where it is | What to compare |
| --- | --- | --- |
| Distro library on the node | OS image. Ubuntu package `brotli` / `libbrotli1`. Alpine `brotli-libs`. | Ubuntu: 22.04 `1.0.9-2ubuntu0.1`, 24.04 `1.1.0-2ubuntu0.1`, 26.04 `1.2.0-3ubuntu0.1`, 26.10 `1.2.0-4ubuntu0.1`. 20.04 and older need Ubuntu Pro. |
| Distro library in a container | Image layer, Trivy `os-pkgs`. Independent of the node. | The image distro's package revision. `dpkg -l libbrotli1` or `apk info brotli-libs` inside the image. AKS says updating the node OS does not fix this. |
| Vendored decoder | Image layer, Trivy `lang-pkgs`, or a binary's own version. | Node.js bundles Brotli on older Ubuntu (20.04 `nodejs` is still vulnerable; 22.04 and newer use the system library and are marked not affected). Python `Brotli` / `brotlicffi` 1.2.1. Java `brotli4j` 1.24.0. .NET 8.0.33, 9.0.22, 10.0.14. `process.versions.brotli` can still print 1.2.0 after the Node.js patch. Use the Node.js release, not that string. |

AKS-2026-0008 (3 November 2026): node components do not decompress untrusted Brotli, so the library sitting on the node is not the exposed path. Customer images and proxies are. Azure Linux VHD `202610.23.0` contains the OS fix. The Ubuntu 22.04/24.04 node VHD `202610.30.0` was still planned; the `SecurityPatch` channel stamp `20261028T000000Z` was rolling out, expected in all regions by 12 November. That channel updates the **node**. Rebuild workload images separately.

Where to look:

- Node OS: `dpkg -l libbrotli1` or the Azure Linux RPM, then [ubuntu.com/security/CVE-2026-111497](https://ubuntu.com/security/CVE-2026-111497).
- Container OS package: Trivy `Class: os-pkgs`, `PkgName` `libbrotli1` or `brotli-libs`, `VulnerabilityID` `CVE-2026-111497`.
- Vendored copy: Trivy `Class: lang-pkgs` and `PkgPath` (a `node_modules` path, a JAR, a Python `dist-info`, or a Go binary). Those rows stay after the distro package is patched.

## November KEV entries that are not in these images

CISA added these on 9 and 10 November 2026. They are appliances, desktop software, or an application you would notice as its own deployment. A node image scan and a base-image scan will not list them unless you have actually installed that product into the image.

| CVE | Added | Product | Why it is absent from a normal image scan |
| --- | --- | --- | --- |
| CVE-2026-102895 | 9 Nov | GPUStack authentication | Application. Only an image that installs GPUStack can show it. |
| CVE-2026-116779 | 9 Nov | FreeSWITCH code injection | Application or VM appliance, not a base OS package. |
| CVE-2026-123218 | 9 Nov | IBM Aspera Faspex authorization | Appliance. |
| CVE-2026-20320 | 10 Nov | Cisco BroadWorks XXE | Appliance. |
| CVE-2026-111560 | 10 Nov | Barracuda OS command injection | Appliance. |
| CVE-2026-116606 | 10 Nov | Barracuda ESG authentication bypass | Appliance. CVSS 9.3, exploited. |
| CVE-2026-111793 | 10 Nov | Openwave Webtop transcoder | Appliance. |
| CVE-2026-124194 | 10 Nov | Microsoft Outlook | Desktop client. |
| CVE-2026-125350 | 10 Nov | Chromium use-after-free, fixed in 157.0.8103.50 | Shows up only when the OS image or a container image actually ships `chromium` or Chrome (headless browser images). It is not in the node kernel or in a distroless app image. |

Catalog additions: [9 November](https://www.cisa.gov/news-events/alerts/2026/11/09/cisa-adds-four-known-exploited-vulnerabilities-catalog), [10 November](https://www.cisa.gov/news-events/alerts/2026/11/10/cisa-adds-six-known-exploited-vulnerabilities-catalog).

## Confirming a hit

On a node:

```bash
uname -r
dpkg -l 'linux-image*' | grep ^ii          # Ubuntu
dpkg -l libbrotli1
# Alpine:
apk info -e openssh openssh-server brotli-libs
```

Match the source package, not the scanner's generic name, on the distro tracker. For an AKS Ubuntu node the installed package is `linux-azure` even when the report says `linux`.

On a container image, ask Trivy for the two classes separately so a kernel-shaped finding cannot hide among application libraries:

```bash
trivy image --pkg-types os      --format json <image@sha256:...>
trivy image --pkg-types library --format json <image@sha256:...>
```

In the JSON, `Results[].Class` is `os-pkgs` or `lang-pkgs`, `Results[].Type` is the distro or ecosystem (`ubuntu`, `alpine`, `jar`, `node-pkg`), and each vulnerability has `VulnerabilityID`, `PkgName`, `InstalledVersion`, and `FixedVersion`. `SeveritySource` says which vendor score Trivy used. For a language package, `PkgPath` is the file to open.

`posture` stores a short form of the same container result: control `TRIVY-VULN`, evidence `critical=… high=…; examples: CVE-… <pkg>`. The full package version and the OS-versus-library class are in the Trivy JSON, not in that one-line summary.

## Inventory the cluster

`posture scan` runs image CVEs in the same Trivy command as misconfigurations, secrets, and RBAC. Each workload becomes one `TRIVY-VULN` finding in `report.md`: a severity count and five example ids. The finding does not repeat every package version.

Trivy can write the full list to its own file when you need every installed version. `--report all` keeps every CVE. `--disable-node-collector` skips the privileged node Job. That Job checks node configuration. It is not the image CVE scan, and on kind it usually dies before Trivy can print the report.

```bash
trivy k8s --timeout 15m --disable-node-collector \
  --scanners vuln --report all --format json \
  -o cluster-cves.json
```

Each vulnerability row has `VulnerabilityID`, `PkgName`, `InstalledVersion`, and `FixedVersion`. `Results[].Class` is `os-pkgs` or `lang-pkgs`. `Results[].Target` names the image. The report covers running container images and the Kubernetes component versions Trivy can read from the API. It does not scan the node OS image. A kind node's root filesystem is outside this file.

The inventory taken from `kind-global-chat` on 11 November 2026 is [kind-global-chat-cves.md](kind-global-chat-cves.md).

## Sources

- Ubuntu, CVE-2026-98432 (updated 11 November 2026): https://ubuntu.com/security/CVE-2026-98432
- Ubuntu, fixes for CVE-2026-98432 (updated 9 November 2026): https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432
- Ubuntu, CVE-2026-111497: https://ubuntu.com/security/CVE-2026-111497
- AKS security bulletins, AKS-2026-0007 and AKS-2026-0008: https://learn.microsoft.com/en-us/azure/aks/security-bulletins/overview
- CISA KEV additions, 9 and 10 November 2026: links in the table above
- Alpine point releases carrying the OpenSSH fix: https://www.alpinelinux.org/posts/alpine-3.21.10-3.22.8-3.23.8-3.24.4-released/
- OpenSSH 10.6p2: https://www.openssh.com/releasenotes.html
- Trivy OS package versus language package classes: https://trivy.dev/docs/latest/guide/scanner/vulnerability/
