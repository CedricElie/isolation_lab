
# Kubernetes Workload Isolation Lab: Distroless vs. Kata Containers (MicroVMs)

A practical, reproducible Kubernetes lab demonstrating the architectural security boundary between **Distroless containers** (userland minimization on a shared host kernel) and **Kata Containers** (hardware-virtualized microVMs with a dedicated guest kernel via Cloud Hypervisor).

---

## Table of Contents
1. [Architecture & Threat Model](#1-architecture--threat-model)
2. [Lab Prerequisites & VM Setup](#2-lab-prerequisites--vm-setup)
3. [Cluster Setup: k3s + Kata Containers](#3-cluster-setup-k3s--kata-containers)
4. [Building the Distroless Test Workload](#4-building-the-distroless-test-workload)
5. [Deploying Side-by-Side Comparison Pods](#5-deploying-side-by-side-comparison-pods)
6. [Verification & Security Tests](#6-verification--security-tests)
   - [Test 1: Kernel Isolation Proof](#test-1-kernel-isolation-proof)
   - [Test 2: Host Process & Hypervisor Boundary](#test-2-host-process--hypervisor-boundary)
   - [Test 3: Kernel Ring Buffer & Hardware Visibility](#test-3-kernel-ring-buffer--hardware-visibility)
   - [Test 4: Privileged Container Blast Radius](#test-4-privileged-container-blast-radius)
   - [Test 5: Resource Overhead Benchmark](#test-5-resource-overhead-benchmark)
7. [Summary Comparison Matrix](#7-summary-comparison-matrix)
8. [Cleanup](#8-cleanup)

---

## 1. Architecture & Threat Model

A common misconception in container security is that **Distroless images** and **MicroVMs** solve the same problem:

* **Distroless (`runc`):** Removes shells (`/bin/sh`), package managers, and OS utilities to minimize the *container filesystem*. However, the application still makes syscalls directly against the **shared host Linux kernel**.
* **Kata Containers (`kata-clh`):** Wraps the exact same OCI image inside a lightweight KVM-backed microVM (using **Cloud Hypervisor**) with its own dedicated guest kernel.

```text
+-----------------------------------+     +-----------------------------------+
|      Pod: app-distroless-runc     |     |      Pod: app-distroless-kata     |
|  +-----------------------------+  |     |  +-----------------------------+  |
|  |   Distroless App (/demo)    |  |     |  |   Distroless App (/demo)    |  |
|  +-----------------------------+  |     |  +-----------------------------+  |
|                 |                 |     |                 |                 |
|         (Direct Syscalls)         |     |     +-----------------------+     |
|                 |                 |     |     |  Guest Linux Kernel   |     |
|                 v                 |     |     |      (e.g. 6.18)      |     |
+-----------------|-----------------+     |     +-----------------------+     |
                  |                       |     |   Cloud Hypervisor    |     |
                  |                       |     +-----------------------+     |
                  |                       +-----------------|-----------------+
                  |                                         | (KVM ioctls)
                  v                                         v
+-----------------------------------------------------------------------------+
|                     Host Ubuntu 24.04 Linux Kernel (6.8)                    |
+-----------------------------------------------------------------------------+

```

---

## 2. Lab Prerequisites & VM Setup

### Hardware / Hypervisor Requirements

* **Host Machine:** Bare-metal Linux `x86_64` or macOS (`x86_64` Intel / Apple Silicon M3+ on macOS 15+) running VMware Fusion / Workstation.
* **Nested Virtualization:** Must be enabled in your hypervisor so `/dev/kvm` is exposed inside the guest VM.
* *VMware Fusion:* Power off VM → **Settings** → **Processors & Memory** → **Advanced options** → Check **Enable hypervisor applications in this virtual machine**.


* **VM Sizing:**
* **OS:** Ubuntu 24.04 LTS Server (`amd64`)
* **vCPUs:** 4
* **RAM:** 8 GB
* **Disk:** 20 GB+



### Verify KVM Support on the Ubuntu Host

```bash
egrep -c '(vmx|svm)' /proc/cpuinfo   # Must return > 0
ls -l /dev/kvm                       # Must exist (crw-rw----)

```

---

## 3. Cluster Setup: k3s + Kata Containers

> **Note:** Avoid `kind` or `minikube` for Kata labs; running Kubernetes nodes inside Docker containers introduces double-nested virtualization and cgroup/storage conflicts. Single-node `k3s` provides native `containerd` integration.

### 3.1 Install k3s

```bash
curl -sfL [https://get.k3s.io](https://get.k3s.io) | sh -

# Configure user kubeconfig access
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
chmod 600 ~/.kube/config

export KUBECONFIG=~/.kube/config
echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc

kubectl get nodes

```

### 3.2 Install Helm & Deploy Kata Containers

Kata Containers is deployed via its official OCI Helm chart, configuring `k8sDistribution=k3s` to automatically wire up k3s's embedded `containerd`:

```bash
# Install Helm v3
curl -fsSL [https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3](https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3) | bash

# Deploy Kata Containers DaemonSet & RuntimeClasses
helm install kata-deploy \
  oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy \
  --namespace kube-system \
  --set k8sDistribution=k3s \
  --set runtimeClasses.createDefault=true \
  --wait --timeout 10m

```

### 3.3 Verify Registered RuntimeClasses

```bash
kubectl get runtimeclass

```

Expected output includes `kata`, `kata-clh` (Cloud Hypervisor), and `kata-qemu`.

---

## 4. Building the Distroless Test Workload

Because pure distroless images (`gcr.io/distroless/static-debian12:nonroot`) contain no shell or `/bin/sleep`, we compile a minimal static Go binary that prints `/proc/version` at startup and blocks cleanly on `SIGINT`/`SIGTERM`.

### 4.1 Install Podman

```bash
sudo apt-get update && sudo apt-get install -y podman

```

### 4.2 Create Application Source & Multi-Stage Dockerfile

```bash
mkdir -p ~/distroless-demo && cd ~/distroless-demo

cat << 'EOF' > main.go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	data, _ := os.ReadFile("/proc/version")
	fmt.Printf("Started! Kernel: %s\n", string(data))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
EOF

cat << 'EOF' > Dockerfile
FROM docker.io/library/golang:1.23-alpine AS builder
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /demo-app main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /demo-app /demo-app
ENTRYPOINT ["/demo-app"]
EOF

```

### 4.3 Build and Import Image into k3s `containerd`

```bash
podman build -t localhost/distroless-demo:v1 .
podman save localhost/distroless-demo:v1 | sudo k3s ctr images import -

# Verify image availability in k3s
sudo k3s ctr images ls | grep distroless-demo

```

---

## 5. Deploying Side-by-Side Comparison Pods

Deploy two pods running the exact same distroless image—one on the default `runc` runtime and one on `kata-clh`:

```bash
cat << 'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: app-distroless-runc
  labels:
    runtime: runc
spec:
  containers:
  - name: app
    image: localhost/distroless-demo:v1
    imagePullPolicy: Never
---
apiVersion: v1
kind: Pod
metadata:
  name: app-distroless-kata
  labels:
    runtime: kata-clh
spec:
  runtimeClassName: kata-clh
  containers:
  - name: app
    image: localhost/distroless-demo:v1
    imagePullPolicy: Never
EOF

kubectl get pods -w

```

---

## 6. Verification & Security Tests

### Test 1: Kernel Isolation Proof

Inspect the startup logs of both pods and compare against the host VM's kernel:

```bash
uname -r
kubectl logs app-distroless-runc
kubectl logs app-distroless-kata

```

**Observed Results:**

* **Host VM:** `6.8.0-151-generic`
* **`app-distroless-runc`:** `Linux version 6.8.0-151-generic ...` *(Shares the host kernel)*
* **`app-distroless-kata`:** `Linux version 6.18.62 ...` *(Dedicated Kata guest kernel)*

---

### Test 2: Host Process & Hypervisor Boundary

Inspect the process table on the Ubuntu host VM:

```bash
ps aux | grep demo-app
ps aux | grep cloud-hypervisor

```

**Observed Results:**

* `app-distroless-runc` appears directly in the host process table under UID `65532` (`/demo-app`), scheduled directly by the host kernel.
* `app-distroless-kata`'s `/demo-app` process is completely hidden from the host; the host only sees the `/opt/kata/bin/cloud-hypervisor` VMM process.

---

### Test 3: Kernel Ring Buffer & Hardware Visibility

Attach ephemeral debug containers (`busybox`) to inspect `/proc/cmdline`, `dmesg`, and `/dev`:

```bash
# Inspect runc pod
kubectl debug app-distroless-runc --image=docker.io/library/busybox:1.36 --attach=true -- \
  sh -c "cat /proc/cmdline; echo '---'; dmesg 2>&1 | head -n 2"

# Inspect Kata pod
kubectl debug app-distroless-kata --image=docker.io/library/busybox:1.36 --attach=true -- \
  sh -c "dmesg | head -n 5; echo '---'; ls /dev | head -n 15"

```

**Observed Results:**

* **`runc`:** `/proc/cmdline` exposes the host VM's GRUB kernel parameters (`BOOT_IMAGE=/vmlinuz-6.8.0-151-generic...`), while `dmesg` is blocked only because Ubuntu enforces `kernel.dmesg_restrict=1`.
* **`kata-clh`:** `dmesg` shows the microVM's own virtual boot log (`root=/dev/vda1 rootflags=ro rootfstype=erofs...` and `BIOS-e820` virtual RAM map), completely isolated from host hardware logs.

---

### Test 4: Privileged Container Blast Radius

Test what happens if a manifest is misconfigured with `privileged: true` (or if an attacker achieves `CAP_SYS_ADMIN` via a runtime/kernel exploit):

```bash
cat << 'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: priv-test-runc
spec:
  containers:
  - name: shell
    image: docker.io/library/busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
---
apiVersion: v1
kind: Pod
metadata:
  name: priv-test-kata
spec:
  runtimeClassName: kata-clh
  containers:
  - name: shell
    image: docker.io/library/busybox:1.36
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
EOF

kubectl wait --for=condition=Ready pod/priv-test-runc pod/priv-test-kata --timeout=60s

# Compare visible block devices inside both privileged pods
kubectl exec priv-test-runc -- fdisk -l
kubectl exec priv-test-kata -- fdisk -l

```

**Observed Results:**

* **`priv-test-runc`:** Exposes the host VM's physical disk (`/dev/sda`, 20 GB) and LVM root volume (`/dev/dm-0`, 10 GB), allowing full host filesystem mount and node takeover.
* **`priv-test-kata`:** Returns empty output; host disks are invisible to the microVM's virtual bus, containing even `privileged: true` root inside an ephemeral sandbox.

---

### Test 5: Resource Overhead Benchmark

Measure memory footprint (`RSS`) and pod startup timestamps:

```bash
# Memory footprint (RSS in KB)
ps -o pid,rss,vsz,comm -C demo-app
ps -o pid,rss,vsz,comm -C cloud-hypervisor

# Startup event timestamps
kubectl describe pod app-distroless-runc | grep -E "Scheduled|Pulled|Started"
kubectl describe pod app-distroless-kata | grep -E "Scheduled|Pulled|Started"

```

**Observed Results:**

* **`runc` (`/demo-app`):** ~`1,984 KB` (~2 MB) RSS.
* **`kata-clh` (`cloud-hypervisor`):** ~`177,064 KB` (~173 MB) RSS (includes VMM + dedicated guest kernel + guest agent).

---

## 7. Summary Comparison Matrix

| Dimension | Distroless (`runc`) | Rootless Containers (`UserNS`) | Kata Containers (`kata-clh`) |
| --- | --- | --- | --- |
| **Primary Isolation** | Minimal userland filesystem | UID/GID namespace remapping | Hardware virtualization (KVM microVM) |
| **Kernel Boundary** | Shared host kernel | Shared host kernel | **Dedicated guest kernel per pod** |
| **Host Process View** | Visible (`PID` on host) | Visible (unprivileged host UID) | Hidden inside `cloud-hypervisor` VMM |
| **`privileged: true` Impact** | Full host disk & kernel access | Scoped to user namespace | Trapped inside ephemeral microVM |
| **Memory Overhead** | ~2 MB RSS | ~2 MB RSS | ~173 MB RSS (VMM + guest kernel) |
| **Best Use Cases** | Trusted internal microservices | CI runners, multi-tenant trusted apps | Untrusted code, AI sandboxes, hostile multi-tenancy |

---

## 8. Cleanup

```bash
kubectl delete pod app-distroless-runc app-distroless-kata priv-test-runc priv-test-kata --ignore-not-found

```



