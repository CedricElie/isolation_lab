
# Technical Note: Host-Level eBPF Syscall Observability (`runc` vs. Kata Containers)

## Overview
This note documents the eBPF syscall tracing extension for the **Distroless vs. Kata Containers** Kubernetes lab. By attaching eBPF tracepoints (`bpftrace`) to the host Ubuntu 24.04 kernel (`6.8.0-151-generic`), we observe how application syscalls cross—or fail to cross—the isolation boundary in standard `runc` containers versus KVM-backed Kata microVMs (`kata-clh`).

---

## 1. Architectural Mechanism

* **Distroless Container (`runc`):** Although stripped of shells and userland tools, the compiled binary executes natively as a host process. Every file access, timer sleep, and network call invokes the **shared host Linux kernel** directly via standard syscalls (`openat`, `read`, `close`, etc.).
* **Kata Container (`kata-clh`):** The exact same distroless binary executes inside a lightweight Cloud Hypervisor microVM running its own dedicated **guest Linux kernel** (`6.18.62`). Application syscalls are trapped and serviced entirely by the guest kernel inside the VM's address space; the host kernel only interacts with the `cloud-hypervisor` VMM process via KVM `ioctl` calls when virtual hardware/device I/O requires hypervisor intervention.

```text
  [Host eBPF Probes: raw_syscalls / sys_enter_openat]
             │                                  │
             ▼ (Sees all app syscalls)          ✕ (Blind to guest syscalls)
  +---------------------+            +---------------------+
  |  demo-app (runc)    |            |  demo-app (Kata)    |
  |  openat, read, etc. |            |  openat, read, etc. |
  +---------------------+            +----------│----------+
             │                                  ▼
             │                       +---------------------+
             │                       | Guest Kernel 6.18   |
             │                       +----------│----------+
             │                                  ▼ (KVM ioctl only)
             │                       +---------------------+
             │                       |  cloud-hypervisor   |
             ▼                       +----------│----------+
  ==============================================▼=============
                  Host Ubuntu Kernel (6.8.0)

```

---

## 2. Workload Instrumentation (`v2`)

To generate deterministic, periodic syscalls without requiring an interactive shell inside the distroless image (`gcr.io/distroless/static-debian12:nonroot`), the Go test binary wakes every 2 seconds to read `/etc/hostname`:

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	data, _ := os.ReadFile("/proc/version")
	fmt.Printf("Started! Kernel: %s\n", string(data))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Triggers openat (257), read (0), fstat (5), and close (3) every 2s
			_, _ = os.ReadFile("/etc/hostname")
		case <-sig:
			return
		}
	}
}

```

Build and import into k3s:

```bash
podman build -t localhost/distroless-demo:v2 .
podman save localhost/distroless-demo:v2 | sudo k3s ctr images import -

```

---

## 3. Host eBPF Tracing Experiments

### Prerequisites

Install `bpftrace` on the Ubuntu 24.04 Kubernetes worker node:

```bash
sudo apt-get update && sudo apt-get install -y bpftrace

```

> **Linux `comm` Truncation Note:** The Linux kernel truncates process `comm` names in `task_struct` to **15 characters** (`TASK_COMM_LEN - 1`). When filtering by process name in `bpftrace`, match `"cloud-hyperviso"` (without the trailing `r`).

### Experiment A: 5-Second Raw Syscall Surface Count

Count all syscalls entering the host kernel from either `demo-app` (`app-distroless-runc`) or `cloud-hyperviso` (`app-distroless-kata`) over a 5-second window:

```bash
sudo bpftrace -e '
tracepoint:raw_syscalls:sys_enter /comm == "demo-app" || comm == "cloud-hyperviso"/ {
  @[comm, args.id] = count();
}
interval:s:5 { exit(); }'

```

#### Observed Output & Syscall Decoding (`x86_64`)

```text
Attaching 2 probes...

@[demo-app, 15]: 2
@[demo-app, 3]: 2
@[demo-app, 257]: 2
@[demo-app, 5]: 2
@[demo-app, 233]: 2
@[demo-app, 234]: 2
@[demo-app, 281]: 2
@[demo-app, 39]: 2
@[demo-app, 0]: 4
@[demo-app, 72]: 8
@[demo-app, 202]: 10
@[demo-app, 35]: 25

```

| Syscall ID (`x86_64`) | Syscall Name | Count (5s) | Source & Behavior |
| --- | --- | --- | --- |
| `257` | `openat` | 2 | `demo-app` (`runc`) opening `/etc/hostname` |
| `0` | `read` | 4 | `demo-app` (`runc`) reading file bytes + EOF |
| `3` | `close` | 2 | `demo-app` (`runc`) closing file descriptor |
| `5` | `fstat` | 2 | `demo-app` (`runc`) checking file size |
| `35` | `nanosleep` | 25 | Go runtime `sysmon` background timer |
| `202` | `futex` | 10 | Go goroutine scheduling & synchronization |
| `281` | `epoll_pwait` | 2 | Go network/timer poller |
| *(Any)* | *(`cloud-hyperviso`)* | **0** | **Handled internally by Kata guest kernel `6.18.62**` |

---

### Experiment B: Real-Time File Access Monitoring (`sys_enter_openat`)

Stream live file-open attempts hitting the host kernel from both workloads:

```bash
sudo bpftrace -e '
tracepoint:syscalls:sys_enter_openat /comm == "demo-app" || comm == "cloud-hyperviso"/ {
  printf("%-16s PID:%-6d openat: %s\n", comm, pid, str(args.filename));
}'

```

#### Observed Output

```text
Attaching 1 probe...
demo-app         PID:20392  openat: /etc/hostname
demo-app         PID:20392  openat: /etc/hostname
demo-app         PID:20392  openat: /etc/hostname

```

* **`app-distroless-runc` (`PID: 20392`):** Every file open is visible to the host kernel in real time.
* **`app-distroless-kata`:** Zero events appear on the host; `/etc/hostname` is resolved inside the microVM's guest filesystem (`erofs`/overlayfs) via its private kernel.

---

## 4. Key Engineering Takeaways

1. **Attack Surface Reduction:** In a standard or distroless container, an attacker who achieves memory-corruption RCE can invoke any of the ~350+ host Linux syscalls directly (e.g., exploiting `io_uring`, `netfilter`, or filesystem bugs). Under Kata Containers, those syscalls hit an ephemeral guest kernel; the host kernel only exposes the minimal KVM hypervisor interface (`ioctl`) to the VMM.
2. **The Runtime Observability Trade-Off:** Host-based eBPF security and observability agents (e.g., Cilium Tetragon, Falco eBPF, Tracee, Inspektor Gadget) effortlessly inspect every syscall made by `runc` containers from the host node, **but are completely blind to application syscalls inside Kata microVMs**. Securing and observing Kata workloads requires shifting telemetry to network policies (CNI/Cilium L3–L7), VMM-level auditing, or in-guest agents.

```
