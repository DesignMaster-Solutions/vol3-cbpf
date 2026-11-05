# Memory samples

Two dumps of the same benign guest, one per kernel. Download them from the
[v1.0.0 release](https://github.com/DesignMaster-Solutions/vol3-cbpf/releases/tag/v1.0.0) or rebuild them.

| Kernel | Dump (zstd) | Uncompressed sha256 | Ground truth |
|---|---|---|---|
| Debian 12 `6.1.0-54-cloud-amd64` (6.1.190-1) | `cbpf-6.1.0-54-cloud-amd64.elf.zst` | `expected/cbpf-6.1.0-54-cloud-amd64.elf.sha256` | `expected/serial-6.1.0-54-cloud-amd64.log` |
| Debian 13 `6.12.115+deb13.1-cloud-amd64` | `cbpf-6.12.115+deb13.1-cloud-amd64.elf.zst` | `expected/cbpf-6.12.115+deb13.1-cloud-amd64.elf.sha256` | `expected/serial-6.12.115+deb13.1-cloud-amd64.log` |

Both kernels have `CONFIG_CHECKPOINT_RESTORE=y` (seccomp programs are kept) and neither has `CONFIG_X86_X32_ABI`.
The release also has `SHA256SUMS` for the compressed files and the two symbol tables (`*.json.xz`, made with
dwarf2json `9f14607e`). Put the symbol table under `<dir>/linux/` and pass `-s <dir>`:

```
zstd -d cbpf-6.1.0-54-cloud-amd64.elf.zst
mkdir -p isf/linux && mv 6.1.0-54-cloud-amd64.json.xz isf/linux/
vol -p plugins -s isf -f cbpf-6.1.0-54-cloud-amd64.elf linux.cbpf.Seccomp
```

## What the guest runs

`guest/init` is PID 1 of an Alpine 3.20 userland. Before the dump it prints, on the serial console, everything the
tests compare against (`TRUTH` lines):

| Process | What it installs |
|---|---|
| `tcpdump` x2 | `udp and dst port 53` and `tcp[tcpflags] & (tcp-syn\|tcp-fin) != 0 and not src net 10.0.0.0/8` on `lo`; `tcpdump -d` and `-dd` of both printed |
| `cbpf-trigger` | `AF_PACKET` raw socket, filter shaped like a magic-packet trigger: IPv4, UDP, not fragmented, payload starts with `CBPF`. It only counts matches |
| `cbpf-udptrigger` | `AF_INET` UDP socket on 127.0.0.1:40000 with a payload-marker filter; also only counts |
| `cbpf-strict` | seccomp strict mode |
| `cbpf-dockerish` | libseccomp allowlist shaped like Docker's default profile: default `ERRNO(EPERM)`, 71 syscalls allowed, `personality` allowed only for 4 argument values |
| `cbpf-noexec` | `no_new_privs` and two stacked hand-written filters: `execve`/`execveat` -> `EPERM`, `mount`/`umount2` -> `EACCES`, foreign arch -> kill |
| `cbpf-pool` | a parent and 4 identical workers; 3 load the same libseccomp policy independently, worker 2 does not |

`cbpf_demo send` sends 3 datagrams to 127.0.0.1:40000, 2 with the marker: `cbpf-udptrigger` counts 2 and
`cbpf-trigger` counts 4, because an `AF_PACKET` socket on `lo` sees each packet leave and arrive. Nothing talks to the
outside: the guest has no network beyond loopback.

The guest also prints `/proc/<pid>/status` (`NoNewPrivs`, `Seccomp`, `Seccomp_filters`), the socket file descriptors
of every task and `/proc/net/packet`.

## Rebuilding

Requirements: Docker with linux/amd64 emulation. QEMU runs in TCG mode (no KVM); `-cpu max,la57=off` because these
kernels are built with `X86_5LEVEL=y` and Volatility needs 4-level paging in the dump.

```
./build_sample.sh                                              # 6.1, writes work/
WORK=$PWD/work-6.12 SUITE=trixie KVER=6.12.115+deb13.1-cloud-amd64 ./build_sample.sh
```

`dwarf2json` for the 6.12 vmlinux needs more than the 8 GB a default Docker Desktop VM has; if it is killed, build
dwarf2json on the host and run `dwarf2json linux --elf work-6.12/vmlinux-<KVER> --system-map
work-6.12/System.map-<KVER> | xz > work-6.12/isf/linux/<KVER>.json.xz`. Process IDs and the dump hash change on every
rebuild; the tests read PIDs from the serial log, so they keep working.
