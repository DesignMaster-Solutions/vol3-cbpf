# vol3-cbpf: classic BPF programs in Linux memory, decoded

Two Volatility 3 plugins that read the classic BPF (cBPF) programs the Linux kernel keeps in memory:

| Plugin | What it shows |
|---|---|
| `linux.cbpf.SocketFilters` | Every socket with a filter (`SO_ATTACH_FILTER`), including `AF_PACKET` raw sockets: PID, process, fd, family, type, protocol, program length, a sha256 of the program for matching known triggers, and a one-line summary of what it accepts. `--dump` adds the program as a listing identical to `tcpdump -d`. |
| `linux.cbpf.Seccomp` | Every task's seccomp mode, `no_new_privs`, filter count and a fingerprint of its filter chain, with the policy evaluated per x86_64 system call (default action, the exceptions, rules that depend on arguments, what happens to i386 and x32 system calls). Processes with the same parent and name that run a different policy are flagged. `--table` lists every syscall whose action differs from the default; `--dump` lists each filter. |

## Why

- **Socket filters.** tcpdump uses them; so does BPFDoor:
  [Sandfly's analysis](https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/)
  describes a capture loop that "loads a BPF filter (hence the name)" and waits for a magic packet before it
  starts attacker operations. The filter is the trigger: decode it and you know which packet wakes the implant.
- **Seccomp policies.** Container runtimes, browsers, systemd units and many daemons confine themselves with
  seccomp, which is also a cBPF program, run on every system call. Which processes were confined, by which policy,
  and which worker in a group of identical ones was not, is a question asked after a container escape.

`linux.sockstat` already reports that a socket has a filter (`socket_filter`, `cBPF`) but does not decode it, and
no Volatility 3 plugin reads seccomp state (the framework mentions seccomp only as ptrace option flags). The eBPF
plugins presented in 2023
([blog post](https://vobst.github.io/2023/12/21/bpf_memory_forensics_with_volatility_3.html)) leave classic BPF
out on purpose; the post notes that bvp47, Symbiote and BPFDoor "are using only what is now known as classic BPF".
The kernel runs a translated eBPF version but keeps the original program in `bpf_prog->orig_prog`, which is what
these plugins read: always for socket filters, and for seccomp filters when the kernel was built with
`CONFIG_CHECKPOINT_RESTORE=y` (Debian's cloud kernels are). Without it, `Seccomp` still reports mode,
`no_new_privs` and filter count, and says the program was not kept.

## Usage

Python 3, Volatility 3 2.28.2 (the latest on PyPI on 5 November 2026).

```
pip install volatility3==2.28.2
vol -p plugins -s <symbols> -f <dump> linux.cbpf.SocketFilters [--pid N ...] [--dump]
vol -p plugins -s <symbols> -f <dump> linux.cbpf.Seccomp [--pid N ...] [--all] [--table] [--dump]
```

`--all` also lists tasks without seccomp (by default only confined tasks and flagged siblings are shown).

### Real output on the sample (Debian 6.1 kernel)

`linux.cbpf.SocketFilters` (sha256 shortened here; the plugin prints it in full):

```
PID  Process          FD  Family     Type   Protocol   Kind  Insns  SHA256        Program
89   tcpdump          4   AF_PACKET  RAW    ETH_P_ALL  cBPF  16     bffed42c2744  accept if (ether.type == 0x800 and ip.proto == 0x11 and !(ip.frag & 0x1fff) and l4[2:2] == 0x35 (53)) or (ether.type == 0x86dd and ip6.nxt == 0x11 and ip6.l4[2:2] == 0x35 (53))
94   tcpdump          4   AF_PACKET  RAW    ETH_P_ALL  cBPF  14     a2e1df11d35d  accept if (ether.type == 0x800 and ip.proto == 0x6 and !(ip.frag & 0x1fff) and l4[13:1] & 0x3 and (ip.src & 0xff000000) != 0xa000000)
95   cbpf-trigger     3   AF_PACKET  RAW    ETH_P_ALL  cBPF  11     178789198798  accept if (ether.type == 0x800 and ip.proto == 0x11 and !(ip.frag & 0x1fff) and l4[8:4] == 0x43425046 "CBPF")
96   cbpf-udptrigger  3   AF_INET    DGRAM  UDP        cBPF  6      8579baf8c44c  accept if (len >= 0xc and pkt[8:4] == 0x43425046 "CBPF")
```

`--pid 95 --dump` (the trigger-shaped filter), the listing rows:

```
(000) ldh      [12]
(001) jeq      #0x800           jt 2	jf 10
(002) ldb      [23]
(003) jeq      #0x11            jt 4	jf 10
(004) ldh      [20]
(005) jset     #0x1fff          jt 10	jf 6
(006) ldxb     4*([14]&0xf)
(007) ld       [x + 22]
(008) jeq      #0x43425046      jt 9	jf 10
(009) ret      #65535
(010) ret      #0
```

`linux.cbpf.Seccomp` (the `Summary` column is abbreviated with `...`; full text in `docs/output/`):

```
PID  PPID  Process         Mode      NNP    Filters  Policy            Siblings                                       Summary
99   1     cbpf-strict     strict    False  0        strict                                                           default KILL_THREAD; ALLOW 4: read,write,rt_sigreturn,exit; ...
101  1     cbpf-dockerish  filter    False  1        a8ddec582eb62e12                                                 default ERRNO(1); ALLOW|ERRNO(1) (depends on arguments) 1: personality; ALLOW 71: read,write,close,...
103  1     cbpf-noexec     filter    True   2        6c6888771bca4ad5                                                 default ALLOW; ERRNO(1) 2: execve,execveat; ERRNO(13) 2: mount,umount2; i386 KILL_PROCESS; x32 ALLOW (kernel built without the x32 ABI)
107  105   cbpf-pool       filter    True   1        58e5c97672d3b446                                                 default KILL_PROCESS; ALLOW 16: read,write,close,mmap,...
108  105   cbpf-pool       filter    True   1        58e5c97672d3b446                                                 default KILL_PROCESS; ALLOW 16: ...
109  105   cbpf-pool       disabled  False  0        none              DIFFERS: 3 of 4 siblings run 58e5c97672d3b446  no seccomp
110  105   cbpf-pool       filter    True   1        58e5c97672d3b446                                                 default KILL_PROCESS; ALLOW 16: ...
```

Reading it: `cbpf-noexec`'s hand-written filters check the architecture but not the x32 bit, so x32 numbers would
be allowed; on this kernel that is harmless because it has no x32 ABI, and the plugin says so (it looks for the
kernel's x32 dispatch symbol). Worker 109 is the one that skipped its policy.

Complete, unedited output of every command (both kernels) is in [`docs/output/`](docs/output/).

## Memory samples and what was tested

| Kernel | `CONFIG_CHECKPOINT_RESTORE` | x32 ABI | Result |
|---|---|---|---|
| Debian 12 `6.1.0-54-cloud-amd64` | y | no | full test suite passes (197 tests) |
| Debian 13 `6.12.115+deb13.1-cloud-amd64` | y | no | memory and guest tests pass (16 tests); same programs, same hashes |

Both dumps (zstd, about 37 MB each) and their symbol tables are assets of the
[v1.0.0 release](https://github.com/DesignMaster-Solutions/vol3-cbpf/releases/tag/v1.0.0), with sha256 sums.
[`sample/README.md`](sample/README.md) describes the guest and how to rebuild everything with Docker and QEMU.

The guest prints the ground truth on its serial console before the dump: `tcpdump -d`/`-dd`, the raw program of
every hand-written filter, libseccomp's PFC and rule list for every policy, `/proc/<pid>/status` and socket fds. The
tests compare the plugins with that log ([`sample/expected/`](sample/expected/)):

- `tests/test_decoder.py`: the listing equals the real tcpdump 4.99.4 / libpcap 1.10.4 `-d` output, line by line,
  for 27 expressions covering every instruction tcpdump emits (`tests/data/tcpdump_corpus.txt`, regenerated by
  `tests/gen_tcpdump_corpus.sh`) and for the two captures in the guest; the remaining instructions, all 16 Linux
  ancillary loads and all 65536 possible opcodes (`unimp`) follow libpcap's `bpf_image.c`.
- `tests/test_evaluate.py`, `tests/test_semantics.py`: seccomp action precedence across stacked filters,
  argument-dependent rules, every ALU/load/jump on a known packet, infeasible-path pruning, summaries.
- `tests/test_memory.py` (needs the sample): every filtered socket found with its fd, program bytes hash-equal to the
  guest's `-dd`, listing equal to the guest's `tcpdump -d`; mode, `no_new_privs` and filter count equal to
  `/proc/<pid>/status`; per-syscall tables equal to each policy's rules; filter order; the odd worker flagged.

Run them with `pytest tests` (memory tests skip themselves without the sample; for the 6.12 sample set
`KVER=6.12.115+deb13.1-cloud-amd64 CBPF_WORK=<dir>`).

Every test was seen failing: injected defects in the plugins (no_new_privs bit, filter order, skipped family, sibling
marking, link-layer naming, x32 note, short read) each turned the memory tests red. Mutation testing of the shared
library with mutmut 3 (`tests/run_mutmut.sh`): 726 mutants, 621 killed (a handful of them by timeout; the split varies between runs), 105 survived. None of the survivors is in the
disassembler (one equivalent boundary mutant in `_abs_operand`); most change only the text of symbolic expressions
or defensive branches. Mutation testing found one real bug, fixed: codes with stray high bits were printed as
instructions, where libpcap prints `unimp`.

## Limits

- x86_64 kernels only.
- Seccomp programs need `CONFIG_CHECKPOINT_RESTORE=y`; without it only mode, `no_new_privs` and count are shown.
- `SO_ATTACH_BPF` (eBPF) socket programs are reported as eBPF and left to `linux.ebpf`; reuseport cBPF programs
  (`SO_ATTACH_REUSEPORT_CBPF`) are not decoded.
- Field names in summaries assume an Ethernet frame only for `AF_PACKET` raw sockets; elsewhere offsets are raw.
- The evaluator caps paths (512 per socket summary, 256 per syscall) and says so when the cap is hit.
- The sibling comparison uses one entry per process; threads are listed individually.

Design, validation and motivation in detail: [`docs/writeup.md`](docs/writeup.md).

Author: Alan De Bortolo, Design Master Solutions LLC. Prepared for the 2026 Volatility Plugin Contest.

License: Volatility Software License 1.0, the license of Volatility 3 ([LICENSE.txt](LICENSE.txt)).
