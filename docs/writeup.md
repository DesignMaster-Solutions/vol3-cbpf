# vol3-cbpf: classic BPF in Linux memory, decoded

Write-up for the 2026 Volatility Plugin Contest. Author: Alan De Bortolo, Design Master Solutions LLC.

## Motivation

Two kinds of tiny programs decide a lot on a Linux machine, and both are classic BPF (cBPF):

1. **Socket filters.** `setsockopt(SO_ATTACH_FILTER)` hands the kernel a cBPF program that decides which packets a
   socket receives. tcpdump uses it. So do implants that wait for a "magic packet": Sandfly's analysis of BPFDoor
   describes a capture loop that "loads a BPF filter (hence the name)" and only wakes up for a crafted packet
   ([Sandfly Security](https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/)).
   The filter *is* the trigger. If an investigator can read it from memory, they know which packet wakes the
   implant, can write a network signature for it, and can look for the same filter elsewhere by hash.
2. **Seccomp policies.** Container runtimes, browsers, systemd services and sandboxed daemons confine themselves
   with seccomp, which runs a cBPF program on every system call. After a container escape or a privilege
   escalation the questions are: which processes were confined, by which policy, and which worker in a pool of
   identical ones was not?

What Volatility 3 offers today:

- `linux.sockstat` reports that a socket has a filter (`filter_type=socket_filter,bpf_filter_type=cBPF`) but does
  not decode it.
- Nothing reads seccomp.
- The eBPF plugins presented in 2023 deliberately leave classic BPF out; the accompanying post notes that bvp47,
  Symbiote and BPFDoor "are using only what is now known as classic BPF"
  ([vobst, 2023](https://vobst.github.io/2023/12/21/bpf_memory_forensics_with_volatility_3.html)).

The kernel translates cBPF to eBPF before running it, so the runnable form is not what the user wrote. But it also
keeps the original: `bpf_prog->orig_prog` (a `sock_fprog_kern`) is always saved for socket filters, and for seccomp
filters when the kernel has `CONFIG_CHECKPOINT_RESTORE=y` (so that CRIU can dump them). Debian's cloud kernels
6.1 and 6.12 have it. That original is what these plugins read.

## Design

```
plugins/linux/
  cbpf_lib.py       pure Python, no Volatility import: decoder, symbolic evaluator, summaries, seccomp semantics
  cbpf_syscalls.py  x86_64 syscall numbers (generated from the guest's linux-headers)
  cbpf.py           the two Volatility plugins
```

**Decoder.** `image()` reproduces libpcap 1.10.4's `bpf_image()` character for character, including the Linux
ancillary loads (`[proto]`, `[vlan_tci]`, ...), signed printing of `ret` and ALU immediates, and the
`jt`/`jf` targets. The result is a listing an analyst can diff against `tcpdump -d '<expr>'`.

**Symbolic evaluator.** `explore()` walks every path of a cBPF program (cBPF only jumps forward, so it always
terminates), keeping the accumulator, index register and scratch memory as either concrete numbers or symbolic
expressions. Conditions on symbolic values fork the path and are recorded; equalities already established on a
path prune impossible branches (an `ether.type == 0x800` path cannot later take `ether.type == 0x86dd`).

- For socket filters, packet bytes are symbolic and named (`ether.type`, `ip.proto`, `ip.frag`, `ip.src`, and
  `l4[...]` for offsets relative to the transport header after the usual `ldxb 4*([14]&0xf)`). The summary lists the
  conditions of every accepting path and prints 2-4 byte constants as ASCII when printable, which is how a magic
  marker shows up: `l4[8:4] == 0x43425046 "CBPF"`.
- For seccomp, `seccomp_data.nr` and `.arch` are concrete and the instruction pointer and arguments are symbolic.
  Each of the 365 x86_64 syscalls is evaluated through the whole filter chain. If a path branches on an argument,
  the result is the set of reachable actions, marked "depends on arguments" (Docker's `personality` rule).

**Kernel semantics.** Filters are evaluated newest first and combined the way `seccomp_run_filters()` does: the
action with the lowest `(s32)(ret & SECCOMP_RET_ACTION_FULL)` wins and ties keep the newest filter's value. Strict
mode (mode 1) is the fixed read/write/exit/rt_sigreturn set. The plugin also evaluates an i386 syscall (bad
architecture handling) and x32 numbers (`nr | 0x40000000`), since a filter that forgets the x32 bit is a known
pitfall.

**Grouping.** Each process's chain is fingerprinted (sha256 over the per-filter program hashes). Processes with the
same parent and name are expected to share a fingerprint; members that do not are flagged `DIFFERS: n of m siblings
run <fingerprint>`.

## Validation

The memory sample is built by a script (`sample/build_sample.sh`): a Debian kernel with debug symbols boots an
Alpine userland in QEMU (TCG, no KVM), a benign workload installs known programs and **prints the ground truth on
the serial console before the dump**: `tcpdump -d` and `-dd` of the two capture expressions, the raw `-dd` of every
hand-written filter, the libseccomp PFC and rule list of every seccomp policy, and `/proc/<pid>/status` (Seccomp,
NoNewPrivs, Seccomp_filters) and `/proc/<pid>/fd` for every task. The tests compare the plugins' output with that
log, not with what the code is expected to produce:

- the decoder against the real tcpdump 4.99.4/libpcap 1.10.4, line by line, on 27 expressions chosen to reach every
  instruction class tcpdump emits (239 lines) plus the two programs captured in the guest; instructions tcpdump
  never emits are checked against the format strings in libpcap's `bpf_image.c`;
- `SocketFilters` on the dump: every socket with a filter found with the right PID and fd, the recovered bytes
  hash-equal to the guest's `-dd`, and the listing equal to the guest's `tcpdump -d`;
- `Seccomp` on the dump: mode, no_new_privs and filter count equal to `/proc/<pid>/status` for every task; the
  per-syscall table equal to the rule list each process printed; the one unconfined worker flagged.

Tests were seen failing before passing: injected defects in the decoder (jump targets, signedness, column width,
hex/decimal choice, an ancillary name) and in the plugins (no_new_privs bit, filter order, family handling, sibling
marking, link-layer naming) each turned the suite red. Mutation testing (mutmut) of `cbpf_lib.py` is reported in the
README.

## Limits

- x86_64 only (syscall table, `AUDIT_ARCH_X86_64`, little-endian `sock_filter`).
- Seccomp programs are only recoverable when the kernel kept `orig_prog` (`CONFIG_CHECKPOINT_RESTORE=y`); otherwise
  the plugin says so instead of guessing from the translated eBPF.
- eBPF socket programs (`SO_ATTACH_BPF`) are reported as eBPF and left to `linux.ebpf`; `SO_ATTACH_REUSEPORT_CBPF`
  programs are not decoded yet.
- Threads are evaluated individually, but the sibling comparison uses one entry per process.
- The socket summary names fields assuming an Ethernet frame only for `AF_PACKET` raw sockets; elsewhere offsets are
  printed raw (`pkt[8:4]`).
- Symbolic evaluation caps the number of paths (512 for summaries, 256 per syscall); when hit, the summary says so.

## Why it should win

- **Useful on day one.** It answers two questions responders already ask (what wakes this implant, and who was not
  sandboxed) with output that can be pasted into a report or diffed against `tcpdump -d`.
- **It closes a gap others named.** sockstat sees the filter but not the program; the eBPF work set classic BPF
  aside; nothing reads seccomp.
- **Correct by construction, then proven.** The output format is libpcap's, the precedence rules are the kernel's,
  and every claim is checked against ground truth printed inside the guest before the dump, on two kernels.
- **Reproducible.** One script rebuilds the sample, the symbol table and the expected output from public packages.
