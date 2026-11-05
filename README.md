# vol3-cbpf: classic BPF programs in Linux memory, decoded

Two kinds of small programs decide a lot about a Linux system and are almost invisible to an
investigator who only has a memory image:

- **Socket filters.** A process can attach a classic BPF program to a socket (`SO_ATTACH_FILTER`)
  so the kernel only hands it the packets that match. tcpdump does this. So does BPFDoor:
  [Sandfly's analysis](https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/)
  describes how its packet capture loop "loads a BPF filter (hence the name)" and waits for a
  magic packet before it starts attacker operations such as a bind shell. The filter is the
  trigger: decode it and you know exactly which packet wakes the implant.
- **Seccomp policies.** Container runtimes, browsers, systemd units and many daemons confine
  themselves with seccomp, which is also a classic BPF program, run on every system call. Which
  processes were confined, by which policy, and which one in a group of identical workers was not,
  is a question incident responders ask after a container escape.

Volatility 3 can already see that a socket has a filter (`linux.sockstat` reports
`socket_filter` and `cBPF`), but nothing decodes the program, and nothing reads seccomp at all.
The eBPF plugins presented in 2023
([blog post](https://vobst.github.io/2023/12/21/bpf_memory_forensics_with_volatility_3.html))
leave classic BPF out on purpose: it notes that bvp47, Symbiote and BPFDoor "are using only what
is now known as classic BPF". The kernel keeps the original classic program next to the
translated one (`bpf_prog->orig_prog`), so it can be recovered intact from memory.

## Planned plugins

| Plugin | What it shows |
|---|---|
| `linux.cbpf.SocketFilters` | Every socket with a classic filter, including `AF_PACKET` raw sockets: PID, process, fd, family, type, protocol, program length, the decoded program (a `tcpdump -d` style listing) and a one-line summary of what it accepts, plus a hash for matching known triggers. |
| `linux.cbpf.Seccomp` | Every task's seccomp mode, `no_new_privs`, and each filter in its chain decoded into a system call table (allow, errno, kill, trap, log, notify, trace), with the architecture checks. Identical policies are grouped, so the one process that differs from its siblings stands out. |

## Memory sample

A reproducible QEMU guest (Debian kernel with debug symbols, symbol table built with
`dwarf2json`) running benign programs whose policies are printed as ground truth before the dump:
a capture with a known tcpdump expression and the matching `tcpdump -d` listing, a filter shaped
like a magic-packet trigger, and processes under different seccomp policies. Build script,
expected output and hashes will live in `sample/`.

## Status

In development for the 2026 Volatility Plugin Contest (deadline 31 December 2026). Nothing in the
table above is released yet. This README will list exactly what works, on which kernels it was
tested and what it does not cover.

Author: Alan De Bortolo, Design Master Solutions LLC.
