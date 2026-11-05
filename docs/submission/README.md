# Submission package (not sent)

Everything the contest rules ask for, ready for Alan to send. **Nothing here has been sent.** The signed
Individual Contributor License Agreement (ICLA) must be requested from the Volatility Foundation and signed by
Alan before sending.

Rules checked on 2026-11-05 at https://volatilityfoundation.org/volatility-plugin-contest/ : send to
`contest@volatilityfoundation.org`, include source code, a memory sample, usage, a write-up with motivation and
why it should win, and a signed ICLA; say whether multiple plugins are one entry or several; deadline
31 December 2026, earlier is preferred.

| Required item | Where |
|---|---|
| Source code | this repository, `plugins/linux/`, tag `v1.0.0` |
| Memory sample | Release v1.0.0: `cbpf-6.1.0-54-cloud-amd64.elf.zst` and `cbpf-6.12.115+deb13.1-cloud-amd64.elf.zst` + symbol tables + `SHA256SUMS`; uncompressed sha256 in `sample/expected/`. Download, hash check, decompression and a plugin run on the downloaded file were verified on 2026-11-05 |
| How it is used | `README.md` (Usage, real output) |
| Write-up | `docs/writeup.md` |
| Signed ICLA | to be attached by Alan |
| Entry type | one entry, separate from our io_uring entry (see e-mail) |

## E-mail text

To: contest@volatilityfoundation.org
Subject: Volatility Plugin Contest 2026 submission: classic BPF in memory (socket filters and seccomp)

Hello,

I would like to submit "vol3-cbpf" to the 2026 Volatility Plugin Contest.

It adds two Volatility 3 plugins that decode the classic BPF programs the Linux kernel keeps in memory:
linux.cbpf.SocketFilters (every socket filter, the mechanism BPFDoor uses as its magic-packet trigger, shown as a
tcpdump -d listing with a one-line summary and a hash) and linux.cbpf.Seccomp (each task's seccomp mode,
no_new_privs and its policy evaluated per system call, with sibling processes that run a different policy flagged).

- Source code, usage and real output: https://github.com/DesignMaster-Solutions/vol3-cbpf (submitted version: tag v1.0.0)
- Memory samples (Debian 6.1 and 6.12 kernels) and symbol tables: https://github.com/DesignMaster-Solutions/vol3-cbpf/releases/tag/v1.0.0 (sha256 in the repository, sample/expected/)
- Write-up: https://github.com/DesignMaster-Solutions/vol3-cbpf/blob/v1.0.0/docs/writeup.md
- Signed ICLA: attached

Please evaluate the two plugins together as ONE entry. It is separate from my other submission this year
(io_uring plugins, repository vol3-io-uring), which should be evaluated as its own entry.

Thank you,
Alan De Bortolo
Design Master Solutions LLC

## Before sending (Alan)

1. Request the ICLA from the Volatility Foundation (already scheduled by the Impressora), sign it, attach it.
2. Send the e-mail above from the address that will receive the prize correspondence.
3. If anything changes after v1.0.0, tag a new version and update the tag in the e-mail.
