# vol3-cbpf: classic BPF programs in Linux memory, decoded.
#   linux.cbpf.SocketFilters  socket filters (SO_ATTACH_FILTER): tcpdump, AF_PACKET triggers such as BPFDoor's
#   linux.cbpf.Seccomp        seccomp mode, no_new_privs and the per-syscall policy of every task
# Copyright 2026 Alan De Bortolo, Design Master Solutions LLC. Licensed under the Volatility Software License 1.0.

import hashlib
import logging
import os
import sys
from collections import Counter
from typing import List, Optional

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist, sockstat

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cbpf_lib as L  # noqa: E402
from cbpf_syscalls import X86_64  # noqa: E402

vollog = logging.getLogger(__name__)

BPF_MAXINSNS = 4096


def read_orig_prog(context, prog) -> Optional[List[L.Insn]]:
    """The classic program the kernel kept in bpf_prog->orig_prog (sock_fprog_kern), or None if absent."""
    if not prog or not prog.has_member("orig_prog") or not prog.orig_prog:
        return None
    fprog = prog.orig_prog.dereference()
    n = int(fprog.len)
    if not 0 < n <= BPF_MAXINSNS:
        raise exceptions.InvalidAddressException(prog.vol.layer_name, prog.vol.offset, f"bad orig_prog len {n}")
    raw = context.layers[prog.vol.layer_name].read(int(fprog.filter), n * 8)
    return L.parse(raw)


def _base_requirements():
    return [
        requirements.ModuleRequirement(name="kernel", description="Linux kernel", architectures=["Intel64"]),
        requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(4, 0, 0)),
        requirements.ListRequirement(name="pid", element_type=int, optional=True,
                                     description="Only these process IDs"),
        requirements.BooleanRequirement(name="dump", default=False, optional=True,
                                        description="Print each program as a tcpdump -d style listing"),
    ]


class SocketFilters(interfaces.plugins.PluginInterface):
    """Decodes the classic BPF filter attached to every socket (SO_ATTACH_FILTER)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return _base_requirements() + [
            requirements.VersionRequirement(name="sockstat", component=sockstat.Sockstat, version=(3, 0, 0)),
        ]

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid"))
        for task, _ns, fd, family, stype, proto, fields in sockstat.Sockstat.list_sockets(
                self.context, vmlinux.name, filter_func):
            sk = self.context.object(vmlinux.symbol_table_name + "!sock", layer_name=fields[0].vol.layer_name,
                                     offset=fields[0].vol.offset)  # struct sock is the first member of every *_sock
            if not sk.sk_filter:
                continue
            try:
                prog = sk.sk_filter.prog
                insns = read_orig_prog(self.context, prog)
            except exceptions.InvalidAddressException as e:
                vollog.info(f"pid {task.pid} fd {fd}: {e}")
                insns, prog = None, None
            ptype = prog.get_type() if prog else None
            if insns is None:
                kind = "eBPF" if ptype == "BPF_PROG_TYPE_SOCKET_FILTER" else "unreadable"
                summary = "eBPF program, see linux.ebpf" if kind == "eBPF" else "orig_prog not readable"
                count, digest = renderers.NotAvailableValue(), renderers.NotAvailableValue()
            else:
                kind, count, digest = "cBPF", len(insns), L.program_hash(insns)
                ethernet = family == "AF_PACKET" and stype == "RAW"
                summary = L.summarize_socket_filter(insns, ethernet=ethernet)
            yield 0, (int(task.tgid), utility.array_to_string(task.comm), int(fd), family or "?", stype or "?",
                      str(proto) if proto else "?", format_hints.Hex(sk.vol.offset), kind, count, digest, summary)
            if insns and self.config.get("dump"):
                for line in L.disassemble(insns):
                    yield 1, (int(task.tgid), utility.array_to_string(task.comm), int(fd), family or "?",
                              stype or "?", str(proto) if proto else "?", format_hints.Hex(sk.vol.offset), kind,
                              count, digest, line)

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("FD", int), ("Family", str), ("Type", str), ("Protocol", str),
             ("Sock", format_hints.Hex), ("Kind", str), ("Insns", int), ("SHA256", str), ("Program", str)],
            self._generator())


MODES = {0: "disabled", 1: "strict", 2: "filter"}


class Seccomp(interfaces.plugins.PluginInterface):
    """Seccomp mode, no_new_privs and the decoded per-syscall policy of every task, grouped by sibling."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return _base_requirements() + [
            requirements.BooleanRequirement(name="all", default=False, optional=True,
                                            description="Also list tasks without seccomp"),
            requirements.BooleanRequirement(name="table", default=False, optional=True,
                                            description="List every syscall whose action differs from the default"),
        ]

    def _chain(self, task):
        """Filters newest first, as the kernel runs them; None marks a filter whose program was not kept."""
        chain, f, seen = [], task.seccomp.filter, set()
        while f and int(f) not in seen and len(chain) < 512:
            seen.add(int(f))
            chain.append(read_orig_prog(self.context, f.prog))
            f = f.prev
        return chain

    def _collect(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid"))
        for task in pslist.PsList.list_tasks(self.context, vmlinux.name, filter_func, include_threads=True):
            if not task.mm:
                continue  # kernel threads
            mode = int(task.seccomp.mode)
            nnp = bool(int(task.atomic_flags) & 1)  # PFA_NO_NEW_PRIVS
            row = {"task": task, "mode": mode, "nnp": nnp, "chain": [], "policy": None, "fp": "none"}
            try:
                if mode == 2:
                    row["chain"] = self._chain(task)
                    if any(c is None for c in row["chain"]):
                        row["fp"] = "unreadable"
                    else:
                        row["fp"] = hashlib.sha256(
                            "".join(L.program_hash(c) for c in row["chain"]).encode()).hexdigest()[:16]
                        row["policy"] = L.evaluate_policy(row["chain"], X86_64)
                elif mode == 1:
                    row["fp"], row["policy"] = "strict", L.strict_policy(X86_64)
            except exceptions.InvalidAddressException as e:
                vollog.info(f"tid {task.pid}: {e}")
                row["fp"] = "unreadable"
            yield row

    @staticmethod
    def mark_siblings(rows):
        """Tasks sharing parent and name are expected to share a policy; flag the ones that do not."""
        groups = {}
        for r in rows:
            t = r["task"]
            if int(t.pid) == int(t.tgid):  # one entry per process for the comparison
                groups.setdefault((int(t.real_parent.tgid), utility.array_to_string(t.comm)), []).append(r)
        for members in groups.values():
            counts = Counter(r["fp"] for r in members)
            if len(members) < 2 or len(counts) < 2:
                continue
            major, n = counts.most_common(1)[0]
            for r in members:
                if r["fp"] != major:
                    r["siblings"] = f"DIFFERS: {n} of {len(members)} siblings run {major}"

    def _generator(self):
        rows = list(self._collect())
        self.mark_siblings(rows)
        vmlinux = self.context.modules[self.config["kernel"]]
        x32 = any(vmlinux.has_symbol(n) for n in ("x32_sys_call", "x32_sys_call_table"))
        for r in rows:
            t = r["task"]
            if r["mode"] == 0 and not self.config.get("all") and "siblings" not in r:
                continue
            filters = int(t.seccomp.filter_count.counter) if t.seccomp.has_member("filter_count") else len(r["chain"])
            if r["policy"]:
                summary = L.summarize_policy(r["policy"], X86_64)
                if not x32:
                    summary += " (kernel built without the x32 ABI)"
            elif r["fp"] == "unreadable":
                summary = "filter program not kept in memory (kernel without CONFIG_CHECKPOINT_RESTORE?)"
            else:
                summary = "no seccomp"
            base = (int(t.tgid), int(t.pid), int(t.real_parent.tgid), utility.array_to_string(t.comm),
                    MODES.get(r["mode"], str(r["mode"])), r["nnp"], filters, r["fp"], r.get("siblings", ""))
            yield 0, base + (summary,)
            if self.config.get("dump"):
                for i, prog in enumerate(r["chain"]):
                    yield 1, base + (f"filter {i} (newest first): {len(prog or [])} insns",)
                    for line in L.disassemble(prog or []):
                        yield 2, base + (line,)
            if self.config.get("table") and r["policy"]:
                default = Counter(r["policy"].table.values()).most_common(1)[0][0]
                for nr, act in r["policy"].table.items():
                    if act != default:
                        yield 1, base + (f"{X86_64[nr]} ({nr}): {act}",)

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("TID", int), ("PPID", int), ("Process", str), ("Mode", str), ("NoNewPrivs", bool),
             ("Filters", int), ("Policy", str), ("Siblings", str), ("Summary", str)],
            self._generator())
