"""Runs the plugins on the real memory sample and checks every row against what the guest printed before the dump.
Skipped when the sample is not present (it is a 550 MB release asset; see sample/README.md)."""
import json
import os
import re
import subprocess

import pytest

from conftest import KVER, ROOT, serial_truth
import cbpf_lib as L
from cbpf_syscalls import X86_64

WORK = os.environ.get("CBPF_WORK", os.path.join(ROOT, "sample", "work"))
ELF = os.path.join(WORK, f"cbpf-{KVER}.elf")
VOL = os.path.join(ROOT, ".venv", "bin", "vol")
pytestmark = pytest.mark.skipif(not os.path.exists(ELF), reason="memory sample not built/downloaded")


def vol(plugin, *args):
    out = subprocess.run([VOL, "-q", "-r", "json", "-p", os.path.join(ROOT, "plugins"), "-s",
                          os.path.join(WORK, "isf"), "-f", ELF, plugin, *args],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out[out.index("["):])


@pytest.fixture(scope="module")
def truth():
    return serial_truth()


@pytest.fixture(scope="module")
def sockets():
    return vol("linux.cbpf.SocketFilters", "--dump")


@pytest.fixture(scope="module")
def seccomp():
    return vol("linux.cbpf.Seccomp", "--table")


def _pid(t, tag):
    return int(re.search(r"pid=(\d+)", " ".join(t[tag]["meta"])).group(1))


def test_every_filtered_socket_is_found_with_its_fd(truth, sockets):
    fds = {(int(m.group(1)), int(m.group(2))) for tag in truth if tag == "fd"
           for m in (re.search(r"pid=(\d+) fd=(\d+)", x) for x in truth[tag]["meta"])}
    assert {(r["PID"], r["FD"]) for r in sockets} == fds


@pytest.mark.parametrize("tag", ["tcpdump1", "tcpdump2", "trigger", "udptrigger"])
def test_program_bytes_and_listing_match_ground_truth(truth, sockets, tag):
    row = next(r for r in sockets if r["PID"] == _pid(truth, tag))
    want = truth[tag]["dd"]
    assert row["Kind"] == "cBPF" and row["Insns"] == len(want)
    assert row["SHA256"] == L.program_hash(want)
    listing = [c["Program"] for c in row["__children"]]
    assert listing == L.disassemble(want)
    if truth[tag]["d"]:  # tcpdump -d printed by the real tcpdump in the guest
        assert listing == truth[tag]["d"]


def test_socket_families(truth, sockets):
    by = {r["PID"]: (r["Family"], r["Type"]) for r in sockets}
    assert by[_pid(truth, "trigger")] == ("AF_PACKET", "RAW")
    assert by[_pid(truth, "udptrigger")] == ("AF_INET", "DGRAM")
    assert 'l4[8:4] == 0x43425046 "CBPF"' in next(r for r in sockets if r["PID"] == _pid(truth, "trigger"))["Program"]


def _status(truth):
    out = {}
    for x in truth["status"]["meta"]:
        m = re.search(r"pid=(\d+) comm=(\S+) NoNewPrivs: (\d) Seccomp: (\d) Seccomp_filters: (\d+)", x)
        out[int(m.group(1))] = (m.group(2), int(m.group(3)), int(m.group(4)), int(m.group(5)))
    return out


def test_mode_nnp_and_filter_count_match_proc_status(truth, seccomp):
    st = {pid: s for pid, s in _status(truth).items() if s[2] != 0}
    rows = {r["PID"]: r for r in seccomp if r["Mode"] != "disabled"}
    assert set(rows) == set(st)
    for pid, (_comm, nnp, mode, nfilters) in st.items():
        r = rows[pid]
        assert (r["Mode"], r["NoNewPrivs"], r["Filters"]) == ({1: "strict", 2: "filter"}[mode], bool(nnp), nfilters)


def _rules(truth, tag):
    meta = " ".join(truth["seccomp:" + tag]["meta"])
    allow = set(re.search(r"allow=(\S+)", meta).group(1).split(","))
    return re.search(r"default=(\S+)", meta).group(1), allow


def _nondefault(row):
    return {c["Summary"].split(" ")[0]: c["Summary"].split(": ", 1)[1] for c in row["__children"]}


@pytest.mark.parametrize("tag", ["dockerish", "worker-0", "worker-1", "worker-3"])
def test_libseccomp_policies_match_their_rules(truth, seccomp, tag):
    default, allow = _rules(truth, tag)
    row = next(r for r in seccomp if r["PID"] == _pid(truth, "seccomp:" + tag))
    assert row["Summary"].startswith(f"default {default};")
    want = {name: "ALLOW" for name in allow}
    if tag == "dockerish":
        want["personality"] = "ALLOW|ERRNO(1) (depends on arguments)"
    assert _nondefault(row) == want


def test_noexec_policy(truth, seccomp):
    row = next(r for r in seccomp if r["PID"] == _pid(truth, "seccomp:noexec"))
    assert _nondefault(row) == {"execve": "ERRNO(1)", "execveat": "ERRNO(1)", "mount": "ERRNO(13)",
                                "umount2": "ERRNO(13)"}
    assert "i386 KILL_PROCESS" in row["Summary"]
    assert row["Summary"].endswith("x32 ALLOW (kernel built without the x32 ABI)")  # both Debian cloud kernels


def test_strict(truth, seccomp):
    row = next(r for r in seccomp if r["PID"] == _pid(truth, "seccomp:strict"))
    assert row["Mode"] == "strict" and _nondefault(row) == {n: "ALLOW" for n in ("read", "write", "exit",
                                                                                   "rt_sigreturn")}


def test_unconfined_worker_is_flagged(truth, seccomp):
    odd = _pid(truth, "seccomp:worker-2")
    flagged = {r["PID"] for r in seccomp if r["Siblings"].startswith("DIFFERS")}
    assert flagged == {odd}
    workers = {_pid(truth, f"seccomp:worker-{i}") for i in (0, 1, 3)}
    assert len({r["Policy"] for r in seccomp if r["PID"] in workers}) == 1


def test_filter_chain_is_newest_first(truth):
    pid = _pid(truth, "seccomp:noexec")
    row = vol("linux.cbpf.Seccomp", "--pid", str(pid), "--dump")[0]
    filters = row["__children"]
    assert [f["Summary"].split(":")[0] for f in filters] == ["filter 0 (newest first)", "filter 1 (newest first)"]
    listings = [[c["Summary"] for c in f["__children"]] for f in filters]
    assert listings == [L.disassemble(truth["noexec-2"]["dd"]), L.disassemble(truth["noexec-1"]["dd"])]
