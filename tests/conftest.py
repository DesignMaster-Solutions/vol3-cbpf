import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "plugins", "linux"))

import cbpf_lib  # noqa: E402

KVER = os.environ.get("KVER", "6.1.0-54-cloud-amd64")
SERIAL = os.path.join(ROOT, "sample", "expected", f"serial-{KVER}.log")
DD = re.compile(r"\{ (0x[0-9a-f]+), (\d+), (\d+), (0x[0-9a-f]+) \}")


def parse_dd(lines):
    return [cbpf_lib.Insn(int(c, 16), int(t), int(f), int(k, 16)) for c, t, f, k in (DD.search(x).groups() for x in lines)]


def serial_truth():
    """{tag: {"d": [...], "dd": [insns], "meta": [...]}} from the TRUTH lines printed by the guest."""
    out = {}
    for line in open(SERIAL, encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        if not line.startswith("TRUTH "):
            continue
        _, tag, rest = line.split(" ", 2)
        if tag == "seccomp":
            tag, rest = rest.split(" ", 1)
            tag = "seccomp:" + tag
        t = out.setdefault(tag, {"d": [], "dd": [], "meta": []})
        if rest.startswith("d "):
            t["d"].append(rest[2:])
        elif rest.startswith("dd "):
            t["dd"].append(rest[3:])
        else:
            t["meta"].append(rest)
    for t in out.values():
        t["dd"] = parse_dd(t["dd"])
    return out
