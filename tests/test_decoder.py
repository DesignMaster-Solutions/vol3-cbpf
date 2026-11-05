"""The disassembler must print exactly what the real tcpdump -d prints for the same program."""
import os

import pytest

from conftest import ROOT, parse_dd, serial_truth
import cbpf_lib as L

CORPUS = os.path.join(ROOT, "tests", "data", "tcpdump_corpus.txt")


def corpus():
    cases, cur = [], None
    for line in open(CORPUS):
        line = line.rstrip("\n")
        if line.startswith("EXPR "):
            cur = (line[5:], [], [])
            cases.append(cur)
        elif line.startswith("D "):
            cur[1].append(line[2:])
        elif line.startswith("DD "):
            cur[2].append(line[3:])
    return cases


@pytest.mark.parametrize("expr,d,dd", corpus(), ids=[c[0] for c in corpus()])
def test_matches_real_tcpdump_corpus(expr, d, dd):
    assert L.disassemble(parse_dd(dd)) == d


def test_matches_tcpdump_in_guest():
    truth = serial_truth()
    for tag in ("tcpdump1", "tcpdump2"):
        assert truth[tag]["d"], tag
        assert L.disassemble(truth[tag]["dd"]) == truth[tag]["d"]


def I(code, k=0, jt=0, jf=0):
    return L.Insn(code, jt, jf, k)


# Instructions tcpdump never emits; expected text follows libpcap 1.10.4 bpf_image.c.
@pytest.mark.parametrize("insn,n,text", [
    (I(0x01, 7), 0, "(000) ldx      #0x7"),
    (I(0x03, 2), 1, "(001) stx      M[2]"),
    (I(0x87), 2, "(002) txa      "),
    (I(0x16), 3, "(003) ret      "),
    (I(0x06, 0xFFFFFFFF), 4, "(004) ret      #-1"),
    (I(0x3D, 0, 1, 2), 5, "(005) jge      x                jt 7\tjf 8"),
    (I(0x4D, 0, 0, 0), 6, "(006) jset     x                jt 7\tjf 7"),
    (I(0x05, 0xFFFFFFFE), 7, "(007) ja       6"),
    (I(0x1C), 0, "(000) sub      x"),
    (I(0x2C), 0, "(000) mul      x"),
    (I(0x3C), 0, "(000) div      x"),
    (I(0x9C), 0, "(000) mod      x"),
    (I(0x5C), 0, "(000) and      x"),
    (I(0x4C), 0, "(000) or       x"),
    (I(0xAC), 0, "(000) xor      x"),
    (I(0x6C), 0, "(000) lsh      x"),
    (I(0x7C), 0, "(000) rsh      x"),
    (I(0x0C), 0, "(000) add      x"),
    (I(0x04, 0xFFFFFFFF), 0, "(000) add      #-1"),
    (I(0x54, 0xFFFFFFFF), 0, "(000) and      #0xffffffff"),
    (I(0x44, 0x10), 0, "(000) or       #0x10"),
    (I(0x20, 0xFFFFF000), 0, "(000) ld       [proto]"),
    (I(0x28, 0xFFFFF004), 0, "(000) ldh      [type]"),
    (I(0x30, 0xFFFFF03C), 0, "(000) ldb      [vlan_tpid]"),
    (I(0x20, 0xFFFFF002), 0, "(000) ld       [-4094]"),
    (I(0x20, 0xFFFFF040), 0, "(000) ld       [-4032]"),
    (I(0x40, 0xFFFFFFFC), 0, "(000) ld       [x + -4]"),
    (I(0x60, 15), 0, "(000) ld       M[15]"),
    (I(0xFF), 9, "(009) unimp    0xff"),
    (I(0x25, 3, 255, 0), 10, "(010) jgt      #0x3             jt 266\tjf 11"),
])
def test_formats_not_in_corpus(insn, n, text):
    assert L.image(insn, n) == text


def test_parse_little_endian_and_hash():
    raw = bytes.fromhex("2800 00 00 0c000000" "0600 00 00 ffff0000")
    assert L.parse(raw) == [I(0x28, 12), I(0x06, 0xFFFF)]
    assert L.parse(raw + b"\x01\x02") == L.parse(raw)  # trailing partial instruction ignored
    assert L.program_hash(L.parse(raw)) == __import__("hashlib").sha256(raw).hexdigest()


# libpcap 1.10.4 bpf_image.c offsets[] (Linux SKF_AD_* ancillary loads), by byte offset from SKF_AD_OFF.
LIBPCAP_AD = {0: "proto", 4: "type", 8: "ifidx", 12: "nla", 16: "nlan", 20: "mark", 24: "queue", 28: "hatype",
              32: "rxhash", 36: "cpu", 40: "xor_x", 44: "vlan_tci", 48: "vlanp", 52: "poff", 56: "random",
              60: "vlan_tpid"}


@pytest.mark.parametrize("off", range(0, 64))
def test_ancillary_names(off):
    want = f"[{LIBPCAP_AD[off]}]" if off in LIBPCAP_AD else f"[{off - 4096}]"
    assert L.image(I(0x20, 0xFFFFF000 + off), 0) == f"(000) ld       {want}"
