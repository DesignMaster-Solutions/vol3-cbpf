"""Concrete semantics of the evaluator: every ALU op, load mode and jump, on a known packet."""
import pytest

from conftest import serial_truth
import cbpf_lib as L
from cbpf_syscalls import X86_64

PKT = bytes(range(0x10, 0x50))  # 64 bytes: pkt[i] = 0x10 + i


def load(off, size):
    return int.from_bytes(PKT[off:off + size], "big") if isinstance(off, int) and off + size <= len(PKT) else L.Sym("oob")


def I(code, k=0, jt=0, jf=0):
    return L.Insn(code, jt, jf, k)


def run(prog):
    paths = L.explore(prog, load, length=64)
    assert len(paths) == 1 and paths[0].conds == ()
    return paths[0].ret


A7 = I(0x00, 7)  # ld #7
X3 = I(0x01, 3)  # ldx #3


@pytest.mark.parametrize("op,want", [(0x00, 10), (0x10, 4), (0x20, 21), (0x30, 2), (0x90, 1), (0x50, 3), (0x40, 7),
                                     (0xA0, 4), (0x60, 56), (0x70, 0)])
def test_alu_x_and_k(op, want):
    assert run([A7, X3, I(0x04 | op | 0x08), I(0x16)]) == want  # A op= X
    assert run([A7, I(0x04 | op, 3), I(0x16)]) == want  # A op= 3


def test_alu_wraps_and_neg():
    assert run([I(0x00, 0xFFFFFFFF), I(0x04, 2), I(0x16)]) == 1
    assert run([I(0x00, 1), I(0x14, 2), I(0x16)]) == 0xFFFFFFFF
    assert run([I(0x00, 1), I(0x64, 33), I(0x16)]) == 2  # shift count masked to 5 bits
    assert run([I(0x00, 1), I(0x84), I(0x16)]) == 0xFFFFFFFF
    assert run([I(0x00, 0x10000), I(0x24, 0x10000), I(0x16)]) == 0
    assert isinstance(run([A7, I(0x34, 0), I(0x16)]), L.Sym)  # division by zero is not a number


def test_loads():
    assert run([I(0x20, 4), I(0x16)]) == 0x14151617
    assert run([I(0x28, 4), I(0x16)]) == 0x1415
    assert run([I(0x30, 4), I(0x16)]) == 0x14
    assert run([I(0x80), I(0x16)]) == 64
    assert run([I(0x01, 2), I(0x40, 1), I(0x16)]) == 0x13141516
    assert run([I(0x01, 2), I(0x48, 1), I(0x16)]) == 0x1314
    assert run([I(0x01, 2), I(0x50, 1), I(0x16)]) == 0x13
    assert run([I(0xB1, 0), I(0x87), I(0x16)]) == 0  # 4*(0x10 & 0xf)
    assert run([I(0xB1, 1), I(0x87), I(0x16)]) == 4  # 4*(0x11 & 0xf)
    assert run([A7, I(0x02, 3), I(0x00, 0), I(0x60, 3), I(0x16)]) == 7  # st / ld M[]
    assert run([X3, I(0x03, 15), I(0x61, 15), I(0x87), I(0x16)]) == 3  # stx / ldx M[]
    assert run([A7, I(0x07), I(0x00, 0), I(0x87), I(0x16)]) == 7  # tax / txa
    assert run([I(0x06, 9)]) == 9


@pytest.mark.parametrize("code,k,taken", [(0x15, 7, True), (0x15, 8, False), (0x25, 6, True), (0x25, 7, False),
                                          (0x35, 7, True), (0x35, 8, False), (0x45, 4, True), (0x45, 8, False)])
def test_jumps(code, k, taken):
    assert run([A7, I(code, k, 1, 0), I(0x06, 0), I(0x06, 1)]) == (1 if taken else 0)
    assert run([A7, I(0x01, k), I(code | 0x08, 0, 1, 0), I(0x06, 0), I(0x06, 1)]) == (1 if taken else 0)


def test_ja_and_fall_off():
    assert run([I(0x05, 1), I(0x06, 0), I(0x06, 1)]) == 1
    assert run([A7]) == L.Sym("fell-off-end")


def test_symbolic_conditions_and_path_cap():
    prog = [I(0x20, 0), I(0x25, 5, 0, 1), I(0x06, 1), I(0x06, 0)]
    paths = L.explore(prog, lambda o, s: L.Sym(f"p{o}"))
    assert sorted(paths) == sorted([L.Path(1, ("p0 > 0x5",)), L.Path(0, ("p0 <= 0x5",))])
    chain = []
    for i in range(12):  # 2^12 paths
        chain += [I(0x20, 4 * i), I(0x45, 1, 0, 0)]
    with pytest.raises(L.TooManyPaths):
        L.explore(chain + [I(0x06, 1)], lambda o, s: L.Sym(f"p{o}"), max_paths=100)
    assert L.summarize_socket_filter(chain + [I(0x06, 1)]).startswith("too many paths")


@pytest.mark.parametrize("off,want", [(0, 59), (4, L.AUDIT_ARCH_X86_64), (8, L.Sym("ip")), (12, L.Sym("ip.hi")),
                                      (16, L.Sym("args[0]")), (20, L.Sym("args[0].hi")), (56, L.Sym("args[5]")),
                                      (60, L.Sym("args[5].hi")), (64, L.Sym("data[64]")), (2, L.Sym("data[2]"))])
def test_seccomp_data_layout(off, want):
    assert L._seccomp_load(59, L.AUDIT_ARCH_X86_64)(off, 4) == want


def test_seccomp_narrow_load_is_symbolic():
    assert L._seccomp_load(59, 0)(0, 2) == L.Sym("data[0:2]")


def test_policy_summary_text():
    t = serial_truth()
    p = L.evaluate_policy([t["noexec-2"]["dd"], t["noexec-1"]["dd"]], X86_64)
    assert L.summarize_policy(p, X86_64) == ("default ALLOW; ERRNO(1) 2: execve,execveat; ERRNO(13) 2: mount,umount2; "
                                             "i386 KILL_PROCESS; x32 ALLOW")
    s = L.summarize_policy(L.strict_policy(X86_64), X86_64, max_names=2)
    assert s == "default KILL_THREAD; ALLOW 4: read,write,+2; i386 KILL_THREAD; x32 KILL_THREAD"


def test_summary_annotations():
    assert L._annotate("l4[2:2] == 0x35") == "l4[2:2] == 0x35 (53)"
    assert L._annotate("ip6.l4[2:2] != 0x1bb") == "ip6.l4[2:2] != 0x1bb (443)"
    assert L._annotate("pkt[8:4] == 0x43425046") == 'pkt[8:4] == 0x43425046 "CBPF"'
    assert L._annotate("ip.proto == 0x41") == "ip.proto == 0x41"  # one printable byte is not a marker
    assert L._annotate("l4[0:4] == 0x10000") == "l4[0:4] == 0x10000"
    assert L._annotate("ip.frag & 0x1fff") == "ip.frag & 0x1fff"


SYM = lambda o, s: L.Sym(f"p{o}")  # noqa: E731


@pytest.mark.parametrize("op,txt", [(0x00, "+"), (0x10, "-"), (0x20, "*"), (0x30, "/"), (0x90, "%"), (0x50, "&"),
                                    (0x40, "|"), (0xA0, "^"), (0x60, "<<"), (0x70, ">>")])
def test_symbolic_alu_rendering(op, txt):
    assert L.explore([I(0x20, 4), I(0x04 | op, 3), I(0x16)], SYM)[0].ret == L.Sym(f"(p4 {txt} 0x3)")
    assert L.explore([I(0x01, 9), I(0x20, 4), I(0x0C | op), I(0x16)], SYM)[0].ret == L.Sym(f"(p4 {txt} 0x9)")
    assert L.explore([I(0x20, 4), I(0x07), I(0x00, 2), I(0x0C | op), I(0x16)], SYM)[0].ret == L.Sym(f"(0x2 {txt} p4)")
    assert L.explore([I(0x20, 4), I(0x84), I(0x16)], SYM)[0].ret == L.Sym("-p4")


def test_initial_state_and_scratch_neighbours():
    assert run([I(0x16)]) == 0  # A starts at 0
    assert run([I(0x87), I(0x16)]) == 0  # X starts at 0
    assert run([I(0x00, 5), I(0x02, 3), I(0x60, 4), I(0x16)]) == 0  # st M[3] leaves M[4] alone
    assert run([I(0x00, 5), I(0x02, 3), I(0x60, 2), I(0x16)]) == 0
    assert run([I(0x00, 5), I(0x02, 15), I(0x60, 15), I(0x16)]) == 5
    assert run([I(0x00, 5), I(0x02, 0), I(0x60, 1), I(0x16)]) == 0
    assert run([I(0x01, 2), I(0x40, 0xFFFFFFFE), I(0x16)]) == 0x10111213  # x + k wraps to offset 0


def test_known_inequality_prunes_equal_branch():
    # p0 != 1 on the false branch, then jeq p0 == 1 again must be impossible there
    prog = [I(0x20, 0), I(0x15, 1, 2, 0), I(0x15, 1, 0, 1), I(0x06, 7), I(0x06, 0)]
    rets = sorted(p.ret for p in L.explore(prog, SYM))
    assert rets == [0, 0]
    assert L.explore([I(0x20, 0), I(0x15, 1, 0, 1), I(0x15, 1, 0, 1), I(0x06, 7), I(0x06, 0)], SYM)[0].conds == (
        "p0 == 0x1",)


def test_ret_a_vs_k_and_word_size_default():
    assert run([I(0x00, 3), I(0x16, 9)]) == 3
    assert run([I(0x00, 3), I(0x06, 9)]) == 9
    assert run([I(0x38, 4), I(0x16)]) == 0x14151617  # size bits 0x18 = BPF_DW is not cBPF: treated as a word load


def test_parse_is_unsigned():
    assert L.parse(bytes.fromhex("ffff ff fe ffffffff")) == [I(0xFFFF, 0xFFFFFFFF, 0xFF, 0xFE)]
