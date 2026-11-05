"""Seccomp evaluation and socket-filter summaries, on the programs the guest printed and on small hand cases."""
from conftest import serial_truth
import cbpf_lib as L
from cbpf_syscalls import X86_64

NR = {v: k for k, v in X86_64.items()}
ALLOW, KILLP = 0x7FFF0000, 0x80000000


def I(code, k=0, jt=0, jf=0):
    return L.Insn(code, jt, jf, k)


def ret(k):
    return I(0x06, k)


def only(nr, hit, miss=ALLOW):  # if (nr == x) return hit; else return miss
    return [I(0x20, 0), I(0x15, nr, 0, 1), ret(hit), ret(miss)]


def test_noexec_chain_from_guest():
    t = serial_truth()
    chain = [t["noexec-2"]["dd"], t["noexec-1"]["dd"]]  # newest first
    p = L.evaluate_policy(chain, X86_64)
    want = {NR["execve"]: "ERRNO(1)", NR["execveat"]: "ERRNO(1)", NR["mount"]: "ERRNO(13)",
            NR["umount2"]: "ERRNO(13)"}
    assert {nr: a for nr, a in p.table.items() if a != "ALLOW"} == want
    assert p.foreign_arch == "KILL_PROCESS"
    assert p.x32 == "ALLOW"  # hand-written filters without the x32 bit check
    assert p.argdep == ()


def test_precedence_lowest_action_wins_ties_go_to_newest():
    nr = NR["read"]
    errno5, errno7 = 0x00050005, 0x00050007
    assert L.chain_outcomes([only(nr, errno5), only(nr, errno7)], nr)[0] == {errno5}
    assert L.chain_outcomes([only(nr, errno7), only(nr, errno5)], nr)[0] == {errno7}
    assert L.chain_outcomes([only(nr, 0x7FFC0000), only(nr, KILLP)], nr)[0] == {KILLP}
    assert L.chain_outcomes([only(nr, ALLOW), only(nr, 0x00030000)], nr)[0] == {0x00030000}
    assert L.chain_outcomes([only(nr, 0x7FFC0000), only(nr, ALLOW)], nr)[0] == {0x7FFC0000}
    assert L.chain_outcomes([only(nr, 0x7FC00000), only(nr, 0x7FF00000)], nr)[0] == {0x7FC00000}
    assert L.chain_outcomes([only(nr, 0x00000000), only(nr, 0x00030000)], nr)[0] == {0x00000000}


def test_argument_dependence():
    # if (nr == personality) { if (args[0] == 8) allow; else errno(1) } else allow
    prog = [I(0x20, 0), I(0x15, NR["personality"], 0, 3), I(0x20, 16), I(0x15, 8, 1, 0), ret(0x00050001), ret(ALLOW)]
    rets, dep = L.filter_outcomes(prog, NR["personality"])
    assert rets == {ALLOW, 0x00050001} and dep
    rets, dep = L.filter_outcomes(prog, NR["read"])
    assert rets == {ALLOW} and not dep
    p = L.evaluate_policy([prog], X86_64)
    assert p.argdep == (NR["personality"],)
    assert p.table[NR["personality"]] == "ALLOW|ERRNO(1) (depends on arguments)"


def test_action_names():
    assert [L.action_name(v) for v in (KILLP, 0, 0x30000, 0x50001, 0x7FC00000, 0x7FF00002, 0x7FFC0000, ALLOW)] == [
        "KILL_PROCESS", "KILL_THREAD", "TRAP", "ERRNO(1)", "USER_NOTIF", "TRACE(2)", "LOG", "ALLOW"]
    assert L.action_name(0x12340000) == "UNKNOWN(0x12340000)"


def test_strict():
    p = L.strict_policy(X86_64)
    assert {X86_64[n] for n, a in p.table.items() if a == "ALLOW"} == {"read", "write", "exit", "rt_sigreturn"}


def test_alu_ld_mem_and_len_in_seccomp():
    # A = nr; M[0] = A; A = len; A -= 64; jeq 0 -> X = M[0]; A = X; A &= 0xff; jeq 59 -> errno(1)
    prog = [I(0x20, 0), I(0x02, 0), I(0x80), I(0x14, 64), I(0x15, 0, 0, 5), I(0x61, 0), I(0x87), I(0x54, 0xFF),
            I(0x15, 59, 0, 1), ret(0x00050001), ret(ALLOW)]
    assert L.filter_outcomes(prog, 59)[0] == {0x00050001}
    assert L.filter_outcomes(prog, 59 + 256)[0] == {0x00050001}
    assert L.filter_outcomes(prog, 60)[0] == {ALLOW}


def test_trigger_summaries_from_guest():
    t = serial_truth()
    s = L.summarize_socket_filter(t["trigger"]["dd"], ethernet=True)
    assert s == ('accept if (ether.type == 0x800 and ip.proto == 0x11 and !(ip.frag & 0x1fff) and '
                 'l4[8:4] == 0x43425046 "CBPF")')
    assert L.summarize_socket_filter(t["udptrigger"]["dd"], ethernet=False) == \
        'accept if (len >= 0xc and pkt[8:4] == 0x43425046 "CBPF")'


def test_infeasible_paths_are_pruned():
    t = serial_truth()
    s = L.summarize_socket_filter(t["tcpdump1"]["dd"])
    assert s.endswith("or (ether.type == 0x86dd and ip6.nxt == 0x11 and ip6.l4[2:2] == 0x35 (53))")
    # ldh [12]; jeq 0x800 -> ldh [12]; jeq 0x86dd (impossible now) -> accept
    prog = [I(0x28, 12), I(0x15, 0x800, 0, 3), I(0x28, 12), I(0x15, 0x86DD, 0, 1), ret(1), ret(0)]
    assert L.summarize_socket_filter(prog) == "drops every packet"


def test_simple_summaries():
    assert L.summarize_socket_filter([ret(0)]) == "drops every packet"
    assert L.summarize_socket_filter([ret(0xFFFF)]) == "accepts every packet (snaplen 65535)"
    assert L.summarize_socket_filter([]) == "empty program"
