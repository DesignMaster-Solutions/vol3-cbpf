# vol3-cbpf: classic BPF decoding and evaluation, shared by linux.cbpf.SocketFilters and linux.cbpf.Seccomp.
# Pure Python, no Volatility import, so it can be tested on its own.
# Copyright 2026 Alan De Bortolo, Design Master Solutions LLC. Licensed under the Volatility Software License 1.0.

import hashlib
import struct
from typing import Dict, List, NamedTuple, Optional, Set, Tuple, Union

# Classes, sizes, modes, ops, sources (linux/bpf_common.h).
LD, LDX, ST, STX, ALU, JMP, RET, MISC = range(8)
W, H, B = 0x00, 0x08, 0x10
IMM, ABS, IND, MEM, LEN, MSH = 0x00, 0x20, 0x40, 0x60, 0x80, 0xA0
K, X, A = 0x00, 0x08, 0x10
JA, JEQ, JGT, JGE, JSET = 0x00, 0x10, 0x20, 0x30, 0x40
ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, NEG, MOD, XOR = (0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                                                        0x90, 0xA0)
TAX, TXA = 0x00, 0x80

SKF_AD_OFF = 0xFFFFF000  # -0x1000 as u32
SKF_AD_NAMES = {0: "proto", 4: "type", 8: "ifidx", 12: "nla", 16: "nlan", 20: "mark", 24: "queue", 28: "hatype",
                32: "rxhash", 36: "cpu", 40: "xor_x", 44: "vlan_tci", 48: "vlanp", 52: "poff", 56: "random",
                60: "vlan_tpid"}
SKF_AD_MAX = 64


class Insn(NamedTuple):
    code: int
    jt: int
    jf: int
    k: int


def parse(raw: bytes) -> List[Insn]:
    """struct sock_filter[] as stored by the kernel (little endian x86): u16 code, u8 jt, u8 jf, u32 k."""
    return [Insn(*struct.unpack_from("<HBBI", raw, i)) for i in range(0, len(raw) - len(raw) % 8, 8)]


def program_hash(insns: List[Insn]) -> str:
    return hashlib.sha256(b"".join(struct.pack("<HBBI", *i) for i in insns)).hexdigest()


def _s32(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def _abs_operand(k: int) -> str:
    if SKF_AD_OFF <= k < SKF_AD_OFF + SKF_AD_MAX and (k - SKF_AD_OFF) in SKF_AD_NAMES:
        return f"[{SKF_AD_NAMES[k - SKF_AD_OFF]}]"
    return f"[{_s32(k)}]"


def _ja(k: int, n: int) -> str:
    return f"{_s32((n + 1 + k) & 0xFFFFFFFF)}"


_HEX = lambda k, n: f"#0x{k:x}"  # noqa: E731
_DEC = lambda k, n: f"#{_s32(k)}"  # noqa: E731
_NONE = lambda k, n: ""  # noqa: E731
_X = lambda k, n: "x"  # noqa: E731
_MEMF = lambda k, n: f"M[{_s32(k)}]"  # noqa: E731
_INDF = lambda k, n: f"[x + {_s32(k)}]"  # noqa: E731
_ABSF = lambda k, n: _abs_operand(k)  # noqa: E731

# Exactly the cases of libpcap 1.10.4 bpf_image(): it switches on the whole 16-bit code, so anything else,
# including a valid-looking code with stray high bits, prints as "unimp".
_IMAGE = {
    RET | K: ("ret", _DEC), RET | A: ("ret", _NONE),
    LD | W | ABS: ("ld", _ABSF), LD | H | ABS: ("ldh", _ABSF), LD | B | ABS: ("ldb", _ABSF),
    LD | W | LEN: ("ld", lambda k, n: "#pktlen"),
    LD | W | IND: ("ld", _INDF), LD | H | IND: ("ldh", _INDF), LD | B | IND: ("ldb", _INDF),
    LD | IMM: ("ld", _HEX), LDX | IMM: ("ldx", _HEX),
    LDX | MSH | B: ("ldxb", lambda k, n: f"4*([{_s32(k)}]&0xf)"),
    LD | MEM: ("ld", _MEMF), LDX | MEM: ("ldx", _MEMF), ST: ("st", _MEMF), STX: ("stx", _MEMF),
    JMP | JA: ("ja", _ja),
    JMP | JGT | K: ("jgt", _HEX), JMP | JGE | K: ("jge", _HEX), JMP | JEQ | K: ("jeq", _HEX),
    JMP | JSET | K: ("jset", _HEX),
    JMP | JGT | X: ("jgt", _X), JMP | JGE | X: ("jge", _X), JMP | JEQ | X: ("jeq", _X), JMP | JSET | X: ("jset", _X),
    ALU | NEG: ("neg", _NONE), MISC | TAX: ("tax", _NONE), MISC | TXA: ("txa", _NONE),
}
for _op, _name in ((ADD, "add"), (SUB, "sub"), (MUL, "mul"), (DIV, "div"), (MOD, "mod"), (AND, "and"), (OR, "or"),
                   (XOR, "xor"), (LSH, "lsh"), (RSH, "rsh")):
    _IMAGE[ALU | _op | X] = (_name, _X)
    _IMAGE[ALU | _op | K] = (_name, _HEX if _op in (AND, OR, XOR) else _DEC)


def image(p: Insn, n: int) -> str:
    """One line in the exact format of libpcap's bpf_image() (what `tcpdump -d` prints)."""
    c = p.code
    op, fmt = _IMAGE.get(c, ("unimp", lambda k, n: f"0x{c:x}"))
    operand = fmt(p.k, n)
    if c & 0x07 == JMP and c & 0xF0 != JA:
        return f"({n:03d}) {op:<8} {operand:<16} jt {n + 1 + p.jt}\tjf {n + 1 + p.jf}"
    return f"({n:03d}) {op:<8} {operand}"


def disassemble(insns: List[Insn]) -> List[str]:
    return [image(p, n) for n, p in enumerate(insns)]


# ---- symbolic execution: concrete ints where the input is known, expressions where it is not ----

class Sym(NamedTuple):
    expr: str


Val = Union[int, Sym]


class Path(NamedTuple):
    ret: Val
    conds: Tuple[str, ...]


Loader = callable  # (offset: int, size: int) -> Val


def _alu(op: int, a: Val, b: Val) -> Val:
    if isinstance(a, int) and isinstance(b, int):
        if op in (DIV, MOD) and b == 0:
            return Sym("div-by-zero")
        r = {ADD: a + b, SUB: a - b, MUL: a * b, DIV: a // b if b else 0, MOD: a % b if b else 0, AND: a & b,
             OR: a | b, XOR: a ^ b, LSH: a << (b & 31), RSH: a >> (b & 31)}[op]
        return r & 0xFFFFFFFF
    sym = {ADD: "+", SUB: "-", MUL: "*", DIV: "/", MOD: "%", AND: "&", OR: "|", XOR: "^", LSH: "<<", RSH: ">>"}[op]
    fa = a.expr if isinstance(a, Sym) else f"0x{a:x}"
    fb = b.expr if isinstance(b, Sym) else f"0x{b:x}"
    return Sym(f"({fa} {sym} {fb})")


def _cond(op: int, a: Val, b: Val) -> Tuple[Optional[bool], str, str]:
    """(decided, text-if-true, text-if-false)."""
    if isinstance(a, int) and isinstance(b, int):
        return {JEQ: a == b, JGT: a > b, JGE: a >= b, JSET: bool(a & b)}[op], "", ""
    fa = a.expr if isinstance(a, Sym) else f"0x{a:x}"
    fb = b.expr if isinstance(b, Sym) else f"0x{b:x}"
    return {JEQ: (None, f"{fa} == {fb}", f"{fa} != {fb}"),
            JGT: (None, f"{fa} > {fb}", f"{fa} <= {fb}"),
            JGE: (None, f"{fa} >= {fb}", f"{fa} < {fb}"),
            JSET: (None, f"{fa} & {fb}", f"!({fa} & {fb})")}[op]


class TooManyPaths(Exception):
    pass


def explore(insns: List[Insn], load, length: Val = Sym("len"), max_paths: int = 512) -> List[Path]:
    """Every path from the first instruction to a return. `load(offset, size)` gives the input bytes."""
    out: List[Path] = []
    stack = [(0, 0, 0, (0,) * 16, (), {})]  # pc, A, X, M, conds, facts {expr: value it equals / set it is not}
    while stack:
        pc, a, x, m, conds, facts = stack.pop()
        while True:
            if pc >= len(insns):
                out.append(Path(Sym("fell-off-end"), conds))
                break
            p = insns[pc]
            c, k, cls = p.code, p.k, p.code & 0x07
            pc += 1
            if cls == RET:
                out.append(Path(a if c & 0x18 == A else k, conds))
                break
            if cls in (LD, LDX):
                mode, size = c & 0xE0, {W: 4, H: 2, B: 1}.get(c & 0x18, 4)
                if mode == IMM:
                    v = k
                elif mode == ABS:
                    v = load(k, size)
                elif mode == IND:
                    v = load(Sym(f"{x.expr}+{k}") if isinstance(x, Sym) else (x + k) & 0xFFFFFFFF, size)
                elif mode == MEM:
                    v = m[k & 15]
                elif mode == LEN:
                    v = length
                elif mode == MSH:
                    b = load(k, 1)
                    v = (b & 0xF) * 4 if isinstance(b, int) else Sym(f"4*({b.expr}&0xf)")
                else:
                    v = Sym(f"bad-mode-0x{c:x}")
                if cls == LD:
                    a = v
                else:
                    x = v
            elif cls in (ST, STX):
                m = m[:k & 15] + ((a if cls == ST else x),) + m[(k & 15) + 1:]
            elif cls == ALU:
                op = c & 0xF0
                a = (Sym(f"-{a.expr}") if isinstance(a, Sym) else (-a) & 0xFFFFFFFF) if op == NEG else \
                    _alu(op, a, x if c & X else k)
            elif cls == MISC:
                if c & 0xF8 == TXA:
                    a = x
                else:
                    x = a
            elif cls == JMP:
                op = c & 0xF0
                if op == JA:
                    pc += k
                    continue
                b = x if c & X else k
                decided, ct, cf = _cond(op, a, b)
                if decided is None and op == JEQ and isinstance(a, Sym) and isinstance(b, int):
                    known = facts.get(a.expr)
                    if isinstance(known, int):
                        decided = known == b
                    elif known and b in known:
                        decided = False  # this path already established a != b
                if decided is None:
                    if len(out) + len(stack) > max_paths:
                        raise TooManyPaths()
                    ffacts = facts
                    if op == JEQ and isinstance(a, Sym) and isinstance(b, int):
                        prev = facts.get(a.expr)
                        ffacts = {**facts, a.expr: (prev if isinstance(prev, frozenset) else frozenset()) | {b}}
                        facts = {**facts, a.expr: b}
                    stack.append((pc + p.jf, a, x, m, conds + (cf,), ffacts))
                    pc, conds = pc + p.jt, conds + (ct,)
                else:
                    pc += p.jt if decided else p.jf
    return out


# ---- socket filters ----

# Names for byte offsets when the filter sees an Ethernet frame (AF_PACKET SOCK_RAW, tcpdump on Ethernet/lo).
ETHER_FIELDS = {(12, 2): "ether.type", (23, 1): "ip.proto", (20, 2): "ip.frag", (26, 4): "ip.src", (30, 4): "ip.dst",
                (14, 1): "ip.vhl", (20, 1): "ip6.nxt", (22, 4): "ip6.src[0]", (38, 4): "ip6.dst[0]",
                (54, 2): "ip6.l4[0:2]", (56, 2): "ip6.l4[2:2]"}


def _ascii(v: int) -> str:
    b = v.to_bytes(4, "big").lstrip(b"\0")
    return f' "{b.decode()}"' if len(b) > 1 and all(0x20 <= ch < 0x7F for ch in b) else ""


def _annotate(cond: str) -> str:
    """Adds ASCII to magic constants and decimal to transport-layer fields (ports)."""
    if "== 0x" not in cond and "!= 0x" not in cond:
        return cond
    v = int(cond.rsplit("0x", 1)[1], 16)
    return cond + (f" ({v})" if cond.startswith(("l4[", "ip6.l4[")) and v < 0x10000 else "") + _ascii(v)


def socket_load(fields: Dict[Tuple[int, int], str]):
    def load(off, size):
        if isinstance(off, Sym):
            base, _, k = off.expr.rpartition("+")
            if fields and base == "4*(ip.vhl&0xf)" and k.isdigit():  # x = IPv4 header length (ldxb 4*([14]&0xf))
                return Sym(f"l4[{int(k) - 14}:{size}]")
            return Sym(f"pkt[{off.expr}:{size}]")
        if off >= SKF_AD_OFF:
            return Sym(SKF_AD_NAMES.get(off - SKF_AD_OFF, f"ad{off - SKF_AD_OFF}"))
        return Sym(fields.get((off, size), f"pkt[{off}:{size}]"))
    return load


def summarize_socket_filter(insns: List[Insn], ethernet: bool = True, max_paths: int = 6) -> str:
    """One line: the conditions under which the filter accepts (returns non-zero), with ASCII for magic values."""
    if not insns:
        return "empty program"
    try:
        paths = explore(insns, socket_load(ETHER_FIELDS if ethernet else {}))
    except TooManyPaths:
        return "too many paths to summarize; see the listing"
    accept = [p for p in paths if not (isinstance(p.ret, int) and p.ret == 0)]
    if not accept:
        return "drops every packet"
    if len(accept) == len(paths) and all(not p.conds for p in accept):
        return f"accepts every packet (snaplen {accept[0].ret if isinstance(accept[0].ret, int) else 'A'})"
    parts = []
    for p in accept[:max_paths]:
        eq = {c.split(" == ")[0] for c in p.conds if " == " in c}
        conds = [_annotate(c) for c in p.conds if not (" != " in c and c.split(" != ")[0] in eq)]
        parts.append("(" + " and ".join(conds) + ")" if conds else "(always)")
    more = f" or {len(accept) - max_paths} more" if len(accept) > max_paths else ""
    return "accept if " + " or ".join(parts) + more


# ---- seccomp ----

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_I386 = 0x40000003
X32_SYSCALL_BIT = 0x40000000
SECCOMP_DATA_LEN = 64
RET_ACTION_FULL = 0xFFFF0000
ACTIONS = {0x80000000: "KILL_PROCESS", 0x00000000: "KILL_THREAD", 0x00030000: "TRAP", 0x00050000: "ERRNO",
           0x7FC00000: "USER_NOTIF", 0x7FF00000: "TRACE", 0x7FFC0000: "LOG", 0x7FFF0000: "ALLOW"}
STRICT_ALLOWED = {0, 1, 60, 15}  # read, write, exit, rt_sigreturn (kernel mode1_syscalls, x86_64)


def action_name(ret: Val) -> str:
    if isinstance(ret, Sym):
        return f"UNKNOWN({ret.expr})"
    name = ACTIONS.get(ret & RET_ACTION_FULL)
    if name is None:
        return f"UNKNOWN(0x{ret:08x})"  # the kernel treats unknown actions as KILL_PROCESS
    return f"{name}({ret & 0xFFFF})" if name in ("ERRNO", "TRACE") else name


def _seccomp_load(nr: int, arch: int):
    def load(off, size):
        if isinstance(off, Sym) or size != 4:
            return Sym(f"data[{off}:{size}]")
        if off == 0:
            return nr
        if off == 4:
            return arch
        if off in (8, 12):
            return Sym("ip" + (".hi" if off == 12 else ""))
        if 16 <= off < 64 and off % 4 == 0:
            return Sym(f"args[{(off - 16) // 8}]" + (".hi" if off % 8 else ""))
        return Sym(f"data[{off}]")
    return load


def filter_outcomes(insns: List[Insn], nr: int, arch: int = AUDIT_ARCH_X86_64) -> Tuple[Set[Val], bool]:
    """Possible return values of one filter for a syscall; True if they depend on arguments/ip."""
    try:
        paths = explore(insns, _seccomp_load(nr, arch), length=SECCOMP_DATA_LEN, max_paths=256)
    except TooManyPaths:
        return {Sym("too-many-paths")}, True
    return {p.ret for p in paths}, any(p.conds for p in paths)


def _precedence(ret: Val) -> int:
    return -(1 << 31) if isinstance(ret, Sym) else _s32(ret & RET_ACTION_FULL)


def chain_outcomes(chain: List[List[Insn]], nr: int, arch: int = AUDIT_ARCH_X86_64) -> Tuple[Set[Val], bool]:
    """Combined result of a filter chain (newest first), as the kernel does: lowest action wins, ties go to
    the newest filter (kernel/seccomp.c seccomp_run_filters)."""
    results: Set[Val] = {ALLOW_RET}
    first, argdep = True, False
    for insns in chain:
        rets, dep = filter_outcomes(insns, nr, arch)
        argdep |= dep
        if first:
            results, first = set(rets), False
            continue
        results = {old if _precedence(old) <= _precedence(new) else new for old in results for new in rets}
    return results, argdep


ALLOW_RET = 0x7FFF0000


class Policy(NamedTuple):
    table: Dict[int, str]  # syscall nr -> action, "A|B" when it depends on arguments
    argdep: Tuple[int, ...]
    foreign_arch: str  # action for an i386 syscall
    x32: str  # actions for x32 ABI numbers (nr | 0x40000000)


def _fmt(rets: Set[Val], argdep: bool) -> str:
    names = sorted({action_name(r) for r in rets})
    return "|".join(names) + (" (depends on arguments)" if argdep and len(names) > 1 else "")


def evaluate_policy(chain: List[List[Insn]], syscalls: Dict[int, str]) -> Policy:
    table, argdep = {}, []
    for nr in sorted(syscalls):
        rets, dep = chain_outcomes(chain, nr)
        table[nr] = _fmt(rets, dep)
        if dep and len({action_name(r) for r in rets}) > 1:
            argdep.append(nr)
    foreign = _fmt(*chain_outcomes(chain, 0, AUDIT_ARCH_I386))
    x32 = sorted({_fmt(*chain_outcomes(chain, X32_SYSCALL_BIT | nr)) for nr in range(0, 548)})
    return Policy(table, tuple(argdep), foreign, "|".join(x32))


def strict_policy(syscalls: Dict[int, str]) -> Policy:
    return Policy({nr: "ALLOW" if nr in STRICT_ALLOWED else "KILL_THREAD" for nr in syscalls}, (), "KILL_THREAD",
                  "KILL_THREAD")


def summarize_policy(policy: Policy, syscalls: Dict[int, str], max_names: int = 12) -> str:
    """'default ERRNO(1); ALLOW 73: read,write,...; args: personality; i386 KILL_THREAD; x32 ...'."""
    groups: Dict[str, List[str]] = {}
    for nr, act in policy.table.items():
        groups.setdefault(act, []).append(syscalls[nr])
    default = max(groups, key=lambda a: len(groups[a]))
    parts = [f"default {default}"]
    for act in sorted(groups, key=lambda a: len(groups[a])):
        if act == default:
            continue
        names = groups[act]
        shown = ",".join(names[:max_names]) + (f",+{len(names) - max_names}" if len(names) > max_names else "")
        parts.append(f"{act} {len(names)}: {shown}")
    parts.append(f"i386 {policy.foreign_arch}")
    parts.append(f"x32 {policy.x32}")
    return "; ".join(parts)
