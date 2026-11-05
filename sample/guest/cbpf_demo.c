/*
 * Benign workload for the vol3-cbpf memory sample. Every mode installs one known classic BPF
 * program (socket filter or seccomp policy), prints it as ground truth on the console, and then
 * idles so the program is resident in kernel memory when the guest is dumped.
 *
 * Nothing here opens a network connection to the outside, runs a shell or hides itself: the
 * "trigger" filters only count the packets they accept.
 *
 *   cbpf_demo trigger      AF_PACKET raw socket, filter accepts UDP whose payload starts with "CBPF"
 *   cbpf_demo udptrigger   AF_INET UDP socket on 127.0.0.1:40000 with a payload-marker filter
 *   cbpf_demo send         sends marker and non-marker UDP datagrams to 127.0.0.1:40000
 *   cbpf_demo strict       seccomp strict mode (read/write/exit/sigreturn only)
 *   cbpf_demo dockerish    libseccomp allowlist shaped like Docker's default profile
 *   cbpf_demo noexec       no_new_privs + two stacked hand-written filters (execve, mount)
 *   cbpf_demo pool         forks 3 identical confined workers and 1 unconfined sibling
 */
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <seccomp.h>

#define MARKER 0x43425046u /* "CBPF" */
#define N(a) (sizeof(a) / sizeof((a)[0]))

static void die(const char *what) { perror(what); exit(1); }

/* Ground truth in the same layout as `tcpdump -dd`, prefixed so the test can find it. */
static void print_dd(const char *tag, const struct sock_filter *f, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("TRUTH %s dd { 0x%x, %d, %d, 0x%08x },\n", tag, f[i].code, f[i].jt, f[i].jf, f[i].k);
}

static void idle(void) { for (;;) pause(); }

static int attach(int fd, struct sock_filter *f, size_t n, const char *tag)
{
    struct sock_fprog prog = { .len = (unsigned short)n, .filter = f };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof prog) < 0) die("SO_ATTACH_FILTER");
    printf("TRUTH %s pid=%d fd=%d len=%zu\n", tag, getpid(), fd, n);
    print_dd(tag, f, n);
    fflush(stdout);
    return fd;
}

/* Ethernet + IPv4 + UDP, unfragmented, first 4 payload bytes == MARKER. */
static int mode_trigger(void)
{
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),             /* ethertype */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 8),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),             /* ip protocol */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 6),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 20),             /* flags + fragment offset */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x1fff, 4, 0),
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),            /* x = ip header length */
        BPF_STMT(BPF_LD | BPF_W | BPF_IND, 22),             /* 14 + 8: first payload word */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MARKER, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 0xffff),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) die("socket(AF_PACKET)");
    attach(fd, f, N(f), "trigger");
    unsigned char buf[2048];
    for (unsigned long count = 1;; count++) {
        if (recv(fd, buf, sizeof buf, 0) < 0) die("recv");
        printf("trigger: matched packet #%lu (counted only)\n", count);
        fflush(stdout);
    }
}

/* On a UDP socket the filter sees the datagram from the UDP header on: payload at offset 8. */
static int mode_udptrigger(void)
{
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 12, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 8),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MARKER, 0, 1),
        BPF_STMT(BPF_RET | BPF_A, 0),                       /* accept: return pkt word (nonzero) */
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) die("socket(AF_INET)");
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(40000) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
    attach(fd, f, N(f), "udptrigger");
    char buf[512];
    for (unsigned long count = 1;; count++) {
        if (recv(fd, buf, sizeof buf, 0) < 0) die("recv");
        printf("udptrigger: accepted datagram #%lu (counted only)\n", count);
        fflush(stdout);
    }
}

static int mode_send(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(40000) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const char *msgs[] = { "CBPF hello", "not a marker", "CBPF again" };
    for (size_t i = 0; i < N(msgs); i++)
        sendto(fd, msgs[i], strlen(msgs[i]), 0, (struct sockaddr *)&a, sizeof a);
    printf("send: %zu datagrams to 127.0.0.1:40000, 2 with the marker\n", N(msgs));
    return 0;
}

static void truth_policy(const char *tag, const char *dflt, const char *rules)
{
    printf("TRUTH seccomp %s pid=%d default=%s %s\n", tag, getpid(), dflt, rules);
    fflush(stdout);
}

static int mode_strict(void)
{
    int p[2];
    if (pipe(p) < 0) die("pipe");
    truth_policy("strict", "KILL", "mode=strict");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) < 0) die("strict");
    char c;
    for (;;) read(p[0], &c, 1); /* nobody writes: blocks forever */
}

static void load_libseccomp(scmp_filter_ctx ctx, const char *tag)
{
    printf("TRUTH seccomp %s pfc-begin\n", tag);
    fflush(stdout);
    seccomp_export_pfc(ctx, STDOUT_FILENO);
    printf("TRUTH seccomp %s pfc-end\n", tag);
    fflush(stdout);
    if (seccomp_load(ctx) < 0) die("seccomp_load");
    seccomp_release(ctx);
}

/* A shortened Docker-style allowlist: default errno(EPERM), personality allowed only for 4 args. */
static const char *dockerish_allow[] = {
    "accept", "accept4", "access", "alarm", "bind", "brk", "chdir", "chmod", "chown", "clock_gettime",
    "clock_nanosleep", "close", "connect", "dup", "dup2", "dup3", "epoll_create1", "epoll_ctl",
    "epoll_pwait", "epoll_wait", "execve", "exit", "exit_group", "fchmod", "fcntl", "fstat", "futex",
    "getcwd", "getdents64", "getegid", "geteuid", "getgid", "getpid", "getppid", "getrandom", "getuid",
    "ioctl", "listen", "lseek", "madvise", "mmap", "mprotect", "munmap", "nanosleep", "newfstatat",
    "openat", "pause", "pipe2", "poll", "pread64", "prlimit64", "read", "readlink", "recvfrom",
    "recvmsg", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sched_yield", "select", "sendmsg",
    "sendto", "set_robust_list", "set_tid_address", "setsockopt", "socket", "stat", "uname", "wait4",
    "write", "writev",
};

static int mode_dockerish(void)
{
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx) die("seccomp_init");
    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0); /* like Docker without no-new-privileges */
    char rules[4096] = "allow=";
    for (size_t i = 0; i < N(dockerish_allow); i++) {
        int nr = seccomp_syscall_resolve_name(dockerish_allow[i]);
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0) < 0) die(dockerish_allow[i]);
        strcat(rules, dockerish_allow[i]);
        strcat(rules, i + 1 < N(dockerish_allow) ? "," : "");
    }
    unsigned long pers[] = { 0x0, 0x8, 0x20000, 0xffffffff };
    for (size_t i = 0; i < N(pers); i++)
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(personality), 1, SCMP_A0(SCMP_CMP_EQ, pers[i]));
    strcat(rules, " argdep=personality");
    truth_policy("dockerish", "ERRNO(1)", rules);
    load_libseccomp(ctx, "dockerish");
    idle();
    return 0;
}

static void install(struct sock_filter *f, size_t n, const char *tag)
{
    struct sock_fprog prog = { .len = (unsigned short)n, .filter = f };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) die("SECCOMP_MODE_FILTER");
    print_dd(tag, f, n);
    fflush(stdout);
}

#define ARCH_CHECK(kill_at) \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, kill_at)

static int mode_noexec(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("no_new_privs");
    truth_policy("noexec", "ALLOW",
                 "nnp=1 filters=2 errno13=mount,umount2 errno1=execve,execveat badarch=KILL_PROCESS");
    struct sock_filter first[] = { /* installed first: mount, umount2 -> EACCES */
        ARCH_CHECK(4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mount, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_umount2, 2, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
    };
    struct sock_filter second[] = { /* installed second (runs first): execve, execveat -> EPERM */
        ARCH_CHECK(4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 2, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
    install(first, N(first), "noexec-1");
    install(second, N(second), "noexec-2");
    idle();
    return 0;
}

static const char *worker_allow[] = {
    "read", "write", "close", "exit", "exit_group", "rt_sigreturn", "rt_sigaction", "rt_sigprocmask",
    "pause", "nanosleep", "clock_nanosleep", "futex", "getpid", "brk", "mmap", "munmap",
};

static void worker(int idx, int confined)
{
    if (confined) {
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
        if (!ctx) die("seccomp_init");
        char rules[1024] = "allow=";
        for (size_t i = 0; i < N(worker_allow); i++) {
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name(worker_allow[i]), 0);
            strcat(rules, worker_allow[i]);
            strcat(rules, i + 1 < N(worker_allow) ? "," : "");
        }
        char tag[32];
        snprintf(tag, sizeof tag, "worker-%d", idx);
        truth_policy(tag, "KILL_PROCESS", rules);
        if (idx == 0) {
            load_libseccomp(ctx, tag);
        } else {
            if (seccomp_load(ctx) < 0) die("seccomp_load");
            seccomp_release(ctx);
        }
    } else {
        printf("TRUTH seccomp worker-%d pid=%d unconfined\n", idx, getpid());
        fflush(stdout);
    }
    idle();
}

static int mode_pool(void)
{
    for (int i = 0; i < 4; i++) {
        pid_t p = fork();
        if (p < 0) die("fork");
        if (p == 0) worker(i, i != 2); /* worker 2 is the sibling that skipped its policy */
        usleep(200000);
    }
    for (;;) wait(NULL);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *m = argc > 1 ? argv[1] : "";
    if (!strcmp(m, "trigger")) return mode_trigger();
    if (!strcmp(m, "udptrigger")) return mode_udptrigger();
    if (!strcmp(m, "send")) return mode_send();
    if (!strcmp(m, "strict")) return mode_strict();
    if (!strcmp(m, "dockerish")) return mode_dockerish();
    if (!strcmp(m, "noexec")) return mode_noexec();
    if (!strcmp(m, "pool")) return mode_pool();
    fprintf(stderr, "usage: %s trigger|udptrigger|send|strict|dockerish|noexec|pool\n", argv[0]);
    return 2;
}
