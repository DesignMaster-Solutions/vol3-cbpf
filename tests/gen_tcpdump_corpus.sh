#!/bin/sh
# Regenerates tests/data/tcpdump_corpus.txt with the real tcpdump of the sample guest (Alpine 3.20:
# tcpdump 4.99.4, libpcap 1.10.4). Each expression is compiled for an Ethernet link (lo), as -d and -dd.
# The expressions are chosen to reach every instruction class and addressing mode tcpdump can emit.
cd "$(dirname "$0")"
docker run --rm -i --platform linux/amd64 alpine:3.20 sh -c 'apk add -q --no-cache tcpdump >/dev/null
tcpdump --version 2>&1 | sed "s/^/# /"
while IFS= read -r e; do
  [ -z "$e" ] && continue
  echo "EXPR $e"
  tcpdump -i lo -d "$e" | sed "s/^/D /"
  tcpdump -i lo -dd "$e" | sed "s/^/DD /"
done' > data/tcpdump_corpus.txt <<'X'
udp and dst port 53
tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src net 10.0.0.0/8
greater 100
less 60
ip[0] & 0xf > 5
ip[2:2] - 20 > 10
ip[1] * 3 = 6
ip[1] / 2 = 4
ip[1] % 3 = 0
ip[1] | 1 = 5
ip[1] ^ 1 = 2
ip[1] << 2 = 8
ip[1] >> 1 = 2
ip[0] = -ip[1]
ip[0] = ip[1]
ip[0] > ip[1]
ip[0] & ip[1] != 0
ip[2:2] + ip[4:2] > 1000
ip6 and tcp port 443
vlan 100 and ip
inbound
ifindex 1
arp or rarp
icmp[icmptype] = icmp-echo
ether[0] & 1 = 1 or ip[16] >= 224
tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420
not ip
X
grep -c '^EXPR' data/tcpdump_corpus.txt
