# Guest userland (x86_64), built with --platform linux/amd64 and exported as an initramfs.
FROM alpine:3.20 AS build
RUN apk add --no-cache build-base linux-headers libseccomp-dev libseccomp-static
COPY cbpf_demo.c /src/
RUN gcc -O1 -static -Wall -Wextra -o /src/cbpf_demo /src/cbpf_demo.c -lseccomp

FROM alpine:3.20
RUN apk add --no-cache tcpdump
COPY --from=build /src/cbpf_demo /usr/local/bin/cbpf_demo
# One name per role, so each process has its own comm in the task list.
RUN cd /usr/local/bin && for n in trigger udptrigger strict dockerish noexec pool; do ln -s cbpf_demo cbpf-$n; done
COPY init /init
