FROM docker/for-desktop-kernel:5.15.49-pr-865cda400dbf95b8b90be9bbfdceef3bcffe1e2c AS ksrc

FROM ubuntu:latest

WORKDIR /
COPY --from=ksrc /kernel-dev.tar /
RUN tar xf kernel-dev.tar && rm kernel-dev.tar

RUN apt update
RUN apt install -y curl wget lsb-release gnupg software-properties-common

RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /etc/apt/keyrings/llvm.gpg
RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/llvm.gpg] http://apt.llvm.org/jammy/ llvm-toolchain-jammy main" | tee /etc/apt/sources.list.d/llvm.list > /dev/nul
RUN apt update
RUN apt install -y bison build-essential cmake flex git libedit-dev libllvm-16-ocaml-dev llvm-dev libclang-dev python3-full zlib1g-dev libelf-dev libfl-dev
RUN apt install -y bpfcc-tools
RUN apt install -y kmod
COPY app.py /root
COPY ebpf.c /root
WORKDIR /root
CMD mount -t debugfs debugfs /sys/kernel/debug && /bin/bash
