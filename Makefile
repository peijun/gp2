TARGET = congestion_control

BPF_OBJ = ${TARGET}.bpf.o
USER_C = ${TARGET}.c
USER_SKEL = ${TARGET}.skel.h

LIBBPF_SRC = /home/peijun/libbpf/src
LIBBPF_OBJ = $(LIBBPF_SRC)/libbpf.a

CFLAGS = -g -O2 -Wall
LDFLAGS = -lelf -lz

all: $(TARGET)

$(TARGET): $(USER_C) $(USER_SKEL)
	$(CC) $(CFLAGS) -o $@ $< $(LIBBPF_OBJ) $(LDFLAGS)

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(BPF_OBJ): ${TARGET}.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(LIBBPF_SRC) -fno-gnu-unique -c $< -o $@

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(USER_SKEL)
