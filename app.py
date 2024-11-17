from bcc import BPF

# eBPFプログラムをファイルから読み込む
with open('ebpf.c', 'r') as f:
    bpf_program = f.read()

# eBPFプログラムをコンパイルしてロード
b = BPF(text=bpf_program)

# TCフックにアタッチ（インターフェース名を適切に変更してください）
b.attach_xdp(dev="eth0", fn=b.load_func("congestion_control", BPF.XDP))

# プログラムを実行し続ける
try:
    print("eBPF program loaded and running. Press CTRL+C to exit.")
    while True:
        pass
except KeyboardInterrupt:
    pass

# クリーンアップ
b.remove_xdp("eth0")
