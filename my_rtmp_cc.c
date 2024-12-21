// my_rtmp_cc.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// 10秒（ナノ秒）
#define DELAY_NS (10ULL * 1000000000ULL)

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);    // ソケットID
    __type(value, __u64); // 輻輳開始時刻(ns), 0なら非輻輳
} congestion_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, bool);  // in_congestionフラグ
} congestion_flag_map SEC(".maps");

// ソケットID取得
static __always_inline __u64 get_sock_id(const struct tcp_sock *tp) {
    return BPF_CORE_READ(tp, sk_common.sk_num);
}

// cong_ops: ssthresh計算
static __always_inline __u32 my_rtmp_cc_ssthresh(struct tcp_sock *tp) {
    __u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);
    return cwnd / 2 < 2 ? 2 : cwnd / 2;
}

// cong_ops: cong_avoidでウィンドウ調整を実施
static __always_inline void my_rtmp_cc_cong_avoid(struct tcp_sock *tp, __u32 ack, __u32 acked) {
    __u64 sid = get_sock_id(tp);

    // 輻輳開始時刻
    __u64 *start_time = bpf_map_lookup_elem(&congestion_start_map, &sid);
    bool *in_cong = bpf_map_lookup_elem(&congestion_flag_map, &sid);

    __u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);
    __u32 lost_out = BPF_CORE_READ(tp, lost_out);

    if (!in_cong || !start_time) {
        // 初期状態
        cwnd++;
        BPF_CORE_WRITE(tp, snd_cwnd, cwnd);
        return;
    }

    __u64 now = bpf_ktime_get_ns();

    if (lost_out > 0) {  // パケットロスが発生した場合、輻輳状態とみなす
        *in_cong = true;
        if (*start_time == 0) {
            *start_time = now;
        }
    } else {
        *in_cong = false;
        *start_time = 0;
    }

    if (*in_cong) {
        if (now - *start_time >= DELAY_NS) {
            // 10秒経過しても輻輳継続: cwnd半減
            __u32 new_cwnd = cwnd / 2;
            if (new_cwnd < 1) {
                new_cwnd = 1;
            }
            BPF_CORE_WRITE(tp, snd_cwnd, new_cwnd);
        }
    } else {
        // 輻輳解消: 徐々にcwnd増加
        cwnd++;
        BPF_CORE_WRITE(tp, snd_cwnd, cwnd);
    }
}

// cong_ops: undo_cwnd
static __always_inline __u32 my_rtmp_cc_undo_cwnd(struct tcp_sock *tp) {
    __u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);
    return cwnd < 10 ? 10 : cwnd;
}

// init, release
static int my_rtmp_cc_init(struct sock *sk) {
    __u64 sid = BPF_CORE_READ(sk, sk_num);
    __u64 zero = 0;
    bool false_val = false;
    bpf_map_update_elem(&congestion_start_map, &sid, &zero, BPF_ANY);
    bpf_map_update_elem(&congestion_flag_map, &sid, &false_val, BPF_ANY);
    return 0;
}

static void my_rtmp_cc_release(struct sock *sk) {
    __u64 sid = BPF_CORE_READ(sk, sk_num);
    bpf_map_delete_elem(&congestion_start_map, &sid);
    bpf_map_delete_elem(&congestion_flag_map, &sid);
}

// BPF struct_opsを用いてtcp_congestion_opsを登録
struct bpf_tcp_congestion_ops {
    int (*init)(struct sock *sk);
    void (*release)(struct sock *sk);
    void (*cong_avoid)(struct tcp_sock *tp, __u32 ack, __u32 acked);
    __u32 (*ssthresh)(struct tcp_sock *tp);
    __u32 (*undo_cwnd)(struct tcp_sock *tp);
} my_rtmp_cc_ops SEC(".struct_ops.my_rtmp_cc") = {
    .init = (void *)my_rtmp_cc_init,
    .release = (void *)my_rtmp_cc_release,
    .cong_avoid = (void *)my_rtmp_cc_cong_avoid,
    .ssthresh = (void *)my_rtmp_cc_ssthresh,
    .undo_cwnd = (void *)my_rtmp_cc_undo_cwnd,
};