// my_rtmp_cc.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

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
    __u16 sport = bpf_ntohs(BPF_CORE_READ(tp, inet_conn.icsk_inet.inet_sport));
    return (__u64)sport;
}

// cong_ops: ssthresh計算
SEC(".struct_ops/my_rtmp_cc_ssthresh")
__u32 my_rtmp_cc_ssthresh(struct tcp_sock *tp) {
    __u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);
    return cwnd / 2 < 2 ? 2 : cwnd / 2;
}

// cong_ops: cong_avoidでウィンドウ調整を実施
SEC(".struct_ops.my_rtmp_cc_cong_avoid")
void my_rtmp_cc_cong_avoid(struct tcp_sock *tp, __u32 ack, __u32 acked) {
    __u64 sid = get_sock_id(tp);

    // 輻輳開始時刻
    __u64 *start_time = bpf_map_lookup_elem(&congestion_start_map, &sid);
    bool *in_cong = bpf_map_lookup_elem(&congestion_flag_map, &sid);

    __u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);
    __u32 lost_out = BPF_CORE_READ(tp, lost_out);

    if (!in_cong || !start_time) {
        // 初期状態
        cwnd++;
        tp->snd_cwnd = cwnd;
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
            tp->snd_cwnd = new_cwnd;
        }
    } else {
        // 輻輳解消: 徐々にcwnd増加
        cwnd++;
        tp->snd_cwnd = cwnd;
    }
}

// cong_ops: undo_cwnd
SEC(".struct_ops.my_rtmp_cc_undo_cwnd")
__u32 my_rtmp_cc_undo_cwnd(struct tcp_sock *tp) {
    __u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);
    return cwnd < 10 ? 10 : cwnd;
}

// init, release
SEC(".struct_ops.my_rtmp_cc_init")
int my_rtmp_cc_init(struct sock *sk) {
    __u16 num = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u64 sid = (__u64)num;
    __u64 zero = 0;
    bool false_val = false;
    bpf_map_update_elem(&congestion_start_map, &sid, &zero, BPF_ANY);
    bpf_map_update_elem(&congestion_flag_map, &sid, &false_val, BPF_ANY);
    return 0;
}

SEC(".struct_ops.my_rtmp_cc_release")
void my_rtmp_cc_release(struct sock *sk) {
    __u16 num = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u64 sid = (__u64)num;
    bpf_map_delete_elem(&congestion_start_map, &sid);
    bpf_map_delete_elem(&congestion_flag_map, &sid);
}

SEC(".struct_ops") 
struct tcp_congestion_ops my_rtmp_cc_ops = {
    .init = (void *)my_rtmp_cc_init,
    .cong_avoid = (void *)my_rtmp_cc_cong_avoid,
    .ssthresh = (void *)my_rtmp_cc_ssthresh,
    .undo_cwnd = (void *)my_rtmp_cc_undo_cwnd,
    .name       = "my_rtmp_cc",
};