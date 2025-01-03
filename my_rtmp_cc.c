// my_rtmp_cc.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// 10秒（ナノ秒）
#define DELAY_NS (3ULL * 1000000000ULL)

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);    // ソケットID
    __type(value, __u64);  // 輻輳開始時刻(ns), 0なら非輻輳
} congestion_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, bool);   // in_congestionフラグ
} congestion_flag_map SEC(".maps");

// 追加: ウィンドウサイズ（ここでは snd_cwnd）を保持するためのマップ
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);   // ソケットID
    __type(value, __u32); // ウィンドウサイズ（snd_cwnd）
} window_size_map SEC(".maps");

// ソケットID取得
static __always_inline __u64 get_sock_id(const struct tcp_sock *tp) {
    __u16 sport = bpf_ntohs(BPF_CORE_READ(tp, inet_conn.icsk_inet.inet_sport));
    return (__u64)sport;
}

static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
    return (struct tcp_sock *)sk;
}

// cong_ops: ssthresh計算
SEC("struct_ops/my_rtmp_cc_ssthresh")
__u32 my_rtmp_cc_ssthresh(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    __u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);
    return cwnd / 2 < 2 ? 2 : cwnd / 2;
}

extern void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked) __ksym;

SEC("struct_ops")
void BPF_PROG(my_rtmp_cc_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    
    __u16 num = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u64 sid = (__u64)num;

    // 輻輳開始時刻
    __u64 *start_time = bpf_map_lookup_elem(&congestion_start_map, &sid);
    bool *in_cong = bpf_map_lookup_elem(&congestion_flag_map, &sid);

    if (!in_cong || !start_time) {
        // マップにエントリが存在しない場合は初期化するか、適切な処理を行う
        __u64 zero = 0;
        bool false_val = false;
        bpf_printk("Map lookup failed for sid: %llu", sid);
        bpf_map_update_elem(&congestion_start_map, &sid, &zero, BPF_ANY);
        bpf_map_update_elem(&congestion_flag_map, &sid, &false_val, BPF_ANY);
        return;
    }

    __u32 lost_out = BPF_CORE_READ(tp, lost_out);
    __u64 now = bpf_ktime_get_ns();

    if (lost_out > 0) {  // パケットロスが発生した場合、輻輳状態とみなす
        *in_cong = true;
        if (*start_time == 0) {
            *start_time = now;
            bpf_printk("Congestion detected, start_time set.");
        }
    } else {
        *in_cong = false;
        *start_time = 0;
    }

    __u32 cwnd_before = BPF_CORE_READ(tp, snd_cwnd);
    bpf_printk("Before adjusting cwnd: %u", cwnd_before);

    // 既存のロジック: 一定時間経過後に回避アルゴリズム呼び出し
    if (*in_cong) {
        if (now - *start_time >= DELAY_NS) {
            tcp_reno_cong_avoid(sk, ack, acked);
        } else {
            bpf_printk("Waiting for 3 seconds to adjust cwnd.");
            // 処理を終えてウィンドウサイズ確認へ（最後の更新処理に進む）
        }
    } else {
        tcp_reno_cong_avoid(sk, ack, acked);
    }

    // ---- ここからウィンドウサイズ変更検出の追加処理 ----
    // cong_avoid 実行後の cwnd を取得し、前回記録していた値と違えばログ出力＆更新
    __u32 cwnd_after = BPF_CORE_READ(tp, snd_cwnd);

    // sid をキーに window_size_map から前回のウィンドウサイズを取得
    __u32 *prev_cwnd_p = bpf_map_lookup_elem(&window_size_map, &sid);
    if (!prev_cwnd_p) {
        // エントリーがなければ作成する(初期化しただけの場合など)
        bpf_map_update_elem(&window_size_map, &sid, &cwnd_after, BPF_ANY);
    } else {
        if (*prev_cwnd_p != cwnd_after) {
            bpf_printk("Window size changed: %u -> %u", *prev_cwnd_p, cwnd_after);
            // 新しい cwnd を書き込み
            bpf_map_update_elem(&window_size_map, &sid, &cwnd_after, BPF_ANY);
        }
    }
    // ---- 追加処理 終了 ----
}

// cong_ops: undo_cwnd
SEC("struct_ops/my_rtmp_cc_undo_cwnd")
__u32 my_rtmp_cc_undo_cwnd(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    __u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);
    return cwnd < 10 ? 10 : cwnd;
}

// init, release
SEC("struct_ops/my_rtmp_cc_init")
void my_rtmp_cc_init(struct sock *sk) {
    __u16 num = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u64 sid = (__u64)num;
    __u64 zero = 0;
    bool false_val = false;
    
    // congestion_start_map, congestion_flag_map の初期化
    bpf_map_update_elem(&congestion_start_map, &sid, &zero, BPF_ANY);
    bpf_map_update_elem(&congestion_flag_map, &sid, &false_val, BPF_ANY);

    // 追加: window_size_map に初期ウィンドウサイズを登録（念のため）
    struct tcp_sock *tp = tcp_sk(sk);
    __u32 init_cwnd = BPF_CORE_READ(tp, snd_cwnd);
    bpf_map_update_elem(&window_size_map, &sid, &init_cwnd, BPF_ANY);

    bpf_printk("Socket initialized.");
}

SEC("struct_ops/my_rtmp_cc_release")
void my_rtmp_cc_release(struct sock *sk) {
    __u16 num = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u64 sid = (__u64)num;
    bpf_map_delete_elem(&congestion_start_map, &sid);
    bpf_map_delete_elem(&congestion_flag_map, &sid);
    bpf_map_delete_elem(&window_size_map, &sid);
}

SEC(".struct_ops") 
struct tcp_congestion_ops my_rtmp_cc_ops = {
    .init = (void *)my_rtmp_cc_init,
    .release = (void *)my_rtmp_cc_release,
    .ssthresh = (void *)my_rtmp_cc_ssthresh,
    .cong_avoid = (void *)my_rtmp_cc_cong_avoid,
    .undo_cwnd = (void *)my_rtmp_cc_undo_cwnd,
    .name       = "my_rtmp_cc",
};
