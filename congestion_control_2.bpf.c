// rtmp_sockops.c
// コンパイル例: clang -O2 -g -target bpf -c rtmp_sockops.c -o rtmp_sockops.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 独自CCの名前 (カーネル側でtcp_congestion_opsとして登録済み想定)
#define MY_RTMP_CC "my_rtmp_cc"
// 通常のCC（例: cubic）
#define DEFAULT_CC "cubic"

// RTMPと判断するためのポート
#define RTMP_PORT 1935

// RTTが(適当な閾値)以上になったら輻輳とみなす(サンプル用)
#define RTT_THRESHOLD 100000  // 単位usec=0.1sなど、値は適宜

#ifndef TCP_CONGESTION
#define TCP_CONGESTION 13
#endif

// OBSプラグインへの通知を行うためのマップ
// key=0固定, valueに通知状態 (0=正常, 1=輻輳検知等)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} notification_map SEC(".maps");

// ソケット毎にRTTなどを記録しておくマップ
// key: bpf_sock_ops->sid (socket id), value: RTT情報や輻輳検知状態
struct rtmp_cc_info {
    __u64 last_congestion_time;  // 輻輳検知開始時刻(ns)
    bool in_congestion;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct rtmp_cc_info);
} rtmp_cc_map SEC(".maps");

char _license[] SEC("license") = "GPL";

/*
 * sockopsプログラム:
 * 1) コネクション確立時に、ポートを見てRTMPなら独自CCをセット、それ以外は通常CCをセット
 * 2) RTT更新時 (BPF_SOCK_OPS_RTT_CB) に輻輳状態を簡易チェック → OBS通知
 */
SEC("sockops")
int rtmp_sockops(struct bpf_sock_ops *skops)
{
    __u32 op = (__u32) skops->op;
    // ソケットIDを一意のキーとして使う
    __u64 sid = bpf_get_socket_cookie(skops);

    // 1) コネクション確立時に輻輳制御切り替え (RTMP or not)
    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
        op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        // ポート判定 (RTMP_PORT=1935 なら独自CC)
        // 送信元ポート(local_port) or 送信先ポート(remote_port) が1935ならRTMP通信とみなす
        __u16 lport = bpf_ntohs(skops->local_port);
        __u16 rport = skops->remote_port;
        __u32 daddr = skops->remote_ip4;
        __u16 daddr2 = bpf_ntohs(skops->remote_ip4);


        // RTMP判定
        bool is_rtmp = (lport == RTMP_PORT || rport == RTMP_PORT);

        bpf_printk("sid=%llu, lport=%u, rport=%u, is_rtmp=%d, daddr=%u, daddr2=%u\n",
                   sid, lport, rport, is_rtmp, daddr, daddr2);
        if (is_rtmp) {
            bpf_printk("set rtmp cc");
            const char rtmp_cc[] = MY_RTMP_CC;
            bpf_setsockopt(skops, IPPROTO_TCP,TCP_CONGESTION,
                           rtmp_cc, sizeof(rtmp_cc));

            // rtmp_cc_mapに初期エントリ追加
            struct rtmp_cc_info info = {0};
            info.last_congestion_time = 0;
            info.in_congestion = false;
            bpf_map_update_elem(&rtmp_cc_map, &sid, &info, BPF_ANY);
        } else {
            // 通常CC(例: cubic)
            bpf_printk("set normal cc");
            const char default_cc[] = DEFAULT_CC;
            bpf_setsockopt(skops, IPPROTO_TCP,TCP_CONGESTION,
                           default_cc, sizeof(default_cc));
        }
        return 0;
    }

    // 2) RTT更新イベント (BPF_SOCK_OPS_RTT_CB) で輻輳検知
    if (op == BPF_SOCK_OPS_RTT_CB) {
        // rtmp_cc_mapにある = このソケットはRTMPで独自CC中
        struct rtmp_cc_info *info = bpf_map_lookup_elem(&rtmp_cc_map, &sid);
        if (!info)
            return 0;  // RTMPでなければ何もしない

        // 現在のRTT (usec単位)
        __u32 srtt = skops->srtt_us >> 3; // srtt_usは<<3倍された値が入る
        // しきい値超なら輻輳とみなす
        bool congested = (srtt >= RTT_THRESHOLD);

        if (congested && !info->in_congestion) {
            // 新たに輻輳検知
            info->in_congestion = true;
            info->last_congestion_time = bpf_ktime_get_ns();

            // OBS通知mapをセット
            __u32 map_key = 0;
            __u32 *noti_val = bpf_map_lookup_elem(&notification_map, &map_key);
            if (noti_val) {
                // 1をセット(例)
                __u32 v = 1;
                bpf_map_update_elem(&notification_map, &map_key, &v, BPF_ANY);
            }
        } else if (!congested && info->in_congestion) {
            // 輻輳解消
            info->in_congestion = false;
            info->last_congestion_time = 0;

            // OBS通知mapをリセット
            __u32 map_key = 0;
            __u32 v = 0;
            bpf_map_update_elem(&notification_map, &map_key, &v, BPF_ANY);
        }

        return 0;
    }

    // コネクション終了処理 (不必要なら削除OK)
    if (op == BPF_SOCK_OPS_STATE_CB) {
        // BPF_SOCK_OPS_STATE_CB: TCP state変化時
        // TCP_CLOSE等でソケット破棄ならrtmp_cc_mapエントリも削除
        // skops->args[1] に新しいTCP stateが入る (e.g. TCP_CLOSE=7)
        __u32 new_state = skops->args[1];
        if (new_state == TCP_CLOSE) {
            bpf_map_delete_elem(&rtmp_cc_map, &sid);
        }
    }

    return 0;
}
