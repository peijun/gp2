#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 独自CCの名前 (カーネル側でtcp_congestion_opsとして登録済み想定)
#define MY_RTMP_CC "my_rtmp_cc"
// 通常のCC（例: cubic）
#define DEFAULT_CC "cubic"

// RTMPと判断するためのポート
#define RTMP_PORT 1935

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

// ソケット毎にRTTなどを記録しておくマップ(今回は輻輳状態だけを追跡)
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
 * 2) 再送イベント (BPF_SOCK_OPS_RETRANS_CB) を受け取ったら輻輳とみなしてOBS通知
 * 3) 次のRTT更新時 (BPF_SOCK_OPS_RTT_CB) に輻輳解除してOBS通知リセット(サンプル実装)
 */
SEC("sockops")
int rtmp_sockops(struct bpf_sock_ops *skops)
{
    __u32 op = (__u32)skops->op;
    // ソケットIDを一意のキーとして使う
    __u64 sid = bpf_get_socket_cookie(skops);

    // 1) コネクション確立時: 輻輳制御切り替え (RTMP or not)
    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
        op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        // 送信元ポート(local_port) or 送信先ポート(remote_port) が1935ならRTMP通信とみなす
        __u16 lport = bpf_ntohs(skops->local_port);
        __u32 raddr = bpf_ntohl(skops->remote_ip4);
        __u32 rport = bpf_ntohl(skops->remote_port);
        bpf_printk("Remote Port: %u\n", rport);


        // RTMP判定
        bool is_rtmp = (lport == RTMP_PORT || rport == RTMP_PORT);

        bpf_printk("sid=%llu, lport=%u, rport=%u, is_rtmp=%d\n",
                   sid, lport, rport, is_rtmp);
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

    // 2) 再送イベント (BPF_SOCK_OPS_RETRANS_CB) → 輻輳検知
    if (op == BPF_SOCK_OPS_RETRANS_CB) {
        // RTMPの場合のみ処理
        struct rtmp_cc_info *info = bpf_map_lookup_elem(&rtmp_cc_map, &sid);
        if (!info)
            return 0;  // RTMPでなければ何もしない

        // 今回は単純に「再送が発生したら輻輳」とみなす
        if (!info->in_congestion) {
            // 新しく輻輳に入った場合
            info->in_congestion = true;
            info->last_congestion_time = bpf_ktime_get_ns();

            // OBS通知mapをセット (例として1=輻輳状態を通知)
            __u32 map_key = 0;
            __u32 congest_val = 1;
            bpf_map_update_elem(&notification_map, &map_key, &congest_val, BPF_ANY);

            bpf_printk("sid=%llu: packet loss detected, set congestion\n", sid);
        }
        return 0;
    }

    // 3) RTT更新 (BPF_SOCK_OPS_RTT_CB) → 輻輳解除のサンプル（適当な例）
    if (op == BPF_SOCK_OPS_RTT_CB) {
        struct rtmp_cc_info *info = bpf_map_lookup_elem(&rtmp_cc_map, &sid);
        if (!info)
            return 0; // RTMPでなければ何もしない

        // ここでは「一度再送が起きたら次のRTT計測まで輻輳扱いとし、次のRTT計測が来たら解除」
        if (info->in_congestion) {
            // 輻輳解除
            info->in_congestion = false;
            info->last_congestion_time = 0;

            // OBS通知mapをリセット
            __u32 map_key = 0;
            __u32 normal_val = 0;
            bpf_map_update_elem(&notification_map, &map_key, &normal_val, BPF_ANY);

            bpf_printk("sid=%llu: congestion cleared\n", sid);
        }
        return 0;
    }

    // コネクション終了処理 (不必要なら削除可)
    if (op == BPF_SOCK_OPS_STATE_CB) {
        // TCP state変化時 (TCP_CLOSE等でソケット破棄なら rtmp_cc_map エントリも削除)
        __u32 new_state = skops->args[1];
        if (new_state == TCP_CLOSE) {
            bpf_map_delete_elem(&rtmp_cc_map, &sid);
        }
    }

    return 0;
}
