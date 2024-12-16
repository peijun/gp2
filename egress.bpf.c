// egress_bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1
#define TC_ACT_PIPE 3
#define TC_ACT_RECLASSIFY 1

// 10秒（ナノ秒換算）
#define DELAY_NS (10ULL * 1000000000ULL)

struct congestion_info {
    __u64 last_timestamp;
    __u32 packet_count;
    __u32 retransmit_count;
    __u64 congestion_start_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct congestion_info);
} congestion_map SEC(".maps");

// notification_mapもあるがegressでは参照しない
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} notification_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} window_size_map SEC(".maps");

#define CONGESTION_THRESHOLD 10
#define PACKET_INTERVAL_THRESHOLD 1000000
#define RETRANSMIT_THRESHOLD 3
#define RTMP_PORT 1935

char LICENSE[] SEC("license") = "GPL";

// egress用: 10秒経過後のウィンドウサイズ調整のみ行う
SEC("tc")
int congestion_control_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // RTMPトラフィック以外は処理しない
    if (tcp->source != bpf_htons(RTMP_PORT) && tcp->dest != bpf_htons(RTMP_PORT))
        return TC_ACT_OK;

    __u32 key = ip->saddr;
    struct congestion_info *info = bpf_map_lookup_elem(&congestion_map, &key);
    if (!info)
        return TC_ACT_OK;

    __u64 current_time = bpf_ktime_get_ns();

    bool can_apply_congestion_control = false;
    if (info->congestion_start_time != 0 &&
        (current_time - info->congestion_start_time) >= DELAY_NS) {
        can_apply_congestion_control = true;
    }

    if (can_apply_congestion_control) {
        // intervalやretransmit_countはingressで計測済み。
        // ここではcongestion_start_timeが非0かつ10秒以上経過したらウィンドウ調整を実行。
        // 輻輳状態かどうかはcongestion_start_timeが非0で判断できる。
        // （より厳密な判定が必要なら、ingress側でフラグを別途保存するようにする）
        bool congestion_detected = (info->congestion_start_time != 0);

        __u32 window_key = key;
        __u32 *current_window_size = bpf_map_lookup_elem(&window_size_map, &window_key);
        if (current_window_size) {
            __u32 new_window_size;
            if (congestion_detected) {
                new_window_size = *current_window_size / 2;
                if (new_window_size < 1)
                    new_window_size = 1;
            } else {
                new_window_size = *current_window_size + 1;
            }
            bpf_map_update_elem(&window_size_map, &window_key, &new_window_size, BPF_ANY);
        } else {
            __u32 initial_window_size = 10;
            bpf_map_update_elem(&window_size_map, &window_key, &initial_window_size, BPF_ANY);
        }
    }

    return TC_ACT_OK;
}
