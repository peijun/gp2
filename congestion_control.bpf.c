// vmlinux.hをインクルード
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1
#define TC_ACT_PIPE 3
#define TC_ACT_RECLASSIFY 1

// 10秒（ナノ秒換算）
#define DELAY_NS (10ULL * 1000000000ULL)

// 輻輳情報を格納する構造体
struct congestion_info {
    __u64 last_timestamp;
    __u32 packet_count;
    __u32 retransmit_count;
    __u64 congestion_start_time; 
};

// 輻輳情報を保存するためのBPFマップ
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct congestion_info);
} congestion_map SEC(".maps");

// OBSプラグインへの通知状態を管理するためのBPFマップ
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} notification_map SEC(".maps");

// window_size_map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} window_size_map SEC(".maps");

// RTMPパケットカウント用マップ
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} rtmp_packet_count_map SEC(".maps");

// RTMP以外のパケット情報を記録するためのキー
struct ip_port_key {
    __u32 saddr;
    __u32 daddr;
    __u16 source;
    __u16 dest;
};

// RTMP以外の通信を記録するマップ(key: ip_port_key, value: 受信パケット数)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ip_port_key);
    __type(value, __u64);
} non_rtmp_map SEC(".maps");

// 定数の定義
#define CONGESTION_THRESHOLD 10
#define PACKET_INTERVAL_THRESHOLD 100000
#define RETRANSMIT_THRESHOLD 3
#define RTMP_PORT 1935

SEC("tc")
int congestion_control(struct __sk_buff *skb)
{
    // パケットへのポインタ
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

    // RTMP通信（srcやdestのいずれかが1935）でない場合はnon_rtmp_mapに記録し、ログ出力
    if (tcp->source != bpf_htons(RTMP_PORT) && tcp->dest != bpf_htons(RTMP_PORT)) {
        struct ip_port_key non_rtmp_key = {
            .saddr = ip->saddr,
            .daddr = ip->daddr,
            .source = tcp->source,
            .dest = tcp->dest,
        };

        __u64 *val = bpf_map_lookup_elem(&non_rtmp_map, &non_rtmp_key);
        if (val) {
            (*val)++;
        } else {
            __u64 init_val = 1;
            bpf_map_update_elem(&non_rtmp_map, &non_rtmp_key, &init_val, BPF_ANY);
        }

        // ログ出力 (ip, portはネットワークバイトオーダーなのでbpf_ntohl, bpf_ntohsで変換)
        __u32 src_ip = bpf_ntohl(ip->saddr);
        __u32 dst_ip = bpf_ntohl(ip->daddr);
        __u16 src_port = bpf_ntohs(tcp->source);
        __u16 dst_port = bpf_ntohs(tcp->dest);

        bpf_printk("Non-RTMP packet: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
                   (src_ip >> 24) & 0xff, (src_ip >> 16) & 0xff,
                   (src_ip >> 8) & 0xff, src_ip & 0xff, src_port,
                   (dst_ip >> 24) & 0xff, (dst_ip >> 16) & 0xff,
                   (dst_ip >> 8) & 0xff, dst_ip & 0xff, dst_port);

        return TC_ACT_OK;
    }

    // RTMPパケットを検知したので、rtmp_packet_count_mapのカウンタをインクリメント
    {
        __u32 counter_key = 0;
        __u32 *counter = bpf_map_lookup_elem(&rtmp_packet_count_map, &counter_key);
        if (counter) {
            (*counter)++;
        } else {
            __u32 initial = 1;
            bpf_map_update_elem(&rtmp_packet_count_map, &counter_key, &initial, BPF_ANY);
        }
    }

    // ここからはRTMPトラフィックに対するカスタム輻輳制御処理
    __u32 key = ip->saddr;
    struct congestion_info *info = bpf_map_lookup_elem(&congestion_map, &key);
    if (!info) {
        struct congestion_info new_info = {0};
        bpf_map_update_elem(&congestion_map, &key, &new_info, BPF_ANY);
        info = bpf_map_lookup_elem(&congestion_map, &key);
        if (!info)
            return TC_ACT_OK;
    }

    __u64 current_time = bpf_ktime_get_ns();
    __u64 interval = current_time - info->last_timestamp;
    info->last_timestamp = current_time;

    bool is_retransmit = (tcp->syn || tcp->rst || tcp->fin);
    if (is_retransmit)
        info->retransmit_count++;
    else
        info->packet_count++;

    bool congestion_detected = false;
    if (interval < PACKET_INTERVAL_THRESHOLD || info->retransmit_count >= RETRANSMIT_THRESHOLD) {
        congestion_detected = true;
    }

    __u32 notification_key = 0;
    if (congestion_detected) {
        __u32 *notification_value = bpf_map_lookup_elem(&notification_map, &notification_key);
        if (notification_value) {
            (*notification_value)++;
            if (*notification_value > CONGESTION_THRESHOLD) {
                __u32 obs_notification = 1;
                bpf_map_update_elem(&notification_map, &notification_key, &obs_notification, BPF_ANY);
            }
        }

        if (info->congestion_start_time == 0) {
            info->congestion_start_time = current_time;
        }
    } else {
        info->congestion_start_time = 0;
        __u32 reset_value = 0;
        bpf_map_update_elem(&notification_map, &notification_key, &reset_value, BPF_ANY);
    }

    bool can_apply_congestion_control = false;
    if (info->congestion_start_time != 0 &&
        (current_time - info->congestion_start_time) >= DELAY_NS) {
        can_apply_congestion_control = true;
    }

    if (can_apply_congestion_control) {
        __u32 window_key = ip->saddr;
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

char LICENSE[] SEC("license") = "GPL";
