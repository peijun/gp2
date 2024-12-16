// vmlinux.hをインクルード
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

// 輻輳情報を格納する構造体
struct congestion_info {
    __u64 last_timestamp;
    __u32 packet_count;
    __u32 retransmit_count;
    __u64 congestion_start_time; // 輻輳検出開始時刻を記録するフィールドを追加
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

// 定数の定義
#define CONGESTION_THRESHOLD 10
#define PACKET_INTERVAL_THRESHOLD 1000000
#define RETRANSMIT_THRESHOLD 3
#define RTMP_PORT 1935

// TCフック用のeBPF関数
SEC("tc")
int congestion_control(struct __sk_buff *skb)
{
    // パケットデータへのポインタを取得
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    // イーサネットヘッダーの境界チェック
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // IPヘッダーの取得と境界チェック
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // TCPパケットのみを処理
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // TCPヘッダーの取得と境界チェック
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // RTMP通信以外は通常のCC(=何もしない)
    if (tcp->source != bpf_htons(RTMP_PORT) && tcp->dest != bpf_htons(RTMP_PORT))
        return TC_ACT_OK;

    // ここからはRTMPトラフィックに対するカスタム輻輳制御処理
    __u32 key = ip->saddr;
    // 輻輳情報マップからデータを取得または初期化
    struct congestion_info *info = bpf_map_lookup_elem(&congestion_map, &key);
    if (!info) {
        struct congestion_info new_info = {0};
        bpf_map_update_elem(&congestion_map, &key, &new_info, BPF_ANY);
        info = bpf_map_lookup_elem(&congestion_map, &key);
        if (!info)
            return TC_ACT_OK;
    }

    // 現在の時刻を取得し、パケット間隔を計算
    __u64 current_time = bpf_ktime_get_ns();
    __u64 interval = current_time - info->last_timestamp;
    info->last_timestamp = current_time;

    // 再送パケットかどうかを判断
    bool is_retransmit = (tcp->syn || tcp->rst || tcp->fin);
    if (is_retransmit)
        info->retransmit_count++;
    else
        info->packet_count++;

    // 輻輳検出ロジック
    bool congestion_detected = false;
    if (interval < PACKET_INTERVAL_THRESHOLD || info->retransmit_count >= RETRANSMIT_THRESHOLD) {
        congestion_detected = true;
    }

    // 輻輳検出した場合は即座にnotification_mapを更新
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

        // 輻輳開始時刻が未記録またはリセットされている場合は記録
        if (info->congestion_start_time == 0) {
            info->congestion_start_time = current_time;
        }
    } else {
        // 輻輳が解消されたら開始時刻をリセット
        info->congestion_start_time = 0;

        // notification_mapをリセット
        __u32 reset_value = 0;
        bpf_map_update_elem(&notification_map, &notification_key, &reset_value, BPF_ANY);
    }

    // 輻輳検出後10秒経過していたら実際のウィンドウサイズ調整を行う
    bool can_apply_congestion_control = false;
    if (info->congestion_start_time != 0 &&
        (current_time - info->congestion_start_time) >= DELAY_NS) {
        can_apply_congestion_control = true;
    }

    // ウィンドウサイズの調整（10秒待ってから実行）
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
