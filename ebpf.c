// 必要なヘッダーファイルをインクルード
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// 輻輳情報を格納する構造体
struct congestion_info
{
    __u64 last_timestamp;   // 最後のパケットのタイムスタンプ
    __u32 packet_count;     // 通常パケットのカウント
    __u32 retransmit_count; // 再送パケットのカウント
};

// 輻輳情報を保存するためのBPFマップ
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);       // ハッシュマップタイプ
    __uint(max_entries, 1024);             // 最大エントリ数
    __type(key, __u32);                    // キーの型（IPアドレス）
    __type(value, struct congestion_info); // 値の型（輻輳情報構造体）
} congestion_map SEC(".maps");

// OBSプラグインへの通知状態を管理するためのBPFマップ
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY); // 配列マップタイプ
    __uint(max_entries, 1);           // 単一エントリ
    __type(key, __u32);               // キーの型（常に0）
    __type(value, __u32);             // 値の型（通知カウンター）
} notification_map SEC(".maps");

// window_size_map
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY); // 配列マップタイプ
    __uint(max_entries, 1);           // 単一エントリ
    __type(key, __u32);               // キーの型(IPアドレス)
    __type(value, __u32);             // 値の型（ウィンドウサイズ）
} window_size_map SEC(".maps");

// 定数の定義
#define CONGESTION_THRESHOLD 10           // 輻輳と判断するための閾値
#define PACKET_INTERVAL_THRESHOLD 1000000 // パケット間隔の閾値（1ms in nanoseconds）
#define RETRANSMIT_THRESHOLD 3            // 再送回数の閾値

#define RTMP_PORT 1935 // RTMPポート番号

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

    if (tcp->source != bpf_htons(RTMP_PORT) && tcp->dest != bpf_htons(RTMP_PORT))
        return TC_ACT_OK;

    // 送信元IPアドレスをキーとして使用
    __u32 key = ip->saddr;
    // 輻輳情報マップからデータを取得または初期化
    struct congestion_info *info = bpf_map_lookup_elem(&congestion_map, &key);
    if (!info)
    {
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
    bool is_retransmit = tcp->syn || tcp->rst || tcp->fin;
    if (is_retransmit)
        info->retransmit_count++;
    else
        info->packet_count++;

    // 輻輳検出ロジック
    bool congestion_detected = false;
    if (interval < PACKET_INTERVAL_THRESHOLD || info->retransmit_count >= RETRANSMIT_THRESHOLD)
    {
        congestion_detected = true;
    }

    // ウィンドウサイズの調整
    __u32 window_key = ip->saddr;
    __u32 *current_window_size = bpf_map_lookup_elem(&window_size_map, &window_key);
    if (current_window_size)
    {
        __u32 new_window_size;
        if (congestion_detected)
        {
            // 輻輳が検出された場合、ウィンドウサイズを半分に減少
            new_window_size = *current_window_size / 2;
            if (new_window_size < 1)
                new_window_size = 1;
        }
        else
        {
            // 輻輳が検出されなかった場合、ウィンドウサイズを1増加
            new_window_size = *current_window_size + 1;
        }
        bpf_map_update_elem(&window_size_map, &window_key, &new_window_size, BPF_ANY);
    }
    else
    {
        // ウィンドウサイズが初期化されていない場合、初期値を設定
        __u32 initial_window_size = 10;
        bpf_map_update_elem(&window_size_map, &window_key, &initial_window_size, BPF_ANY);
    }

    // 輻輳が検出された場合の処理
    if (congestion_detected)
    {
        __u32 notification_key = 0;
        __u32 *notification_value = bpf_map_lookup_elem(&notification_map, &notification_key);
        if (notification_value)
        {
            (*notification_value)++;
            if (*notification_value > CONGESTION_THRESHOLD)
            {
                // OBSプラグインに通知
                // 実際の実装では、この部分を適切な通知メカニズムに置き換える
                __u32 obs_notification = 1;
                bpf_map_update_elem(&notification_map, &notification_key, &obs_notification, BPF_ANY);
            }
        }
    }
    else
    {
        // 輻輳が検出されなかった場合、通知カウンターをリセット
        __u32 notification_key = 0;
        __u32 reset_value = 0;
        bpf_map_update_elem(&notification_map, &notification_key, &reset_value, BPF_ANY);
    }

    // パケットを通常通り処理
    return TC_ACT_OK;
}

// GPLライセンスの宣言（eBPFプログラムに必要）
char _license[] SEC("license") = "GPL";