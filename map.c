#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

struct congestion_info {
    __u64 last_timestamp;
    __u32 packet_count;
    __u32 retransmit_count;
};

int main() {
    // マップのファイルディスクリプタを取得
    int congestion_map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/congestion_map");
    int notification_map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/notification_map");
    int window_size_map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/window_size_map");

    if (congestion_map_fd < 0 || notification_map_fd < 0 || window_size_map_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptors\n");
        return 1;
    }

    // congestion_mapの内容を表示
    __u32 key = 0;
    struct congestion_info value;
    while (bpf_map_get_next_key(congestion_map_fd, &key, &key) == 0) {
        if (bpf_map_lookup_elem(congestion_map_fd, &key, &value) == 0) {
            printf("Congestion Map - Key: %u, Last Timestamp: %llu, Packet Count: %u, Retransmit Count: %u\n",
                   key, value.last_timestamp, value.packet_count, value.retransmit_count);
        }
    }

    // notification_mapの内容を表示
    __u32 notification_value;
    key = 0;
    if (bpf_map_lookup_elem(notification_map_fd, &key, &notification_value) == 0) {
        printf("Notification Map - Value: %u\n", notification_value);
    }

    // window_size_mapの内容を表示
    __u32 window_size;
    key = 0;
    if (bpf_map_lookup_elem(window_size_map_fd, &key, &window_size) == 0) {
        printf("Window Size Map - Value: %u\n", window_size);
    }

    close(congestion_map_fd);
    close(notification_map_fd);
    close(window_size_map_fd);

    return 0;
}
