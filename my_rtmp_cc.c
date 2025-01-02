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

extern void tcp_reno_cong_avoid(struct sock *sk, __u32 ack, __u32 acked) __ksym;

#define BICTCP_BETA_SCALE    1024
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */
#define HZ CONFIG_HZ
#define USEC_PER_MSEC	1000UL
#define USEC_PER_SEC	1000000UL
#define USEC_PER_JIFFY	(USEC_PER_SEC / HZ)

/* BIC TCP Parameters */
struct bpf_bictcp {
	__u32	cnt;		/* increase cwnd by 1 after ACKs */
	__u32	last_max_cwnd;	/* last maximum snd_cwnd */
	__u32	last_cwnd;	/* the last snd_cwnd */
	__u32	last_time;	/* time when updated last_cwnd */
	__u32	bic_origin_point;/* origin point of bic function */
	__u32	bic_K;		/* time to origin point
				   from the beginning of the current epoch */
	__u32	delay_min;	/* min delay (usec) */
	__u32	epoch_start;	/* beginning of an epoch */
	__u32	ack_cnt;	/* number of acks */
	__u32	tcp_cwnd;	/* estimated tcp cwnd */
	__u16	unused;
	__u8	sample_cnt;	/* number of samples to decide curr_rtt */
	__u8	found;		/* the exit point is found? */
	__u32	round_start;	/* beginning of each round */
	__u32	end_seq;	/* end_seq of the round */
	__u32	last_ack;	/* last time when the ACK spacing is close */
	__u32	curr_rtt;	/* the minimum rtt of current round */
};

static __u64 div64_u64(__u64 dividend, __u64 divisor)
{
	return dividend / divisor;
}

#define max(a, b) ((a) > (b) ? (a) : (b))

static __u32 cubic_root(__u64 a)
{
	__u32 x, b, shift;

	if (a < 64) {
		/* a in [0..63] */
		return ((__u32)v[(__u32)a] + 35) >> 6;
	}

	b = fls64(a);
	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	/* it is needed for verifier's bound check on v */
	if (shift >= 64)
		return 0;

	x = ((__u32)(((__u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (__u32)div64_u64(a, (__u64)x * (__u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

static void bictcp_update(struct bpf_bictcp *ca, __u32 cwnd, __u32 acked)
{
	__u32 delta, bic_target, max_cnt;
	__u64 offs, t;

	ca->ack_cnt += acked;	/* count the number of ACKed packets */

	if (ca->last_cwnd == cwnd &&
	    (__s64)(bpf_jiffies64 - ca->last_time) <= HZ / 32)
		return;

	/* The CUBIC function can update ca->cnt at most once per jiffy.
	 * On all cwnd reduction events, ca->epoch_start is set to 0,
	 * which will force a recalculation of ca->cnt.
	 */
	if (ca->epoch_start && bpf_jiffies64 == ca->last_time)
		goto tcp_friendliness;

	ca->last_cwnd = cwnd;
	ca->last_time = bpf_jiffies64;

	if (ca->epoch_start == 0) {
		ca->epoch_start = bpf_jiffies64;	/* record beginning */
		ca->ack_cnt = acked;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those variables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (__s64)(bpf_jiffies64 - ca->epoch_start) * USEC_PER_JIFFY;
	t += ca->delay_min;
	/* change the unit from usec to bictcp_HZ */
	t <<= BICTCP_HZ;
	t /= USEC_PER_SEC;

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                            /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                          /* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		__u32 scale = beta_scale;
		__u32 n;

		/* update tcp cwnd */
		delta = (cwnd * scale) >> 3;
		if (ca->ack_cnt > delta && delta) {
			n = ca->ack_cnt / delta;
			ca->ack_cnt -= n * delta;
			ca->tcp_cwnd += n;
		}

		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	ca->cnt = max(ca->cnt, 2U);
}

SEC("struct_ops")
void BPF_PROG(my_rtmp_cc_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bpf_bictcp *ca = inet_csk_ca(sk);
    
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

    if (*in_cong) {
        if (now - *start_time >= DELAY_NS) {
            bictcp_update(ca, tp->snd_cwnd, acked);
        } else {
            bpf_printk("Waiting for 3 seconds to adjust cwnd.");
            return;
        }
    } else {
        bictcp_update(ca, tp->snd_cwnd, acked);
    }
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
    bpf_map_update_elem(&congestion_start_map, &sid, &zero, BPF_ANY);
    bpf_map_update_elem(&congestion_flag_map, &sid, &false_val, BPF_ANY);

    bpf_printk("Socket initialized.");
}

SEC("struct_ops/my_rtmp_cc_release")
void my_rtmp_cc_release(struct sock *sk) {
    __u16 num = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u64 sid = (__u64)num;
    bpf_map_delete_elem(&congestion_start_map, &sid);
    bpf_map_delete_elem(&congestion_flag_map, &sid);
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