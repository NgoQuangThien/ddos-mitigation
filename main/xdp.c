//go:build ignore

#include "../headers/vmlinux.h"
#include "../headers/bpf_endian.h"
#include "../headers/bpf_helpers.h"

#include "data_structures/map.h"
#include "data_structures/struct.h"

#include "packets_define/ethernet.h"
#include "packets_define/ip.h"
#include "packets_define/tcp.h"
#include "packets_define/udp.h"
#include "packets_define/icmp.h"

#include "processor/parsing_header.h"


SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct hdr_cursor nh;

	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	struct icmphdr *icmphdr;

	__u32 eth_type;
	__u32 ip_type;

	__u8 action = XDP_PASS;

	__u32 ip;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &ethhdr);
	switch (eth_type)
	{
	// IPv4
	case bpf_htons(ETH_P_IP):
		ip_type = parse_iphdr(&nh, data_end, &iphdr);

		if (ip_type == IPPROTO_ICMP) {
			if (!parse_ip_src_addr(iphdr, &ip)) {
				// Not an IPv4 packet, so don't count it.
				goto done;
			}

			__u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip);
			if (!pkt_count) {
				// No entry in the map for this IP address yet, so set the initial value to 1.
				__u32 init_pkt_count = 1;
				bpf_map_update_elem(&xdp_stats_map, &ip, &init_pkt_count, BPF_ANY);
			} else {
				// Entry already exists for this IP address,
				// so increment it atomically using an LLVM built-in.
				__sync_fetch_and_add(pkt_count, 1);
			}

			action = XDP_DROP;
			goto done;
		}

		else {
			goto done;
		}

		break;
	
	default:
		action = XDP_PASS;
		goto done;

		break;
	}

done:
	return action;
}

char __license[] SEC("license") = "Dual MIT/GPL";
