//go:build ignore

#include "../headers/vmlinux.h"
#include "../headers/bpf_endian.h"
#include "../headers/bpf_helpers.h"

#include "data_structures/map.h"
#include "data_structures/common.h"

#include "packets_define/ethernet.h"
#include "packets_define/ip.h"
#include "packets_define/tcp.h"
#include "packets_define/udp.h"
#include "packets_define/icmp.h"

/* NOTICE: Re-defining VLAN header levels to parse */
#define VLAN_MAX_DEPTH 10
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
/* Struct for collecting VLANs after parsing via parse_ethhdr_vlan */
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};


static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}


static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
					     void *data_end,
					     struct ethhdr **ethhdr,
					     struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if ((void *)(vlh + 1) > data_end)
		// if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}


static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	/* Expect compiler removes the code that collects VLAN ids */
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}


static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if ((void *)(iph + 1) > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}


static __always_inline int parse_ip_src_addr(struct iphdr *iphdr, __u32 *ip_src_addr) {
	*ip_src_addr = (__u32)(iphdr->saddr);

	return 1;
}


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
