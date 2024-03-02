#ifndef __PARSING_HEADER_H
#define __PARSING_HEADER_H

#include "../headers/vmlinux.h"
#include "../headers/bpf_endian.h"
#include "../headers/bpf_helpers.h"

#include "../data_structures/map.h"
#include "../data_structures/struct.h"

#include "../packets_define/ethernet.h"
#include "../packets_define/ip.h"
#include "../packets_define/tcp.h"
#include "../packets_define/udp.h"
#include "../packets_define/icmp.h"


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
	*ip_src_addr = (__u32)(iphdr->addrs.saddr);

	return 1;
}
#endif /* __PARSING_HEADER_H */
