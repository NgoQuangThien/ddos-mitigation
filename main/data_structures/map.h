#ifndef __MAP_DEFINE_H
#define __MAP_DEFINE_H

#include "../../headers/vmlinux.h"
#include "../../headers/bpf_helpers.h"


#define MAX_MAP_ENTRIES 16

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32); // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");

#endif /* __MAP_DEFINE_H */