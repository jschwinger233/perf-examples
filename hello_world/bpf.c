// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("perf_event")
int bpf_prog1(struct bpf_perf_event_data *ctx)
{
	u64 ktime = bpf_ktime_get_ns();
	bpf_printk("%lld\n", ktime);
	return 0;
}
