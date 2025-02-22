#include <bpf_helpers.h>
#include <ebpf_nethooks.h>

#define MIN(x, y) ((x) < (y)) ? (x) : (y)

typedef struct _process_info {
	uint32_t id;
	char name[32];
	uint32_t count;
} process_info;


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, process_info);
	__uint(max_entries, 1024);
} proc_map SEC(".maps");

SEC("bind")
bind_action_t TraceConnections(bind_md_t* ctx) {
	if (ctx->operation == BIND_OPERATION_BIND) {
		uint32_t pid = (uint32_t)ctx->process_id;
		process_info pi = { 0 };
		process_info* p = bpf_map_lookup_elem(&proc_map, &pid);
		if (p) {
			p->count++;
		}
		else {
			pi.id = pid;
			memcpy(pi.name, ctx->app_id_start, MIN(sizeof(pi.name), ctx->app_id_end - ctx->app_id_start));
			pi.count = 1;
			p = &pi;
		}
		bpf_map_update_elem(&proc_map, &pid, p, 0);
		bpf_printk("PID: %u\n", pid);

	}
	return BIND_PERMIT;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
