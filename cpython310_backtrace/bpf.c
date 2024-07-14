// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("perf_event")
int cpython310_bt(struct bpf_perf_event_data *ctx)
{
	__u64 sp = ctx->regs.sp;
	__u64 frame, pyobj_type, pyobj_tp_name;
	char pyobj_type_name[5];
	bool frame_found = false;
	for (int i = 0; i < 100; i++) {
		bpf_probe_read_user(&frame, sizeof(frame), (void *)sp + 8*i);
		// frame->ob_base.ob_base.ob_type
		bpf_probe_read_user(&pyobj_type, sizeof(pyobj_type), (void *)frame + 8);
		// ob_type->tp_name
		bpf_probe_read_user(&pyobj_tp_name, sizeof(pyobj_tp_name), (void *)pyobj_type + 24);
		bpf_probe_read_user(&pyobj_type_name, 5, (void *)pyobj_tp_name);
		if (bpf_strncmp(pyobj_type_name, 5, "frame") == 0) {
			frame_found = true;
			break;
		}
	}

	if (!frame_found)
		return 0;

	__u64 f_code, co_name;
	char pyfunc_name[100];
	for (int i = 0; i < 20; i++) {
		// frame->f_code
		bpf_probe_read_user(&f_code, sizeof(f_code), (void *)frame + 32);
		// f_code->co_name
		bpf_probe_read_user(&co_name, sizeof(co_name), (void *)f_code + 112);
		bpf_probe_read_user_str(&pyfunc_name, 100, (void *)co_name + 48);
		bpf_printk("%s\n", pyfunc_name);

		// frame = frame->f_back
		bpf_probe_read_user(&frame, sizeof(frame), (void *)frame + 24);
		if (!frame)
			break;
	}
	return 0;
}

