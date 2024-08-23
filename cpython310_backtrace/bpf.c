// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define PAGE_SIZE (1<<12)
#define KASAN_STACK_ORDER 0
#define THREAD_SIZE_ORDER (2 + KASAN_STACK_ORDER)
#define THREAD_SIZE  ((__u64)(PAGE_SIZE << THREAD_SIZE_ORDER))
#define TOP_OF_KERNEL_STACK_PADDING ((__u64)0)

const static u32 ZERO = 0;

struct PyTypeObject {
    char _[24];
    char *tp_name;
};

struct PyObject {
    char _[8];
    struct PyTypeObject *ob_type;
};

struct PyVarObject {
    struct PyObject ob_base;
    char _[8];
};

struct PyASCIIObject {
	__u8 _[16];
	__u64 length;
	__u8 __[24];
};

struct _PyStr {
    struct PyASCIIObject ascii;
    char buf[100];
};

struct PyCodeObject {
    char _[104];
    struct _PyStr *co_filename;
    struct _PyStr *co_name;
};

struct PyFrameObject {
    struct PyVarObject ob_base;
    struct PyFrameObject *f_back;
    struct PyCodeObject *f_code;
    char _[60];
    int f_lineno;
};

struct event {
	__u64 rip;
	__u8 user_mode;
	__s8 python_stack_depth;
	__u64 filename_len[20];
	__u64 funcname_len[20];
	unsigned char filename[20][100];
	unsigned char funcname[20][100];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct event);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<29);
} ringbuf SEC(".maps");

SEC("perf_event/cpython310")
int perf_event_cpython310(struct bpf_perf_event_data *ctx)
{
	__u64 rsp;
	struct event *event;
	struct PyFrameObject *frame;

	event = bpf_map_lookup_elem(&events, &ZERO);
	if (!event)
		return 0;

	rsp = ctx->regs.sp;
	event->rip = ctx->regs.ip;
	event->user_mode = !!(ctx->regs.cs & 3);

	if (!event->user_mode) {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		__u64 __ptr = (__u64)BPF_CORE_READ(task, stack);
		__ptr += THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
		struct pt_regs *pt_regs = ((struct pt_regs *)__ptr) - 1;

		rsp = BPF_CORE_READ(pt_regs, sp);
		event->rip = BPF_CORE_READ(pt_regs, ip);
	}

	char name[5];
	bool found = false;

	for (int i = 0; i < 200; i++) {
		bpf_probe_read_user(&frame, sizeof(frame), (void *)rsp + 8*i);
		if (!frame)
			continue;

		char *tp_name = BPF_PROBE_READ_USER(frame, ob_base.ob_base.ob_type, tp_name);
		bpf_probe_read_user(&name, sizeof(name), (void *)tp_name);
		if (bpf_strncmp(name, 5, "frame") == 0) {
			found = true;
			break;
		}
	}

	if (!found) {
		event->python_stack_depth = -1;
		bpf_ringbuf_output(&ringbuf, event, sizeof(*event), 0);
		return 0;
	}

	for (int i = 0; i < 20; i++) {
		BPF_PROBE_READ_USER_INTO(&event->filename_len[i], frame, f_code, co_filename, ascii.length);
		BPF_PROBE_READ_USER_INTO(&event->filename[i], frame, f_code, co_filename, buf);
		BPF_PROBE_READ_USER_INTO(&event->funcname_len[i], frame, f_code, co_name, ascii.length);
		BPF_PROBE_READ_USER_INTO(&event->funcname[i], frame, f_code, co_name, buf);
		frame = BPF_PROBE_READ_USER(frame, f_back);
		if (!frame) {
			event->python_stack_depth = i;
			break;
		}
	}

	bpf_ringbuf_output(&ringbuf, event, sizeof(*event), 0);
	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
