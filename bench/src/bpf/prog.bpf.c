#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tp_btf/sys_enter")
int BPF_PROG(trace_enter, struct pt_regs *regs, long id)
{
    if (id == -1) {
        bpf_printk("sys_enter: id = -1");
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
