#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, 4);
    __uint(value_size, 4);
} prog_array SEC(".maps");

u64 invocation_counter = 0;

SEC("veryverylongsectionnametobelongerthananyotherrealisticsectionnameusedinpractice")
int loader(u64 *ctx) {
    if (__sync_fetch_and_add(&invocation_counter, 1) % 256 == 0)
        bpf_tail_call(ctx, &prog_array, 0);
    return 0;
}
