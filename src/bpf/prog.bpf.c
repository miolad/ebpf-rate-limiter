#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("raw_tp/task_rename")
int prog() {
    return 0;
}
