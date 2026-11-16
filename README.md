# eBPF monitoring rate-limiting

This repo contains two separate components:
1. **Top  folder**. A Zig custom eBPF object loader built on top of `libbpf` that injects rate-limiting on monitoring-class eBPF programs (like kprobes, tracepoints, etc.). This is the main contribution
2. **bench/**. A Rust binary crate used as a benchmark: it simply calls `syscall(-1)` in a loop to measure eBPF monitoring overhead.

## Zig loader

### Build
The loader is built on **Zig 0.15.2**, and can be built simply with:
```
zig build
```
Note that, given Zig's alpha status, the loader might not compile with later versions of the language.

### Usage
```
$ sudo zig-out/bin/ebpf_rate_limiter -h
Usage: [-h] [-o <str>] [-n <str>]

    -h, --help
            Display this help message and exit.

    -o, --object <str>
            Path to eBPF object file to rate limit.

    -n, --name <str>
            Name of the eBPF program in the provided object file to rate limit.
```

To use it, you must provide the loader with the eBPF binary object file, as well as the name of the eBPF program (in that ELF) that must be loaded. Other details, such as program type or attach point, are automatically inferred from the object.

As of now, the rate-limiting factor is hard-coded in `src/bpf/prog.bpf.c`.

## Rust bench

### Build
To build the bencher, simply call:
```
cd bench

# Builds the userspace bencher
cargo build --release

# Builds the "client" eBPF object file
clang -target bpf -c -O2 src/bpf/prog.bpf.c
```

This also generates `bench/prog.bpf.o`, which is a `tp_btf/sys_enter` program used in the benchmark.

### Usage
```
$ cargo run --release -- -h
    Finished `release` profile [optimized] target(s) in 0.01s
     Running `target/release/ebpf-rate-limiting-bench -h`
Run syscall(-1) in a loop to measure the system call overhead

Usage: ebpf-rate-limiting-bench [OPTIONS]

Options:
  -i, --iterations <ITERATIONS>  [default: 100000]
  -h, --help                     Print help
```

## Acknowledgements

This work has been partially supported by:
* the [ELASTIC project](https://elasticproject.eu/), which received funding from the [Smart Networks and Services Joint Undertaking](https://smart-networks.europa.eu/) (SNS JU) under the European Union’s [Horizon Europe](https://research-and-innovation.ec.europa.eu/funding/funding-opportunities/funding-programmes-and-open-calls/horizon-europe_en) research and innovation programme under [Grant Agreement No. 101139067](https://cordis.europa.eu/project/id/101139067). Views and opinions expressed are however those of the author(s) only and do not necessarily reflect those of the European Union. Neither the European Union nor the granting authority can be held responsible for them.
* the European Union - Next Generation EU under the Italian National Recovery and Resilience Plan (NRRP), Mission 4, Component 2, Investment 1.3, CUP E13C22001870001, partnership on "Telecommunications of the Future" (PE00000001 - program "RESTART").
