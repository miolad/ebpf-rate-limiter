use std::time::Instant;

use clap::Parser;

#[derive(Parser)]
#[clap(about = "Run syscall(-1) in a loop to measure the system call overhead")]
struct Args {
    #[clap(short, long, default_value_t = 100_000)]
    iterations: u32
}

fn main() {
    let args = Args::parse();

    let mut sum = 0;
    for _ in 0..args.iterations {
        let now = Instant::now();
        unsafe { libc::syscall(-1) };
        sum += now.elapsed().as_nanos();
    }

    println!("Average syscall(-1) time: {} ns", sum / args.iterations as u128);
}
