use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pprof::criterion::{Output, PProfProfiler};

use scrypt_jane::scrypt::{scrypt, ScryptParams};

fn scrypting_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("scrypting");

    for n in [128u32, 512, 8192] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let mut output = [0u8; 8];
            let nfactor = n.ilog2() as u8 - 1;
            b.iter(|| {
                scrypt(
                    b"hello world, challenge me!!!!!!!",
                    b"NaCl",
                    ScryptParams::new(nfactor, 0, 0),
                    &mut output,
                );
                black_box(output);
            });
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(1000, Output::Flamegraph(None)));
    targets=scrypting_bench,
);

criterion_main!(benches);
