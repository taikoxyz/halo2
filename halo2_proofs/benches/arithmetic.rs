#[macro_use]
extern crate criterion;

use group::ff::Field;
use halo2_proofs::*;
use halo2curves::pasta::{EqAffine, Fp};
use halo2curves::zal::{H2cEngine, MsmAccel};

use halo2_proofs::poly::{commitment::ParamsProver, ipa::commitment::ParamsIPA};

use criterion::{black_box, Criterion};
use rand_core::OsRng;

fn criterion_benchmark(c: &mut Criterion) {
    let rng = OsRng;

    // small multiexp
    {
        let engine = H2cEngine::new();
        let params: ParamsIPA<EqAffine> = ParamsIPA::new(5);
        let g = &mut params.get_g().to_vec();
        let len = g.len() / 2;
        let (g_lo, g_hi) = g.split_at_mut(len);

        let coeff_1 = Fp::random(rng);
        let coeff_2 = Fp::random(rng);

        c.bench_function("double-and-add", |b| {
            b.iter(|| {
                for (g_lo, g_hi) in g_lo.iter().zip(g_hi.iter()) {
                    engine.msm(&[black_box(coeff_1), black_box(coeff_2)], &[*g_lo, *g_hi]);
                }
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
