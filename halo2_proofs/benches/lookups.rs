#[macro_use]
extern crate criterion;

use group::ff::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Cell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::*;
use halo2_proofs::poly::{commitment::ParamsProver, Rotation};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2curves::pasta::{EqAffine, Fp};
use rand_core::OsRng;

use halo2_proofs::{
    poly::{
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
            strategy::SingleStrategy,
        },
        VerificationStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};

use std::marker::PhantomData;

use criterion::{BenchmarkId, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    #[derive(Clone, Default)]
    struct MyCircuit<F: FieldExt> {
        _marker: PhantomData<F>,
    }

    #[derive(Clone)]
    struct MyConfig {
        selector: Selector,
        table: TableColumn,
        advice: Column<Advice>,
        other_advice: Column<Advice>,
    }

    impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
        type Config = MyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> MyConfig {
            let config = MyConfig {
                selector: meta.complex_selector(),
                table: meta.lookup_table_column(),
                advice: meta.advice_column(),
                other_advice: meta.advice_column(),
            };

            // meta.set_minimum_degree(16);

            meta.lookup("lookup", |meta| {
                let selector = meta.query_selector(config.selector);
                let not_selector = Expression::Constant(F::one()) - selector.clone();
                let advice = meta.query_advice(config.advice, Rotation::cur());
                let other_advice = meta.query_advice(config.other_advice, Rotation::cur());
                vec![(
                    selector.clone() * advice + not_selector.clone(),
                    config.table,
                )]
            });

            meta.lookup("lookup", |meta| {
                let selector = meta.query_selector(config.selector);
                let not_selector = Expression::Constant(F::one()) - selector.clone();
                let advice = meta.query_advice(config.advice, Rotation::cur());
                let other_advice = meta.query_advice(config.other_advice, Rotation::cur());
                vec![(
                    selector.clone() * advice + not_selector.clone(),
                    config.table,
                )]
            });

            meta.lookup("lookup", |meta| {
                let selector = meta.query_selector(config.selector);
                let not_selector = Expression::Constant(F::one()) - selector.clone();
                let advice = meta.query_advice(config.advice, Rotation::cur());
                let other_advice = meta.query_advice(config.other_advice, Rotation::cur());
                vec![(
                    selector.clone() * advice + not_selector.clone(),
                    config.table,
                )]
            });

            meta.lookup("lookup", |meta| {
                let selector = meta.query_selector(config.selector);
                let not_selector = Expression::Constant(F::one()) - selector.clone();
                let advice = meta.query_advice(config.advice, Rotation::cur());
                let other_advice = meta.query_advice(config.other_advice, Rotation::cur());
                vec![(
                    selector.clone() * advice + not_selector.clone(),
                    config.table,
                )]
            });

            meta.lookup("lookup", |meta| {
                let selector = meta.query_selector(config.selector);
                let not_selector = Expression::Constant(F::one()) - selector.clone();
                let advice = meta.query_advice(config.advice, Rotation::cur());
                let other_advice = meta.query_advice(config.other_advice, Rotation::cur());
                vec![(
                    selector.clone() * advice + not_selector.clone(),
                    config.table,
                )]
            });

            config
        }

        fn synthesize(
            &self,
            config: MyConfig,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            layouter.assign_table(
                || "8-bit table",
                |mut table| {
                    for row in 0u64..(1 << 8) {
                        table.assign_cell(
                            || format!("row {}", row),
                            config.table,
                            row as usize,
                            || Value::known(F::from(row + 1)),
                        )?;
                    }

                    Ok(())
                },
            )?;

            layouter.assign_region(
                || "assign values",
                |mut region| {
                    for offset in 0u64..(1 << 10) {
                        config.selector.enable(&mut region, offset as usize)?;
                        region.assign_advice(
                            || format!("offset {}", offset),
                            config.advice,
                            offset as usize,
                            || Value::known(F::from((offset % 256) + 1)),
                        )?;
                    }
                    for offset in 1u64..(1 << 10) {
                        config.selector.enable(&mut region, offset as usize)?;
                        region.assign_advice(
                            || format!("offset {}", offset),
                            config.other_advice,
                            offset as usize - 1,
                            || Value::known(F::from((offset % 256) + 1)),
                        )?;
                    }
                    Ok(())
                },
            )
        }
    }

    fn keygen(k: u32) -> (ParamsIPA<EqAffine>, ProvingKey<EqAffine>) {
        let params: ParamsIPA<EqAffine> = ParamsIPA::new(k);
        let empty_circuit: MyCircuit<Fp> = MyCircuit {
            _marker: PhantomData,
        };
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
        (params, pk)
    }

    fn prover(k: u32, params: &ParamsIPA<EqAffine>, pk: &ProvingKey<EqAffine>) -> Vec<u8> {
        let rng = OsRng;

        let circuit: MyCircuit<Fp> = MyCircuit {
            _marker: PhantomData,
        };

        let mut transcript = Blake2bWrite::<_, _, Challenge255<EqAffine>>::init(vec![]);
        create_proof::<IPACommitmentScheme<EqAffine>, ProverIPA<EqAffine>, _, _, _, _>(
            params,
            pk,
            &[circuit],
            &[&[]],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        transcript.finalize()
    }

    fn verifier(params: &ParamsIPA<EqAffine>, vk: &VerifyingKey<EqAffine>, proof: &[u8]) {
        let strategy = SingleStrategy::new(params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
        assert!(verify_proof(params, vk, strategy, &[&[]], &mut transcript).is_ok());
    }

    let k_range = 11..=11;

    let mut keygen_group = c.benchmark_group("plonk-keygen");
    keygen_group.sample_size(10);
    for k in k_range.clone() {
        keygen_group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, &k| {
            b.iter(|| keygen(k));
        });
    }
    keygen_group.finish();

    let mut prover_group = c.benchmark_group("plonk-prover");
    prover_group.sample_size(10);
    for k in k_range.clone() {
        let (params, pk) = keygen(k);

        prover_group.bench_with_input(
            BenchmarkId::from_parameter(k),
            &(k, &params, &pk),
            |b, &(k, params, pk)| {
                b.iter(|| prover(k, params, pk));
            },
        );
    }
    prover_group.finish();

    let mut verifier_group = c.benchmark_group("plonk-verifier");
    for k in k_range {
        let (params, pk) = keygen(k);
        let proof = prover(k, &params, &pk);

        verifier_group.bench_with_input(
            BenchmarkId::from_parameter(k),
            &(&params, pk.get_vk(), &proof[..]),
            |b, &(params, vk, proof)| {
                b.iter(|| verifier(params, vk, proof));
            },
        );
    }
    verifier_group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
