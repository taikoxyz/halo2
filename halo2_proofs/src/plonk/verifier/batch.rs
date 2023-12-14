use std::{io, marker::PhantomData};

use ff::FromUniformBytes;
use group::ff::Field;
use halo2curves::{CurveAffine, zal::MsmAccel};
use rand_core::{OsRng, RngCore};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};

use super::{verify_proof, VerificationStrategy};
use crate::{
    multicore,
    plonk::{Error, VerifyingKey},
    poly::{
        commitment::{Params, MSM},
        ipa::{
            commitment::{IPACommitmentScheme, ParamsVerifierIPA},
            msm::MSMIPA,
            multiopen::VerifierIPA,
            strategy::GuardIPA,
        },
    },
    transcript::{Blake2bRead, TranscriptReadBuffer},
};

/// A proof verification strategy that returns the proof's MSM.
///
/// `BatchVerifier` handles the accumulation of the MSMs for the batched proofs.
#[derive(Debug)]
struct BatchStrategy<'params, 'zal, C: CurveAffine, Zal>
    where Zal: MsmAccel<C>
{
    msm: MSMIPA<'params, 'zal, C, Zal>,
}

impl<'params, 'zal, C: CurveAffine, Zal>
    VerificationStrategy<'params, IPACommitmentScheme<'zal, C, Zal>, VerifierIPA<'params, 'zal, C, Zal>>
    for BatchStrategy<'params, 'zal, C, Zal>
    where Zal: MsmAccel<C>
{
    type Output = MSMIPA<'params, 'zal, C, Zal>;

    fn new(params: &'params ParamsVerifierIPA<'zal, C, Zal>) -> Self {
        BatchStrategy {
            msm: MSMIPA::new(params),
        }
    }

    fn process(
        self,
        f: impl FnOnce(MSMIPA<'params, 'zal, C, Zal>) -> Result<GuardIPA<'params, 'zal, C, Zal>, Error>,
    ) -> Result<Self::Output, Error> {
        let guard = f(self.msm)?;
        Ok(guard.use_challenges())
    }

    fn finalize(self) -> bool {
        unreachable!()
    }
}

#[derive(Debug)]
struct BatchItem<C: CurveAffine> {
    instances: Vec<Vec<Vec<C::ScalarExt>>>,
    proof: Vec<u8>,
}

/// A verifier that checks multiple proofs in a batch. **This requires the
/// `batch` crate feature to be enabled.**
#[derive(Debug, Default)]
pub struct BatchVerifier<C: CurveAffine> {
    items: Vec<BatchItem<C>>,
}

impl<C: CurveAffine> BatchVerifier<C>
where
    C::Scalar: FromUniformBytes<64>,
{
    /// Constructs a new batch verifier.
    pub fn new() -> Self {
        Self { items: vec![] }
    }

    /// Adds a proof to the batch.
    pub fn add_proof(&mut self, instances: Vec<Vec<Vec<C::Scalar>>>, proof: Vec<u8>) {
        self.items.push(BatchItem { instances, proof })
    }

    /// Finalizes the batch and checks its validity.
    ///
    /// Returns `false` if *some* proof was invalid. If the caller needs to identify
    /// specific failing proofs, it must re-process the proofs separately.
    ///
    /// This uses [`OsRng`] internally instead of taking an `R: RngCore` argument, because
    /// the internal parallelization requires access to a RNG that is guaranteed to not
    /// clone its internal state when shared between threads.
    pub fn finalize<'zal, Zal>(self, params: &ParamsVerifierIPA<'zal, C, Zal>, vk: &VerifyingKey<C>) -> bool
        where Zal: MsmAccel<C>
    {
        fn accumulate_msm<'params, 'zal, C: CurveAffine, Zal>(
            mut acc: MSMIPA<'params, 'zal, C, Zal>,
            msm: MSMIPA<'params, 'zal, C, Zal>,
        ) -> MSMIPA<'params, 'zal, C, Zal>
            where Zal: MsmAccel<C>
        {
            // Scale the MSM by a random factor to ensure that if the existing MSM has
            // `is_zero() == false` then this argument won't be able to interfere with it
            // to make it true, with high probability.
            acc.scale(C::Scalar::random(OsRng));

            acc.add_msm(&msm);
            acc
        }

        let final_msm = self
            .items
            .into_par_iter()
            .enumerate()
            .map(|(i, item)| {
                let instances: Vec<Vec<_>> = item
                    .instances
                    .iter()
                    .map(|i| i.iter().map(|c| &c[..]).collect())
                    .collect();
                let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

                let strategy = BatchStrategy::new(params);
                let mut transcript = Blake2bRead::init(&item.proof[..]);
                verify_proof(params, vk, strategy, &instances, &mut transcript).map_err(|e| {
                    tracing::debug!("Batch item {} failed verification: {}", i, e);
                    e
                })
            })
            .try_fold(
                || params.empty_msm(),
                |msm, res| res.map(|proof_msm| accumulate_msm(msm, proof_msm)),
            )
            .try_reduce(|| params.empty_msm(), |a, b| Ok(accumulate_msm(a, b)));

        match final_msm {
            Ok(msm) => msm.check(),
            Err(_) => false,
        }
    }
}
