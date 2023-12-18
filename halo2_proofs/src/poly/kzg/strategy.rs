use std::{fmt::Debug, marker::PhantomData};

use super::{
    commitment::{KZGCommitmentScheme, ParamsKZG},
    msm::{DualMSM, MSMKZG},
    multiopen::VerifierGWC,
};
use crate::{
    helpers::SerdeCurveAffine,
    plonk::Error,
    poly::{
        commitment::{Verifier, MSM},
        ipa::msm::MSMIPA,
        strategy::{Guard, VerificationStrategy},
    },
    transcript::{EncodedChallenge, TranscriptRead},
};
use ff::{Field, PrimeField};
use group::Group;
use halo2curves::{
    pairing::{Engine, MillerLoopResult, MultiMillerLoop},
    CurveAffine,
};
use rand_core::OsRng;

/// Wrapper for linear verification accumulator
#[derive(Debug, Clone)]
pub struct GuardKZG<'params, 'zal, E: MultiMillerLoop + Debug, Zal> {
    pub(crate) msm_accumulator: DualMSM<'params, 'zal, E, Zal>,
}

/// Define accumulator type as `DualMSM`
impl<'params, 'zal, E, Zal> Guard<KZGCommitmentScheme<'zal, E, Zal>> for GuardKZG<'params, 'zal, E, Zal>
where
    E::Scalar: PrimeField,
    E: MultiMillerLoop + Debug,
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
    type MSMAccumulator = DualMSM<'params, 'zal, E, Zal>;
}

/// KZG specific operations
impl<'params, 'zal, E: MultiMillerLoop + Debug, Zal> GuardKZG<'params, 'zal, E, Zal> {
    pub(crate) fn new(msm_accumulator: DualMSM<'params, 'zal, E, Zal>) -> Self {
        Self { msm_accumulator }
    }
}

/// A verifier that checks multiple proofs in a batch
#[derive(Clone, Debug)]
pub struct AccumulatorStrategy<'params, 'zal, E: Engine, Zal> {
    pub(crate) msm_accumulator: DualMSM<'params, 'zal, E, Zal>,
}

impl<'params, 'zal, E: MultiMillerLoop + Debug, Zal> AccumulatorStrategy<'params, 'zal, E, Zal> {
    /// Constructs an empty batch verifier
    pub fn new(params: &'params ParamsKZG<'zal, E, Zal>) -> Self {
        AccumulatorStrategy {
            msm_accumulator: DualMSM::new(params),
        }
    }

    /// Constructs and initialized new batch verifier
    pub fn with(msm_accumulator: DualMSM<'params, 'zal, E, Zal>) -> Self {
        AccumulatorStrategy { msm_accumulator }
    }
}

/// A verifier that checks a single proof
#[derive(Clone, Debug)]
pub struct SingleStrategy<'params, 'zal, E: Engine, Zal> {
    pub(crate) msm: DualMSM<'params, 'zal, E, Zal>,
}

impl<'params, 'zal, E: MultiMillerLoop + Debug, Zal> SingleStrategy<'params, 'zal, E, Zal> {
    /// Constructs an empty batch verifier
    pub fn new(params: &'params ParamsKZG<'zal, E, Zal>) -> Self {
        SingleStrategy {
            msm: DualMSM::new(params),
        }
    }
}

impl<
        'params, 'zal,
        E: MultiMillerLoop + Debug,
        Zal,
        V: Verifier<
            'params,
            KZGCommitmentScheme<'zal, E, Zal>,
            MSMAccumulator = DualMSM<'params, 'zal, E, Zal>,
            Guard = GuardKZG<'params, 'zal, E, Zal>,
        >,
    > VerificationStrategy<'params, KZGCommitmentScheme<'zal, E, Zal>, V> for AccumulatorStrategy<'params, 'zal, E, Zal>
where
    E::Scalar: PrimeField,
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
    type Output = Self;

    fn new(params: &'params ParamsKZG<'zal, E, Zal>) -> Self {
        AccumulatorStrategy::new(params)
    }

    fn process(
        mut self,
        f: impl FnOnce(V::MSMAccumulator) -> Result<V::Guard, Error>,
    ) -> Result<Self::Output, Error> {
        self.msm_accumulator.scale(E::Scalar::random(OsRng));

        // Guard is updated with new msm contributions
        let guard = f(self.msm_accumulator)?;
        Ok(Self {
            msm_accumulator: guard.msm_accumulator,
        })
    }

    fn finalize(self) -> bool {
        self.msm_accumulator.check()
    }
}

impl<
        'params, 'zal,
        E: MultiMillerLoop + Debug,
        Zal,
        V: Verifier<
            'params,
            KZGCommitmentScheme<'zal, E, Zal>,
            MSMAccumulator = DualMSM<'params, 'zal, E, Zal>,
            Guard = GuardKZG<'params, 'zal, E, Zal>,
        >,
    > VerificationStrategy<'params, KZGCommitmentScheme<'zal, E, Zal>, V> for SingleStrategy<'params, 'zal, E, Zal>
where
    E::Scalar: PrimeField,
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
    type Output = ();

    fn new(params: &'params ParamsKZG<'zal, E, Zal>) -> Self {
        Self::new(params)
    }

    fn process(
        self,
        f: impl FnOnce(V::MSMAccumulator) -> Result<V::Guard, Error>,
    ) -> Result<Self::Output, Error> {
        // Guard is updated with new msm contributions
        let guard = f(self.msm)?;
        let msm = guard.msm_accumulator;
        if msm.check() {
            Ok(())
        } else {
            Err(Error::ConstraintSystemFailure)
        }
    }

    fn finalize(self) -> bool {
        unreachable!();
    }
}
