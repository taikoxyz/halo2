use std::marker::PhantomData;

use super::commitment::{IPACommitmentScheme, ParamsIPA, ParamsVerifierIPA};
use super::msm::MSMIPA;
use super::multiopen::VerifierIPA;
use crate::poly::commitment::CommitmentScheme;
use crate::transcript::TranscriptRead;
use crate::{
    plonk::Error,
    poly::{
        commitment::MSM,
        strategy::{Guard, VerificationStrategy},
    },
    transcript::EncodedChallenge,
};
use ff::Field;
use group::Curve;
use halo2curves::zal::MsmAccel;
use halo2curves::CurveAffine;
use rand_core::{OsRng, RngCore};

/// Wrapper for verification accumulator
#[derive(Debug, Clone)]
pub struct GuardIPA<'params, 'zal, C: CurveAffine, Zal>
    where Zal: MsmAccel<C>
{
    pub(crate) msm: MSMIPA<'params, 'zal, C, Zal>,
    pub(crate) neg_c: C::Scalar,
    pub(crate) u: Vec<C::Scalar>,
    pub(crate) u_packed: Vec<C::Scalar>,
}

/// An accumulator instance consisting of an evaluation claim and a proof.
#[derive(Debug, Clone)]
pub struct Accumulator<C: CurveAffine> {
    /// The claimed output of the linear-time polycommit opening protocol
    pub g: C,

    /// A vector of challenges u_0, ..., u_{k - 1} sampled by the verifier, to
    /// be used in computing G'_0.
    pub u_packed: Vec<C::Scalar>,
}

/// Define accumulator type as `MSMIPA`
impl<'params, 'zal, C: CurveAffine, Zal> Guard<IPACommitmentScheme<'zal, C, Zal>> for GuardIPA<'params, 'zal, C, Zal>
    where Zal: MsmAccel<C>
{
    type MSMAccumulator = MSMIPA<'params, 'zal, C, Zal>;
}

/// IPA specific operations
impl<'params, 'zal, C: CurveAffine, Zal> GuardIPA<'params, 'zal, C, Zal>
    where Zal: MsmAccel<C>
{
    /// Lets caller supply the challenges and obtain an MSM with updated
    /// scalars and points.
    pub fn use_challenges(mut self) -> MSMIPA<'params, 'zal, C, Zal> {
        let s = compute_s(&self.u, self.neg_c);
        self.msm.add_to_g_scalars(&s);

        self.msm
    }

    /// Lets caller supply the purported G point and simply appends
    /// [-c] G to return an updated MSM.
    pub fn use_g(mut self, g: C) -> (MSMIPA<'params, 'zal, C, Zal>, Accumulator<C>) {
        self.msm.append_term(self.neg_c, g.into());

        let accumulator = Accumulator {
            g,
            u_packed: self.u_packed,
        };

        (self.msm, accumulator)
    }

    /// Computes G = ⟨s, params.g⟩
    pub fn compute_g(&self) -> C {
        let s = compute_s(&self.u, C::Scalar::ONE);

        self.msm.params.engine.msm(&s, &self.msm.params.g).to_affine()
    }
}

/// A verifier that checks multiple proofs in a batch.
#[derive(Debug)]
pub struct AccumulatorStrategy<'params, 'zal, C: CurveAffine, Zal>
    where Zal: MsmAccel<C>
{
    msm: MSMIPA<'params, 'zal, C, Zal>,
}

impl<'params, 'zal, C: CurveAffine, Zal>
    VerificationStrategy<'params, IPACommitmentScheme<'zal, C, Zal>, VerifierIPA<'params, 'zal, C, Zal>>
    for AccumulatorStrategy<'params, 'zal, C, Zal>
    where Zal: MsmAccel<C>
{
    type Output = Self;

    fn new(params: &'params ParamsIPA<'zal, C, Zal>) -> Self {
        AccumulatorStrategy {
            msm: MSMIPA::new(params),
        }
    }

    fn process(
        mut self,
        f: impl FnOnce(MSMIPA<'params, 'zal, C, Zal>) -> Result<GuardIPA<'params, 'zal, C, Zal>, Error>,
    ) -> Result<Self::Output, Error> {
        self.msm.scale(C::Scalar::random(OsRng));
        let guard = f(self.msm)?;

        Ok(Self {
            msm: guard.use_challenges(),
        })
    }

    /// Finalizes the batch and checks its validity.
    ///
    /// Returns `false` if *some* proof was invalid. If the caller needs to identify
    /// specific failing proofs, it must re-process the proofs separately.
    #[must_use]
    fn finalize(self) -> bool {
        self.msm.check()
    }
}

/// A verifier that checks single proof
#[derive(Debug)]
pub struct SingleStrategy<'params, 'zal, C: CurveAffine, Zal>
    where Zal: MsmAccel<C>
{
    msm: MSMIPA<'params, 'zal, C, Zal>,
}

impl<'params, 'zal, C: CurveAffine, Zal>
    VerificationStrategy<'params, IPACommitmentScheme<'zal, C, Zal>, VerifierIPA<'params, 'zal, C, Zal>>
    for SingleStrategy<'params, 'zal, C, Zal>
    where Zal: MsmAccel<C>
{
    type Output = ();

    fn new(params: &'params ParamsIPA<'zal, C, Zal>) -> Self {
        SingleStrategy {
            msm: MSMIPA::new(params),
        }
    }

    fn process(
        self,
        f: impl FnOnce(MSMIPA<'params, 'zal, C, Zal>) -> Result<GuardIPA<'params, 'zal, C, Zal>, Error>,
    ) -> Result<Self::Output, Error> {
        let guard = f(self.msm)?;
        let msm = guard.use_challenges();
        if msm.check() {
            Ok(())
        } else {
            Err(Error::ConstraintSystemFailure)
        }
    }

    /// Finalizes the batch and checks its validity.
    ///
    /// Returns `false` if *some* proof was invalid. If the caller needs to identify
    /// specific failing proofs, it must re-process the proofs separately.
    #[must_use]
    fn finalize(self) -> bool {
        unreachable!()
    }
}

/// Computes the coefficients of $g(X) = \prod\limits_{i=0}^{k-1} (1 + u_{k - 1 - i} X^{2^i})$.
fn compute_s<F: Field>(u: &[F], init: F) -> Vec<F> {
    assert!(!u.is_empty());
    let mut v = vec![F::ZERO; 1 << u.len()];
    v[0] = init;

    for (len, u_j) in u.iter().rev().enumerate().map(|(i, u_j)| (1 << i, u_j)) {
        let (left, right) = v.split_at_mut(len);
        let right = &mut right[0..len];
        right.copy_from_slice(left);
        for v in right {
            *v *= u_j;
        }
    }

    v
}
