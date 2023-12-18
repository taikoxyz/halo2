use std::fmt::Debug;

use super::commitment::{KZGCommitmentScheme, ParamsKZG};
use crate::{
    arithmetic::{parallelize, CurveAffine},
    poly::commitment::MSM,
};
use group::{Curve, Group};
use halo2curves::{
    pairing::{Engine, MillerLoopResult, MultiMillerLoop},
    zal::MsmAccel,
};

/// A multiscalar multiplication in the polynomial commitment scheme
#[derive(Clone, Default, Debug)]
pub struct MSMKZG<'zal, E: Engine, Zal>
    where Zal: MsmAccel<E::G1Affine>
{
    pub(crate) engine: &'zal Zal,
    pub(crate) scalars: Vec<E::Scalar>,
    pub(crate) bases: Vec<E::G1>,
}

impl<'zal, E: Engine, Zal> MSMKZG<'zal, E, Zal>
    where Zal: MsmAccel<E::G1Affine>
{
    /// Create an empty MSM instance
    pub fn new(engine: &'zal Zal) -> Self {
        MSMKZG {
            engine,
            scalars: vec![],
            bases: vec![],
        }
    }

    /// Prepares all scalars in the MSM to linear combination
    pub fn combine_with_base(&mut self, base: E::Scalar) {
        use ff::Field;
        let mut acc = E::Scalar::ONE;
        if !self.scalars.is_empty() {
            for scalar in self.scalars.iter_mut().rev() {
                *scalar *= &acc;
                acc *= base;
            }
        }
    }
}

impl<'zal, E: Engine + Debug, Zal> MSM<'zal, E::G1Affine, Zal> for MSMKZG<'zal, E, Zal>
    where Zal: MsmAccel<E::G1Affine>
{
    fn append_term(&mut self, scalar: E::Scalar, point: E::G1) {
        self.scalars.push(scalar);
        self.bases.push(point);
    }

    fn add_msm(&mut self, other: &Self) {
        self.scalars.extend(other.scalars().iter());
        self.bases.extend(other.bases().iter());
    }

    fn scale(&mut self, factor: E::Scalar) {
        if !self.scalars.is_empty() {
            parallelize(&mut self.scalars, |scalars, _| {
                for other_scalar in scalars {
                    *other_scalar *= &factor;
                }
            })
        }
    }

    fn check(&self) -> bool {
        bool::from(self.eval().is_identity())
    }

    fn eval(&self) -> E::G1 {
        use group::prime::PrimeCurveAffine;
        let mut bases = vec![E::G1Affine::identity(); self.scalars.len()];
        E::G1::batch_normalize(&self.bases, &mut bases);
        self.engine.msm(&self.scalars, &bases)
    }

    fn bases(&self) -> Vec<E::G1> {
        self.bases.clone()
    }

    fn scalars(&self) -> Vec<E::Scalar> {
        self.scalars.clone()
    }
}

/// A projective point collector
#[derive(Debug, Clone)]
pub(crate) struct PreMSM<'zal, E: Engine, Zal>
    where Zal: MsmAccel<E::G1Affine>
{
    engine: &'zal Zal,
    projectives_msms: Vec<MSMKZG<'zal, E, Zal>>,
}

impl<'zal, E: Engine + Debug, Zal> PreMSM<'zal, E, Zal>
    where Zal: MsmAccel<E::G1Affine>
{
    pub(crate) fn new(engine: &'zal Zal) -> Self {
        PreMSM {
            engine,
            projectives_msms: vec![],
        }
    }

    pub(crate) fn normalize(self) -> MSMKZG<'zal, E, Zal> {
        use group::prime::PrimeCurveAffine;

        let (scalars, bases) = self
            .projectives_msms
            .into_iter()
            .map(|msm| (msm.scalars, msm.bases))
            .unzip::<_, _, Vec<_>, Vec<_>>();

        MSMKZG {
            engine: self.engine,
            scalars: scalars.into_iter().flatten().collect(),
            bases: bases.into_iter().flatten().collect(),
        }
    }

    pub(crate) fn add_msm(&mut self, other: MSMKZG<'zal, E, Zal>) {
        self.projectives_msms.push(other);
    }
}

impl<'params, 'zal, E: MultiMillerLoop + Debug, Zal> From<&'params ParamsKZG<'zal, E, Zal>> for DualMSM<'params, 'zal, E, Zal>
    where Zal: MsmAccel<E::G1Affine>
{
    fn from(params: &'params ParamsKZG<E, Zal>) -> Self {
        DualMSM::new(params)
    }
}

/// Two channel MSM accumulator
#[derive(Debug, Clone)]
pub struct DualMSM<'a, 'zal, E: Engine, Zal>
    where Zal: MsmAccel<E::G1Affine>
{
    pub(crate) params: &'a ParamsKZG<'zal, E, Zal>,
    pub(crate) left: MSMKZG<'zal, E, Zal>,
    pub(crate) right: MSMKZG<'zal, E, Zal>,
}

impl<'a, 'zal, E: MultiMillerLoop + Debug, Zal> DualMSM<'a, 'zal, E, Zal>
    where Zal: MsmAccel<E::G1Affine>
{
    /// Create a new two channel MSM accumulator instance
    pub fn new(params: &'a ParamsKZG<'zal, E, Zal>) -> Self {
        Self {
            params,
            left: MSMKZG::new(params.engine),
            right: MSMKZG::new(params.engine),
        }
    }

    /// Scale all scalars in the MSM by some scaling factor
    pub fn scale(&mut self, e: E::Scalar) {
        self.left.scale(e);
        self.right.scale(e);
    }

    /// Add another multiexp into this one
    pub fn add_msm(&mut self, other: Self) {
        self.left.add_msm(&other.left);
        self.right.add_msm(&other.right);
    }

    /// Performs final pairing check with given verifier params and two channel linear combination
    pub fn check(self) -> bool {
        let s_g2_prepared = E::G2Prepared::from(self.params.s_g2);
        let n_g2_prepared = E::G2Prepared::from(-self.params.g2);

        let left = self.left.eval();
        let right = self.right.eval();

        let (term_1, term_2) = (
            (&left.into(), &s_g2_prepared),
            (&right.into(), &n_g2_prepared),
        );
        let terms = &[term_1, term_2];

        bool::from(
            E::multi_miller_loop(&terms[..])
                .final_exponentiation()
                .is_identity(),
        )
    }
}
