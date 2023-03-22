use std::iter;

use super::super::{
    circuit::Expression, ChallengeBeta, ChallengeGamma, ChallengeTheta, ChallengeX,
};
use super::Argument;
use crate::{
    arithmetic::{CurveAffine, FieldExt},
    plonk::{Error, VerifyingKey},
    poly::{commitment::MSM, Rotation, VerifierQuery},
    transcript::{EncodedChallenge, TranscriptRead},
};
use ff::Field;

pub struct PreparedCommitments<C: CurveAffine> {
    m_commitment: C,
}

pub struct Committed<C: CurveAffine> {
    prepared: PreparedCommitments<C>,
    phi_commitment: C,
}

pub struct Evaluated<C: CurveAffine> {
    committed: Committed<C>,
    phi_eval: C::Scalar,
    phi_next_eval: C::Scalar,
    m_eval: C::Scalar,
}

impl<F: FieldExt> Argument<F> {
    pub(in crate::plonk) fn read_prepared_commitments<
        C: CurveAffine,
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    >(
        &self,
        transcript: &mut T,
    ) -> Result<PreparedCommitments<C>, Error> {
        let m_commitment = transcript.read_point()?;

        Ok(PreparedCommitments {
            m_commitment,
        })
    }
}

impl<C: CurveAffine> PreparedCommitments<C> {
    pub(in crate::plonk) fn read_grand_sum_commitment<
        E: EncodedChallenge<C>,
        T: TranscriptRead<C, E>,
    >(
        self,
        transcript: &mut T,
    ) -> Result<Committed<C>, Error> {
        let phi_commitment = transcript.read_point()?;
        println!("verifier phi_commitment: {:?}", phi_commitment);

        Ok(Committed {
            prepared: self,
            phi_commitment,
        })
    }
}

impl<C: CurveAffine> Committed<C> {
    pub(crate) fn evaluate<E: EncodedChallenge<C>, T: TranscriptRead<C, E>>(
        self,
        transcript: &mut T,
    ) -> Result<Evaluated<C>, Error> {
        let phi_eval = transcript.read_scalar()?;
        let phi_next_eval = transcript.read_scalar()?;
        let m_eval = transcript.read_scalar()?;

        Ok(Evaluated {
            committed: self,
            phi_eval,
            phi_next_eval,
            m_eval,
        })
    }
}

impl<C: CurveAffine> Evaluated<C> {
    pub(in crate::plonk) fn expressions<'a>(
        &'a self,
        l_0: C::Scalar,
        l_last: C::Scalar,
        l_blind: C::Scalar,
        argument: &'a Argument<C::Scalar>,
        theta: ChallengeTheta<C>,
        beta: ChallengeBeta<C>,
        advice_evals: &[C::Scalar],
        fixed_evals: &[C::Scalar],
        instance_evals: &[C::Scalar],
        challenges: &[C::Scalar],
    ) -> impl Iterator<Item = C::Scalar> + 'a {
        let active_rows = C::Scalar::one() - (l_last + l_blind);

        let grand_sum_expression = || {
            let compress_expressions = |expressions: &[Expression<C::Scalar>]| {
                expressions
                    .iter()
                    .map(|expression| {
                        expression.evaluate(
                            &|scalar| scalar,
                            &|_| panic!("virtual selectors are removed during optimization"),
                            &|query| fixed_evals[query.index],
                            &|query| advice_evals[query.index],
                            &|query| instance_evals[query.index],
                            &|challenge| challenges[challenge.index()],
                            &|a| -a,
                            &|a, b| a + &b,
                            &|a, b| a * &b,
                            &|a, scalar| a * &scalar,
                        )
                    })
                    .fold(C::Scalar::zero(), |acc, eval| acc * &*theta + &eval)
            };

            let f_eval = compress_expressions(&argument.input_expressions);
            let t_eval = compress_expressions(&argument.table_expressions);

            let tau = t_eval + *beta;
            let fi = f_eval + *beta;

            let lhs = tau * fi * (self.phi_next_eval - self.phi_eval);

            let rhs = {
                tau * fi * (fi.invert().unwrap() - self.m_eval * tau.invert().unwrap())
            };

            (lhs - rhs) * active_rows

            // // phi[0] = 0 works
            // l_0 * self.phi_eval

            // // phi[u] = 0 works
            // l_last * self.phi_eval
        };

        iter::once(grand_sum_expression())
    }

    pub(in crate::plonk) fn queries<'r, M: MSM<C> + 'r>(
        &'r self,
        vk: &'r VerifyingKey<C>,
        x: ChallengeX<C>,
    ) -> impl Iterator<Item = VerifierQuery<'r, C, M>> + Clone {
        let x_next = vk.domain.rotate_omega(*x, Rotation::next());

        iter::empty()
            .chain(Some(VerifierQuery::new_commitment(
                &self.committed.phi_commitment,
                *x,
                self.phi_eval,
            )))
            .chain(Some(VerifierQuery::new_commitment(
                &self.committed.phi_commitment,
                x_next,
                self.phi_next_eval,
            )))
            .chain(Some(VerifierQuery::new_commitment(
                &self.committed.prepared.m_commitment,
                *x,
                self.m_eval,
            )))
    }
}
