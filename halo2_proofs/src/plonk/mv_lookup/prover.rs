use super::super::{
    circuit::Expression, ChallengeBeta, ChallengeGamma, ChallengeTheta, ChallengeX, Error,
    ProvingKey,
};
use super::Argument;
use crate::plonk::evaluation::evaluate;
use crate::{
    arithmetic::{eval_polynomial, parallelize, CurveAffine, FieldExt},
    poly::{
        commitment::{Blind, Params},
        Coeff, EvaluationDomain, ExtendedLagrangeCoeff, LagrangeCoeff, Polynomial, ProverQuery,
        Rotation,
    },
    transcript::{EncodedChallenge, TranscriptWrite},
};
use blake2b_simd::Hash;
use group::{
    ff::{BatchInvert, Field},
    Curve,
};
use rand_core::RngCore;
use std::collections::{BTreeSet, HashSet};
use std::{any::TypeId, convert::TryInto, num::ParseIntError, ops::Index};
use std::{
    collections::BTreeMap,
    iter,
    ops::{Mul, MulAssign},
};

#[derive(Debug)]
pub(in crate::plonk) struct Prepared<C: CurveAffine> {
    compressed_input_expression: Polynomial<C::Scalar, LagrangeCoeff>,
    compressed_table_expression: Polynomial<C::Scalar, LagrangeCoeff>,
    m_values: Polynomial<C::Scalar, LagrangeCoeff>,
}

#[derive(Debug)]
pub(in crate::plonk) struct Committed<C: CurveAffine> {
    pub(in crate::plonk) m_poly: Polynomial<C::Scalar, Coeff>,
    pub(in crate::plonk) phi_poly: Polynomial<C::Scalar, Coeff>,
}

pub(in crate::plonk) struct Evaluated<C: CurveAffine> {
    constructed: Committed<C>,
}

impl<F: FieldExt> Argument<F> {
    pub(in crate::plonk) fn prepare<
        'a,
        'params: 'a,
        C,
        P: Params<'params, C>,
        E: EncodedChallenge<C>,
        R: RngCore,
        T: TranscriptWrite<C, E>,
    >(
        &self,
        pk: &ProvingKey<C>,
        params: &P,
        domain: &EvaluationDomain<C::Scalar>,
        theta: ChallengeTheta<C>,
        advice_values: &'a [Polynomial<C::Scalar, LagrangeCoeff>],
        fixed_values: &'a [Polynomial<C::Scalar, LagrangeCoeff>],
        instance_values: &'a [Polynomial<C::Scalar, LagrangeCoeff>],
        challenges: &'a [C::Scalar],
        mut rng: R, // in case we want to blind (do we actually need zk?)
        transcript: &mut T,
    ) -> Result<Prepared<C>, Error>
    where
        C: CurveAffine<ScalarExt = F>,
        C::Curve: Mul<F, Output = C::Curve> + MulAssign<F>,
    {
        // Closure to get values of expressions and compress them
        let compress_expressions = |expressions: &[Expression<C::Scalar>]| {
            let compressed_expression = expressions
                .iter()
                .map(|expression| {
                    pk.vk.domain.lagrange_from_vec(evaluate(
                        expression,
                        params.n() as usize,
                        1,
                        fixed_values,
                        advice_values,
                        instance_values,
                        challenges,
                    ))
                })
                .fold(domain.empty_lagrange(), |acc, expression| {
                    acc * *theta + &expression
                });
            compressed_expression
        };

        // Get values of input expressions involved in the lookup and compress them
        let compressed_input_expression = compress_expressions(&self.input_expressions);

        // Get values of table expressions involved in the lookup and compress them
        let compressed_table_expression = compress_expressions(&self.table_expressions);

        let blinding_factors = pk.vk.cs.blinding_factors();

        // compute m(X)
        let table_index_value_mapping: BTreeMap<C::Scalar, usize> = compressed_table_expression
            .iter()
            .take(params.n() as usize - blinding_factors - 1)
            .enumerate()
            .map(|(i, &x)| (x, i))
            .collect();

        let mut m_values = domain.empty_lagrange();

        compressed_input_expression
            .iter()
            .take(params.n() as usize - blinding_factors - 1)
            .for_each(|fi| {
                let index = table_index_value_mapping.get(fi).expect(&format!(
                    "in lookup: {}, value: {:?} not in table",
                    self.name, fi
                ));
                m_values[*index] += C::Scalar::one();
            });

        #[cfg(feature = "sanity-checks")]
        {
            // check that m is zero after blinders
            let invalid_ms = m_values
                .iter()
                .skip(params.n() as usize - blinding_factors)
                .collect::<Vec<_>>();
            assert_eq!(invalid_ms.len(), blinding_factors);
            for mi in invalid_ms {
                assert_eq!(*mi, C::Scalar::zero());
            }

            // check sums
            let alpha = C::Scalar::random(&mut rng);
            let mut lhs_sum = C::Scalar::zero();
            for &fi in compressed_input_expression
                .iter()
                .take(params.n() as usize - blinding_factors - 1)
            {
                lhs_sum += (fi + alpha).invert().unwrap();
            }

            let mut rhs_sum = C::Scalar::zero();
            for (&ti, &mi) in compressed_table_expression.iter().zip(m_values.iter()) {
                rhs_sum += mi * (ti + alpha).invert().unwrap();
            }

            assert_eq!(lhs_sum, rhs_sum);
        }

        // commit to m(X)
        let blind = Blind(C::Scalar::zero());
        let m_commitment = params.commit_lagrange(&m_values, blind).to_affine();

        // write commitment of m(X) to transcript
        transcript.write_point(m_commitment)?;

        Ok(Prepared {
            compressed_input_expression,
            compressed_table_expression,
            m_values,
        })
    }
}

impl<C: CurveAffine> Prepared<C> {
    pub(in crate::plonk) fn commit_grand_sum<
        'params,
        P: Params<'params, C>,
        E: EncodedChallenge<C>,
        R: RngCore,
        T: TranscriptWrite<C, E>,
    >(
        self,
        pk: &ProvingKey<C>,
        params: &P,
        beta: ChallengeBeta<C>,
        mut rng: R,
        transcript: &mut T,
    ) -> Result<Committed<C>, Error> {
        let mut input_log_derivatives = vec![C::Scalar::zero(); params.n() as usize];

        parallelize(
            &mut input_log_derivatives,
            |input_log_derivatives, start| {
                for (input_log_derivative, fi) in input_log_derivatives
                    .iter_mut()
                    .zip(self.compressed_input_expression[start..].iter())
                {
                    *input_log_derivative = *beta + fi;
                }
            },
        );
        input_log_derivatives.iter_mut().batch_invert();

        let mut table_log_derivatives = vec![C::Scalar::zero(); params.n() as usize];
        parallelize(
            &mut table_log_derivatives,
            |table_log_derivatives, start| {
                for (table_log_derivative, ti) in table_log_derivatives
                    .iter_mut()
                    .zip(self.compressed_table_expression[start..].iter())
                {
                    *table_log_derivative = *beta + ti;
                }
            },
        );
        table_log_derivatives.iter_mut().batch_invert();

        let mut log_derivatives_diff = vec![C::Scalar::zero(); params.n() as usize];
        parallelize(&mut log_derivatives_diff, |log_derivatives_diff, start| {
            for (((log_derivative_diff, fi), ti), mi) in log_derivatives_diff
                .iter_mut()
                .zip(input_log_derivatives[start..].iter())
                .zip(table_log_derivatives[start..].iter())
                .zip(self.m_values[start..].iter())
            {
                // (1/(f_i + α) - m(X) / (t(X) + α))
                *log_derivative_diff = *fi - *mi * *ti;
            }
        });

        // Compute the evaluations of the lookup grand sum polynomial
        // over our domain, starting with phi[0] = 0
        let blinding_factors = pk.vk.cs.blinding_factors();
        let phi = iter::once(C::Scalar::zero())
            .chain(log_derivatives_diff)
            .scan(C::Scalar::zero(), |state, cur| {
                *state += &cur;
                Some(*state)
            })
            // Take all rows including the "last" row which should
            // be a 0
            .take(params.n() as usize - blinding_factors)
            // Chain random blinding factors.
            .chain((0..blinding_factors).map(|_| C::Scalar::random(&mut rng)))
            .collect::<Vec<_>>();
        assert_eq!(phi.len(), params.n() as usize);
        let phi = pk.vk.domain.lagrange_from_vec(phi);

        #[cfg(feature = "sanity-checks")]
        // This test works only with intermediate representations in this method.
        // It can be used for debugging purposes.
        {
            // While in Lagrange basis, check that product is correctly constructed
            let u = (params.n() as usize) - (blinding_factors + 1);
            // q(X) = ((t(X) + α) * (f_i(X) + α) * (ϕ(gX) - ϕ(X)) - (t(X) + α) * (f_i + α) * (1/(f_i(X) + α) - m(X) / (t(X) + α))) mod zH(X)

            for i in 0..u {
                let lhs = {
                    // ((t(X) + α) * (f_i(X) + α) * (ϕ(gX) - ϕ(X))
                    (*beta + self.compressed_input_expression[i])
                        * (*beta + self.compressed_table_expression[i])
                        * (phi[i + 1] - phi[i])
                };

                let rhs = {
                    // (t(X) + α) * (f_i + α) * (1/(f_i(X) + α) - m(X) / (t(X) + α))
                    (*beta + self.compressed_input_expression[i])
                        * (*beta + self.compressed_table_expression[i])
                        * ((*beta + self.compressed_input_expression[i])
                            .invert()
                            .unwrap()
                            - self.m_values[i]
                                * (*beta + self.compressed_table_expression[i])
                                    .invert()
                                    .unwrap())
                };

                assert_eq!(lhs - rhs, C::Scalar::zero());
            }

            assert_eq!(phi[u], C::Scalar::zero());
        }

        let grand_sum_blind = Blind(C::Scalar::zero());
        let phi_commitment = params.commit_lagrange(&phi, grand_sum_blind).to_affine();

        // Hash grand sum commitment
        transcript.write_point(phi_commitment)?;

        Ok(Committed {
            m_poly: pk.vk.domain.lagrange_to_coeff(self.m_values),
            phi_poly: pk.vk.domain.lagrange_to_coeff(phi),
        })
    }
}

impl<C: CurveAffine> Committed<C> {
    pub(in crate::plonk) fn evaluate<E: EncodedChallenge<C>, T: TranscriptWrite<C, E>>(
        self,
        pk: &ProvingKey<C>,
        x: ChallengeX<C>,
        transcript: &mut T,
    ) -> Result<Evaluated<C>, Error> {
        let domain = &pk.vk.domain;
        let x_next = domain.rotate_omega(*x, Rotation::next());

        let phi_eval = eval_polynomial(&self.phi_poly, *x);
        let phi_next_eval = eval_polynomial(&self.phi_poly, x_next);
        let m_eval = eval_polynomial(&self.m_poly, *x);

        // Hash each advice evaluation
        for eval in iter::empty()
            .chain(Some(phi_eval))
            .chain(Some(phi_next_eval))
            .chain(Some(m_eval))
        {
            transcript.write_scalar(eval)?;
        }

        Ok(Evaluated { constructed: self })
    }
}

impl<C: CurveAffine> Evaluated<C> {
    pub(in crate::plonk) fn open<'a>(
        &'a self,
        pk: &'a ProvingKey<C>,
        x: ChallengeX<C>,
    ) -> impl Iterator<Item = ProverQuery<'a, C>> + Clone {
        let x_next = pk.vk.domain.rotate_omega(*x, Rotation::next());

        iter::empty()
            .chain(Some(ProverQuery {
                point: *x,
                poly: &self.constructed.phi_poly,
                blind: Blind(C::Scalar::zero()),
            }))
            .chain(Some(ProverQuery {
                point: x_next,
                poly: &self.constructed.phi_poly,
                blind: Blind(C::Scalar::zero()),
            }))
            .chain(Some(ProverQuery {
                point: *x,
                poly: &self.constructed.m_poly,
                blind: Blind(C::Scalar::zero()),
            }))
    }
}
