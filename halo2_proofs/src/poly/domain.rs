//! Contains utilities for performing polynomial arithmetic over an evaluation
//! domain that is of a suitable size for the application.

use crate::{
    arithmetic::{best_fft, parallelize, parallelize_count, Field as FieldExt},
    multicore,
    plonk::{get_duration, get_time, start_measure, stop_measure, Assigned},
};

use super::{Coeff, ExtendedLagrangeCoeff, LagrangeCoeff, Polynomial, Rotation};
use ff::WithSmallOrderMulGroup;
use group::{
    ff::{BatchInvert, Field, PrimeField},
    Group,
};

use std::{env::var, marker::PhantomData};

/// TEMP
pub static mut FFT_TOTAL_TIME: usize = 0;

fn get_fft_mode() -> usize {
    var("FFT_MODE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("Cannot parse FFT_MODE env var as usize")
}

/// FFTStage
#[derive(Clone, Debug)]
pub struct FFTStage {
    radix: usize,
    length: usize,
}

/// FFT stages
pub fn get_stages(size: usize, radixes: Vec<usize>) -> Vec<FFTStage> {
    let mut stages: Vec<FFTStage> = vec![];

    let mut n = size;

    // Use the specified radices
    for &radix in &radixes {
        n /= radix;
        stages.push(FFTStage { radix, length: n });
    }

    // Fill in the rest of the tree if needed
    let mut p = 2;
    while n > 1 {
        while n % p != 0 {
            if p == 4 {
                p = 2;
            }
        }
        n /= p;
        stages.push(FFTStage {
            radix: p,
            length: n,
        });
    }

    /*for i in 0..stages.len() {
        println!("Stage {}: {}, {}", i, stages[i].radix, stages[i].length);
    }*/

    stages
}

/// FFTData
#[derive(Clone, Debug)]
struct FFTData<F: FieldExt> {
    n: usize,

    stages: Vec<FFTStage>,

    f_twiddles: Vec<Vec<F>>,
    inv_twiddles: Vec<Vec<F>>,
    //scratch: Vec<F>,
}

impl<F: FieldExt> FFTData<F> {
    /// Create FFT data
    pub fn new(n: usize, omega: F, omega_inv: F) -> Self {
        let stages = get_stages(n as usize, vec![]);
        let mut f_twiddles = vec![];
        let mut inv_twiddles = vec![];
        let mut scratch = vec![F::ZERO; n];

        // Generate stage twiddles
        for inv in 0..2 {
            let inverse = inv == 0;
            let o = if inverse { omega_inv } else { omega };
            let stage_twiddles = if inverse {
                &mut inv_twiddles
            } else {
                &mut f_twiddles
            };

            let twiddles = &mut scratch;

            // Twiddles
            parallelize(twiddles, |twiddles, start| {
                let w_m = o;
                let mut w = o.pow_vartime(&[start as u64, 0, 0, 0]);
                for value in twiddles.iter_mut() {
                    *value = w;
                    w *= w_m;
                }
            });

            // Re-order twiddles for cache friendliness
            let num_stages = stages.len();
            stage_twiddles.resize(num_stages, vec![]);
            for l in 0..num_stages {
                let radix = stages[l].radix;
                let stage_length = stages[l].length;

                let num_twiddles = stage_length * (radix - 1);
                stage_twiddles[l].resize(num_twiddles + 1, F::ZERO);

                // Set j
                stage_twiddles[l][num_twiddles] = twiddles[(twiddles.len() * 3) / 4];

                let stride = n / (stage_length * radix);
                let mut tws = vec![0usize; radix - 1];
                for i in 0..stage_length {
                    for j in 0..radix - 1 {
                        stage_twiddles[l][i * (radix - 1) + j] = twiddles[tws[j]];
                        tws[j] += (j + 1) * stride;
                    }
                }
            }
        }

        Self {
            n,
            stages,
            f_twiddles,
            inv_twiddles,
            //scratch,
        }
    }
}

/// Radix 2 butterfly
pub fn butterfly_2<F: FieldExt>(out: &mut [F], twiddles: &[F], stage_length: usize) {
    let mut out_offset = 0;
    let mut out_offset2 = stage_length;

    let t = out[out_offset2];
    out[out_offset2] = out[out_offset] - t;
    out[out_offset] += t;
    out_offset2 += 1;
    out_offset += 1;

    for twiddle in twiddles[1..stage_length].iter() {
        let t = *twiddle * out[out_offset2];
        out[out_offset2] = out[out_offset] - t;
        out[out_offset] += t;
        out_offset2 += 1;
        out_offset += 1;
    }
}

/// Radix 2 butterfly
fn butterfly_2_parallel<F: FieldExt>(
    out: &mut [F],
    twiddles: &[F],
    _stage_length: usize,
    num_threads: usize,
) {
    let n = out.len();
    let mut chunk = (n as usize) / num_threads;
    if chunk < num_threads {
        chunk = n as usize;
    }

    multicore::scope(|scope| {
        let (part_a, part_b) = out.split_at_mut(n / 2);
        for (i, (part0, part1)) in part_a
            .chunks_mut(chunk)
            .zip(part_b.chunks_mut(chunk))
            .enumerate()
        {
            scope.spawn(move |_| {
                let offset = i * chunk;
                for k in 0..part0.len() {
                    let t = twiddles[offset + k] * part1[k];
                    part1[k] = part0[k] - t;
                    part0[k] += t;
                }
            });
        }
    });
}

/// Radix 4 butterfly
pub fn butterfly_4<F: FieldExt>(out: &mut [F], twiddles: &[F], stage_length: usize) {
    let j = twiddles[twiddles.len() - 1];
    let mut tw = 0;

    /* Case twiddle == one */
    {
        let i0 = 0;
        let i1 = stage_length;
        let i2 = stage_length * 2;
        let i3 = stage_length * 3;

        let z0 = out[i0];
        let z1 = out[i1];
        let z2 = out[i2];
        let z3 = out[i3];

        let t1 = z0 + z2;
        let t2 = z1 + z3;
        let t3 = z0 - z2;
        let t4j = j * (z1 - z3);

        out[i0] = t1 + t2;
        out[i1] = t3 - t4j;
        out[i2] = t1 - t2;
        out[i3] = t3 + t4j;

        tw += 3;
    }

    for k in 1..stage_length {
        let i0 = k;
        let i1 = k + stage_length;
        let i2 = k + stage_length * 2;
        let i3 = k + stage_length * 3;

        let z0 = out[i0];
        let z1 = out[i1] * twiddles[tw];
        let z2 = out[i2] * twiddles[tw + 1];
        let z3 = out[i3] * twiddles[tw + 2];

        let t1 = z0 + z2;
        let t2 = z1 + z3;
        let t3 = z0 - z2;
        let t4j = j * (z1 - z3);

        out[i0] = t1 + t2;
        out[i1] = t3 - t4j;
        out[i2] = t1 - t2;
        out[i3] = t3 + t4j;

        tw += 3;
    }
}

/// Radix 4 butterfly
pub fn butterfly_4_parallel<F: FieldExt>(
    out: &mut [F],
    twiddles: &[F],
    _stage_length: usize,
    num_threads: usize,
) {
    let j = twiddles[twiddles.len() - 1];

    let n = out.len();
    let mut chunk = (n as usize) / num_threads;
    if chunk < num_threads {
        chunk = n as usize;
    }
    multicore::scope(|scope| {
        //let mut parts: Vec<&mut [F]> = out.chunks_mut(4).collect();
        //out.chunks_mut(4).map(|c| c.chunks_mut(chunk)).fold(predicate)
        let (part_a, part_b) = out.split_at_mut(n / 2);
        let (part_aa, part_ab) = part_a.split_at_mut(n / 4);
        let (part_ba, part_bb) = part_b.split_at_mut(n / 4);
        for (i, (((part0, part1), part2), part3)) in part_aa
            .chunks_mut(chunk)
            .zip(part_ab.chunks_mut(chunk))
            .zip(part_ba.chunks_mut(chunk))
            .zip(part_bb.chunks_mut(chunk))
            .enumerate()
        {
            scope.spawn(move |_| {
                let offset = i * chunk;
                let mut tw = offset * 3;
                for k in 0..part1.len() {
                    let z0 = part0[k];
                    let z1 = part1[k] * twiddles[tw];
                    let z2 = part2[k] * twiddles[tw + 1];
                    let z3 = part3[k] * twiddles[tw + 2];

                    let t1 = z0 + z2;
                    let t2 = z1 + z3;
                    let t3 = z0 - z2;
                    let t4j = j * (z1 - z3);

                    part0[k] = t1 + t2;
                    part1[k] = t3 - t4j;
                    part2[k] = t1 - t2;
                    part3[k] = t3 + t4j;

                    tw += 3;
                }
            });
        }
    });
}

/// Inner recursion
fn recursive_fft_inner<F: FieldExt>(
    data_in: &[F],
    data_out: &mut [F],
    twiddles: &Vec<Vec<F>>,
    stages: &Vec<FFTStage>,
    in_offset: usize,
    stride: usize,
    level: usize,
    num_threads: usize,
) {
    let radix = stages[level].radix;
    let stage_length = stages[level].length;

    if num_threads > 1 {
        if stage_length == 1 {
            for i in 0..radix {
                data_out[i] = data_in[in_offset + i * stride];
            }
        } else {
            let num_threads_recursive = if num_threads >= radix {
                radix
            } else {
                num_threads
            };
            parallelize_count(data_out, num_threads_recursive, |data_out, i| {
                let num_threads_in_recursion = if num_threads < radix {
                    1
                } else {
                    (num_threads + i) / radix
                };
                recursive_fft_inner(
                    data_in,
                    data_out,
                    twiddles,
                    stages,
                    in_offset + i * stride,
                    stride * radix,
                    level + 1,
                    num_threads_in_recursion,
                )
            });
        }
        match radix {
            2 => butterfly_2_parallel(data_out, &twiddles[level], stage_length, num_threads),
            4 => butterfly_4_parallel(data_out, &twiddles[level], stage_length, num_threads),
            _ => unimplemented!("radix unsupported"),
        }
    } else {
        if stage_length == 1 {
            for i in 0..radix {
                data_out[i] = data_in[in_offset + i * stride];
            }
        } else {
            for i in 0..radix {
                recursive_fft_inner(
                    data_in,
                    &mut data_out[i * stage_length..(i + 1) * stage_length],
                    twiddles,
                    stages,
                    in_offset + i * stride,
                    stride * radix,
                    level + 1,
                    num_threads,
                );
            }
        }
        match radix {
            2 => butterfly_2(data_out, &twiddles[level], stage_length),
            4 => butterfly_4(data_out, &twiddles[level], stage_length),
            _ => unimplemented!("radix unsupported"),
        }
    }
}

fn recursive_fft<F: FieldExt>(data: &FFTData<F>, data_in: &mut Vec<F>, inverse: bool) {
    let num_threads = multicore::current_num_threads();
    //let start = start_measure(format!("recursive fft {} ({})", data_in.len(), num_threads), false);

    // TODO: reuse scratch buffer between FFTs
    //let start_mem = start_measure(format!("alloc"), false);
    let mut scratch = vec![F::ZERO; data_in.len()];
    //stop_measure(start_mem);

    recursive_fft_inner(
        data_in,
        &mut /*data.*/scratch,
        if inverse {
            &data.inv_twiddles
        } else {
            &data.f_twiddles
        },
        &data.stages,
        0,
        1,
        0,
        num_threads,
    );
    //let duration = stop_measure(start);

    //let start = start_measure(format!("copy"), false);
    // Will simply swap the vector's buffer, no data is actually copied
    std::mem::swap(data_in, &mut /*data.*/scratch);
    //stop_measure(start);
}

/// This structure contains precomputed constants and other details needed for
/// performing operations on an evaluation domain of size $2^k$ and an extended
/// domain of size $2^{k} * j$ with $j \neq 0$.
#[derive(Clone, Debug)]
pub struct EvaluationDomain<F: Field> {
    n: u64,
    k: u32,
    extended_k: u32,
    omega: F,
    omega_inv: F,
    extended_omega: F,
    extended_omega_inv: F,
    g_coset: F,
    g_coset_inv: F,
    quotient_poly_degree: u64,
    ifft_divisor: F,
    extended_ifft_divisor: F,
    t_evaluations: Vec<F>,
    barycentric_weight: F,

    // Recursive stuff
    fft_data: FFTData<F>,
    extended_fft_data: FFTData<F>,
}

impl<F: WithSmallOrderMulGroup<3>> EvaluationDomain<F> {
    /// This constructs a new evaluation domain object based on the provided
    /// values $j, k$.
    pub fn new(j: u32, k: u32) -> Self {
        // quotient_poly_degree * params.n - 1 is the degree of the quotient polynomial
        let quotient_poly_degree = (j - 1) as u64;

        // n = 2^k
        let n = 1u64 << k;

        // We need to work within an extended domain, not params.k but params.k + i
        // for some integer i such that 2^(params.k + i) is sufficiently large to
        // describe the quotient polynomial.
        let mut extended_k = k;
        while (1 << extended_k) < (n * quotient_poly_degree) {
            extended_k += 1;
        }
        println!("k: {}, extended_k: {}", k, extended_k);

        let mut extended_omega = F::ROOT_OF_UNITY;

        // Get extended_omega, the 2^{extended_k}'th root of unity
        // The loop computes extended_omega = omega^{2 ^ (S - extended_k)}
        // Notice that extended_omega ^ {2 ^ extended_k} = omega ^ {2^S} = 1.
        for _ in extended_k..F::S {
            extended_omega = extended_omega.square();
        }
        let extended_omega = extended_omega;
        let mut extended_omega_inv = extended_omega; // Inversion computed later

        // Get omega, the 2^{k}'th root of unity (i.e. n'th root of unity)
        // The loop computes omega = extended_omega ^ {2 ^ (extended_k - k)}
        //           = (omega^{2 ^ (S - extended_k)})  ^ {2 ^ (extended_k - k)}
        //           = omega ^ {2 ^ (S - k)}.
        // Notice that omega ^ {2^k} = omega ^ {2^S} = 1.
        let mut omega = extended_omega;
        for _ in k..extended_k {
            omega = omega.square();
        }
        let omega = omega;
        let mut omega_inv = omega; // Inversion computed later

        // We use zeta here because we know it generates a coset, and it's available
        // already.
        // The coset evaluation domain is:
        // zeta {1, extended_omega, extended_omega^2, ..., extended_omega^{(2^extended_k) - 1}}
        let g_coset = F::ZETA;
        let g_coset_inv = g_coset.square();

        let mut t_evaluations = Vec::with_capacity(1 << (extended_k - k));
        {
            // Compute the evaluations of t(X) = X^n - 1 in the coset evaluation domain.
            // We don't have to compute all of them, because it will repeat.
            let orig = F::ZETA.pow_vartime(&[n as u64, 0, 0, 0]);
            let step = extended_omega.pow_vartime(&[n as u64, 0, 0, 0]);
            let mut cur = orig;
            loop {
                t_evaluations.push(cur);
                cur *= &step;
                if cur == orig {
                    break;
                }
            }
            assert_eq!(t_evaluations.len(), 1 << (extended_k - k));

            // Subtract 1 from each to give us t_evaluations[i] = t(zeta * extended_omega^i)
            for coeff in &mut t_evaluations {
                *coeff -= &F::ONE;
            }

            // Invert, because we're dividing by this polynomial.
            // We invert in a batch, below.
        }

        let mut ifft_divisor = F::from(1 << k); // Inversion computed later
        let mut extended_ifft_divisor = F::from(1 << extended_k); // Inversion computed later

        // The barycentric weight of 1 over the evaluation domain
        // 1 / \prod_{i != 0} (1 - omega^i)
        let mut barycentric_weight = F::from(n); // Inversion computed later

        // Compute batch inversion
        t_evaluations
            .iter_mut()
            .chain(Some(&mut ifft_divisor))
            .chain(Some(&mut extended_ifft_divisor))
            .chain(Some(&mut barycentric_weight))
            .chain(Some(&mut extended_omega_inv))
            .chain(Some(&mut omega_inv))
            .batch_invert();

        EvaluationDomain {
            n,
            k,
            extended_k,
            omega,
            omega_inv,
            extended_omega,
            extended_omega_inv,
            g_coset,
            g_coset_inv,
            quotient_poly_degree,
            ifft_divisor,
            extended_ifft_divisor,
            t_evaluations,
            barycentric_weight,
            fft_data: FFTData::<F>::new(n as usize, omega, omega_inv),
            extended_fft_data: FFTData::<F>::new(
                (1 << extended_k) as usize,
                extended_omega,
                extended_omega_inv,
            ),
        }
    }

    /// Obtains a polynomial in Lagrange form when given a vector of Lagrange
    /// coefficients of size `n`; panics if the provided vector is the wrong
    /// length.
    pub fn lagrange_from_vec(&self, values: Vec<F>) -> Polynomial<F, LagrangeCoeff> {
        assert_eq!(values.len(), self.n as usize);

        Polynomial {
            values,
            _marker: PhantomData,
        }
    }

    /// Obtains a polynomial in coefficient form when given a vector of
    /// coefficients of size `n`; panics if the provided vector is the wrong
    /// length.
    pub fn coeff_from_vec(&self, values: Vec<F>) -> Polynomial<F, Coeff> {
        assert_eq!(values.len(), self.n as usize);

        Polynomial {
            values,
            _marker: PhantomData,
        }
    }

    /// Returns an empty (zero) polynomial in the coefficient basis
    pub fn empty_coeff(&self) -> Polynomial<F, Coeff> {
        Polynomial {
            values: vec![F::ZERO; self.n as usize],
            _marker: PhantomData,
        }
    }

    /// Returns an empty (zero) polynomial in the Lagrange coefficient basis
    pub fn empty_lagrange(&self) -> Polynomial<F, LagrangeCoeff> {
        Polynomial {
            values: vec![F::ZERO; self.n as usize],
            _marker: PhantomData,
        }
    }

    /// Returns an empty (zero) polynomial in the Lagrange coefficient basis, with
    /// deferred inversions.
    pub(crate) fn empty_lagrange_assigned(&self) -> Polynomial<Assigned<F>, LagrangeCoeff> {
        Polynomial {
            values: vec![F::ZERO.into(); self.n as usize],
            _marker: PhantomData,
        }
    }

    /// Returns a constant polynomial in the Lagrange coefficient basis
    pub fn constant_lagrange(&self, scalar: F) -> Polynomial<F, LagrangeCoeff> {
        Polynomial {
            values: vec![scalar; self.n as usize],
            _marker: PhantomData,
        }
    }

    /// Returns an empty (zero) polynomial in the extended Lagrange coefficient
    /// basis
    pub fn empty_extended(&self) -> Polynomial<F, ExtendedLagrangeCoeff> {
        Polynomial {
            values: vec![F::ZERO; self.extended_len()],
            _marker: PhantomData,
        }
    }

    /// Returns a constant polynomial in the extended Lagrange coefficient
    /// basis
    pub fn constant_extended(&self, scalar: F) -> Polynomial<F, ExtendedLagrangeCoeff> {
        Polynomial {
            values: vec![scalar; self.extended_len()],
            _marker: PhantomData,
        }
    }

    /// This takes us from an n-length vector into the coefficient form.
    ///
    /// This function will panic if the provided vector is not the correct
    /// length.
    pub fn lagrange_to_coeff(&self, mut a: Polynomial<F, LagrangeCoeff>) -> Polynomial<F, Coeff> {
        assert_eq!(a.values.len(), 1 << self.k);

        // Perform inverse FFT to obtain the polynomial in coefficient form
        self.ifft(&mut a.values, self.omega_inv, self.k, self.ifft_divisor);

        Polynomial {
            values: a.values,
            _marker: PhantomData,
        }
    }

    /// This takes us from an n-length coefficient vector into a coset of the extended
    /// evaluation domain, rotating by `rotation` if desired.
    pub fn coeff_to_extended(
        &self,
        mut a: Polynomial<F, Coeff>,
    ) -> Polynomial<F, ExtendedLagrangeCoeff> {
        assert_eq!(a.values.len(), 1 << self.k);

        self.distribute_powers_zeta(&mut a.values, true);
        a.values.resize(self.extended_len(), F::ZERO);
        best_fft(&mut a.values, self.extended_omega, self.extended_k);

        Polynomial {
            values: a.to_vec(),
            _marker: PhantomData,
        }
    }

    /// Rotate the extended domain polynomial over the original domain.
    pub fn rotate_extended(
        &self,
        poly: &Polynomial<F, ExtendedLagrangeCoeff>,
        rotation: Rotation,
    ) -> Polynomial<F, ExtendedLagrangeCoeff> {
        let new_rotation = ((1 << (self.extended_k - self.k)) * rotation.0.abs()) as usize;

        let mut poly = poly.clone();

        if rotation.0 >= 0 {
            poly.values.rotate_left(new_rotation);
        } else {
            poly.values.rotate_right(new_rotation);
        }

        poly
    }

    /// This takes us from the extended evaluation domain and gets us the
    /// quotient polynomial coefficients.
    ///
    /// This function will panic if the provided vector is not the correct
    /// length.
    // TODO/FIXME: caller should be responsible for truncating
    pub fn extended_to_coeff(&self, mut a: Polynomial<F, ExtendedLagrangeCoeff>) -> Vec<F> {
        assert_eq!(a.values.len(), self.extended_len());

        // Inverse FFT
        self.ifft(
            &mut a.values,
            self.extended_omega_inv,
            self.extended_k,
            self.extended_ifft_divisor,
        );

        // Distribute powers to move from coset; opposite from the
        // transformation we performed earlier.
        self.distribute_powers_zeta(&mut a.values, false);

        // Truncate it to match the size of the quotient polynomial; the
        // evaluation domain might be slightly larger than necessary because
        // it always lies on a power-of-two boundary.
        a.values
            .truncate((&self.n * self.quotient_poly_degree) as usize);

        a.values
    }

    /// This divides the polynomial (in the extended domain) by the vanishing
    /// polynomial of the $2^k$ size domain.
    pub fn divide_by_vanishing_poly(
        &self,
        mut a: Polynomial<F, ExtendedLagrangeCoeff>,
    ) -> Polynomial<F, ExtendedLagrangeCoeff> {
        assert_eq!(a.values.len(), self.extended_len());

        // Divide to obtain the quotient polynomial in the coset evaluation
        // domain.
        parallelize(&mut a.values, |h, mut index| {
            for h in h {
                *h *= &self.t_evaluations[index % self.t_evaluations.len()];
                index += 1;
            }
        });

        Polynomial {
            values: a.values,
            _marker: PhantomData,
        }
    }

    /// Given a slice of group elements `[a_0, a_1, a_2, ...]`, this returns
    /// `[a_0, [zeta]a_1, [zeta^2]a_2, a_3, [zeta]a_4, [zeta^2]a_5, a_6, ...]`,
    /// where zeta is a cube root of unity in the multiplicative subgroup with
    /// order (p - 1), i.e. zeta^3 = 1.
    ///
    /// `into_coset` should be set to `true` when moving into the coset,
    /// and `false` when moving out. This toggles the choice of `zeta`.
    fn distribute_powers_zeta(&self, a: &mut [F], into_coset: bool) {
        let coset_powers = if into_coset {
            [self.g_coset, self.g_coset_inv]
        } else {
            [self.g_coset_inv, self.g_coset]
        };
        parallelize(a, |a, mut index| {
            for a in a {
                // Distribute powers to move into/from coset
                let i = index % (coset_powers.len() + 1);
                if i != 0 {
                    *a *= &coset_powers[i - 1];
                }
                index += 1;
            }
        });
    }

    fn ifft(&self, a: &mut Vec<F>, omega_inv: F, log_n: u32, divisor: F) {
        self.fft_inner(a, omega_inv, log_n, true);
        parallelize(a, |a, _| {
            for a in a {
                // Finish iFFT
                *a *= &divisor;
            }
        });
    }

    fn fft_inner(&self, a: &mut Vec<F>, omega: F, log_n: u32, inverse: bool) {
        let start = get_time();
        if get_fft_mode() == 1 {
            let fft_data = if a.len() == self.fft_data.n {
                &self.fft_data
            } else {
                &self.extended_fft_data
            };
            recursive_fft(fft_data, a, inverse);
        } else {
            best_fft(a, omega, log_n);
        }
        let duration = get_duration(start);

        #[allow(unsafe_code)]
        unsafe {
            FFT_TOTAL_TIME += duration;
        }
    }

    /// Get the size of the domain
    pub fn k(&self) -> u32 {
        self.k
    }

    /// Get the size of the extended domain
    pub fn extended_k(&self) -> u32 {
        self.extended_k
    }

    /// Get the size of the extended domain
    pub fn extended_len(&self) -> usize {
        1 << self.extended_k
    }

    /// Get $\omega$, the generator of the $2^k$ order multiplicative subgroup.
    pub fn get_omega(&self) -> F {
        self.omega
    }

    /// Get $\omega^{-1}$, the inverse of the generator of the $2^k$ order
    /// multiplicative subgroup.
    pub fn get_omega_inv(&self) -> F {
        self.omega_inv
    }

    /// Get the generator of the extended domain's multiplicative subgroup.
    pub fn get_extended_omega(&self) -> F {
        self.extended_omega
    }

    /// Multiplies a value by some power of $\omega$, essentially rotating over
    /// the domain.
    pub fn rotate_omega(&self, value: F, rotation: Rotation) -> F {
        let mut point = value;
        if rotation.0 >= 0 {
            point *= &self.get_omega().pow_vartime(&[rotation.0 as u64]);
        } else {
            point *= &self
                .get_omega_inv()
                .pow_vartime(&[(rotation.0 as i64).unsigned_abs()]);
        }
        point
    }

    /// Computes evaluations (at the point `x`, where `xn = x^n`) of Lagrange
    /// basis polynomials `l_i(X)` defined such that `l_i(omega^i) = 1` and
    /// `l_i(omega^j) = 0` for all `j != i` at each provided rotation `i`.
    ///
    /// # Implementation
    ///
    /// The polynomial
    ///     $$\prod_{j=0,j \neq i}^{n - 1} (X - \omega^j)$$
    /// has a root at all points in the domain except $\omega^i$, where it evaluates to
    ///     $$\prod_{j=0,j \neq i}^{n - 1} (\omega^i - \omega^j)$$
    /// and so we divide that polynomial by this value to obtain $l_i(X)$. Since
    ///     $$\prod_{j=0,j \neq i}^{n - 1} (X - \omega^j)
    ///       = \frac{X^n - 1}{X - \omega^i}$$
    /// then $l_i(x)$ for some $x$ is evaluated as
    ///     $$\left(\frac{x^n - 1}{x - \omega^i}\right)
    ///       \cdot \left(\frac{1}{\prod_{j=0,j \neq i}^{n - 1} (\omega^i - \omega^j)}\right).$$
    /// We refer to
    ///     $$1 \over \prod_{j=0,j \neq i}^{n - 1} (\omega^i - \omega^j)$$
    /// as the barycentric weight of $\omega^i$.
    ///
    /// We know that for $i = 0$
    ///     $$\frac{1}{\prod_{j=0,j \neq i}^{n - 1} (\omega^i - \omega^j)} = \frac{1}{n}.$$
    ///
    /// If we multiply $(1 / n)$ by $\omega^i$ then we obtain
    ///     $$\frac{1}{\prod_{j=0,j \neq 0}^{n - 1} (\omega^i - \omega^j)}
    ///       = \frac{1}{\prod_{j=0,j \neq i}^{n - 1} (\omega^i - \omega^j)}$$
    /// which is the barycentric weight of $\omega^i$.
    pub fn l_i_range<I: IntoIterator<Item = i32> + Clone>(
        &self,
        x: F,
        xn: F,
        rotations: I,
    ) -> Vec<F> {
        let mut results;
        {
            let rotations = rotations.clone().into_iter();
            results = Vec::with_capacity(rotations.size_hint().1.unwrap_or(0));
            for rotation in rotations {
                let rotation = Rotation(rotation);
                let result = x - self.rotate_omega(F::ONE, rotation);
                results.push(result);
            }
            results.iter_mut().batch_invert();
        }

        let common = (xn - F::ONE) * self.barycentric_weight;
        for (rotation, result) in rotations.into_iter().zip(results.iter_mut()) {
            let rotation = Rotation(rotation);
            *result = self.rotate_omega(*result * common, rotation);
        }

        results
    }

    /// Gets the quotient polynomial's degree (as a multiple of n)
    pub fn get_quotient_poly_degree(&self) -> usize {
        self.quotient_poly_degree as usize
    }

    /// Obtain a pinned version of this evaluation domain; a structure with the
    /// minimal parameters needed to determine the rest of the evaluation
    /// domain.
    pub fn pinned(&self) -> PinnedEvaluationDomain<'_, F> {
        PinnedEvaluationDomain {
            k: &self.k,
            extended_k: &self.extended_k,
            omega: &self.omega,
        }
    }
}

/// Represents the minimal parameters that determine an `EvaluationDomain`.
#[allow(dead_code)]
#[derive(Debug)]
pub struct PinnedEvaluationDomain<'a, F: Field> {
    k: &'a u32,
    extended_k: &'a u32,
    omega: &'a F,
}

#[test]
fn test_rotate() {
    use rand_core::OsRng;

    use crate::arithmetic::eval_polynomial;
    use halo2curves::pasta::pallas::Scalar;

    let domain = EvaluationDomain::<Scalar>::new(1, 3);
    let rng = OsRng;

    let mut poly = domain.empty_lagrange();
    assert_eq!(poly.len(), 8);
    for value in poly.iter_mut() {
        *value = Scalar::random(rng);
    }

    let poly_rotated_cur = poly.rotate(Rotation::cur());
    let poly_rotated_next = poly.rotate(Rotation::next());
    let poly_rotated_prev = poly.rotate(Rotation::prev());

    let poly = domain.lagrange_to_coeff(poly);
    let poly_rotated_cur = domain.lagrange_to_coeff(poly_rotated_cur);
    let poly_rotated_next = domain.lagrange_to_coeff(poly_rotated_next);
    let poly_rotated_prev = domain.lagrange_to_coeff(poly_rotated_prev);

    let x = Scalar::random(rng);

    assert_eq!(
        eval_polynomial(&poly[..], x),
        eval_polynomial(&poly_rotated_cur[..], x)
    );
    assert_eq!(
        eval_polynomial(&poly[..], x * domain.omega),
        eval_polynomial(&poly_rotated_next[..], x)
    );
    assert_eq!(
        eval_polynomial(&poly[..], x * domain.omega_inv),
        eval_polynomial(&poly_rotated_prev[..], x)
    );
}

#[test]
fn test_l_i() {
    use rand_core::OsRng;

    use crate::arithmetic::{eval_polynomial, lagrange_interpolate};
    use halo2curves::pasta::pallas::Scalar;
    let domain = EvaluationDomain::<Scalar>::new(1, 3);

    let mut l = vec![];
    let mut points = vec![];
    for i in 0..8 {
        points.push(domain.omega.pow(&[i, 0, 0, 0]));
    }
    for i in 0..8 {
        let mut l_i = vec![Scalar::zero(); 8];
        l_i[i] = Scalar::ONE;
        let l_i = lagrange_interpolate(&points[..], &l_i[..]);
        l.push(l_i);
    }

    let x = Scalar::random(OsRng);
    let xn = x.pow(&[8, 0, 0, 0]);

    let evaluations = domain.l_i_range(x, xn, -7..=7);
    for i in 0..8 {
        assert_eq!(eval_polynomial(&l[i][..], x), evaluations[7 + i]);
        assert_eq!(eval_polynomial(&l[(8 - i) % 8][..], x), evaluations[7 - i]);
    }
}

#[test]
fn test_fft() {
    use crate::arithmetic::{eval_polynomial, lagrange_interpolate};
    use halo2curves::pasta::pallas::Scalar;
    use rand_core::OsRng;

    fn get_degree() -> usize {
        var("DEGREE")
            .unwrap_or_else(|_| "8".to_string())
            .parse()
            .expect("Cannot parse DEGREE env var as usize")
    }
    let k = get_degree() as u32;

    let mut domain = EvaluationDomain::<Scalar>::new(1, k);
    let n = domain.n as usize;

    let input = vec![Scalar::random(OsRng); n];
    /*let mut input = vec![Scalar::zero(); n];
    for i in 0..n {
        input[i] = Scalar::random(OsRng);
    }*/

    let num_threads = multicore::current_num_threads();

    let mut a = input.clone();
    let start = start_measure(format!("best fft {} ({})", a.len(), num_threads), false);
    best_fft(&mut a, domain.omega, k);
    stop_measure(start);

    let mut b = input.clone();
    let start = start_measure(
        format!("recursive fft {} ({})", a.len(), num_threads),
        false,
    );
    recursive_fft(&mut domain.fft_data, &mut b, false);
    stop_measure(start);

    for i in 0..n {
        //println!("{}: {} {}", i, a[i], b[i]);
        assert_eq!(a[i], b[i]);
    }
}
