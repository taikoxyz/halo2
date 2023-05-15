//! This module provides common utilities, traits and structures for group,
//! field and polynomial arithmetic.

use std::env;

use crate::{
    arithmetic::{self, log2_floor, parallelize, parallelize_count, FftGroup},
    multicore,
    plonk::{get_duration, get_time},
};

pub use ff::Field;
use ff::WithSmallOrderMulGroup;
use group::{
    ff::{BatchInvert, PrimeField},
    Curve, Group, GroupOpsOwned, ScalarMulOwned,
};

pub use halo2curves::{CurveAffine, CurveExt};

/// Performs a radix-$2$ Fast-Fourier Transformation (FFT) on a vector of size
/// $n = 2^k$, when provided `log_n` = $k$ and an element of multiplicative
/// order $n$ called `omega` ($\omega$). The result is that the vector `a`, when
/// interpreted as the coefficients of a polynomial of degree $n - 1$, is
/// transformed into the evaluations of this polynomial at each of the $n$
/// distinct powers of $\omega$. This transformation is invertible by providing
/// $\omega^{-1}$ in place of $\omega$ and dividing each resulting field element
/// by $n$.
///
/// This will use multithreading if beneficial.
pub fn best_fft<Scalar: Field, G: FftGroup<Scalar>>(a: &mut [G], omega: Scalar, log_n: u32) {
    let threads = multicore::current_num_threads();
    let log_threads = log2_floor(threads);
    let n = a.len() as usize;
    assert_eq!(n, 1 << log_n);

    for k in 0..n {
        let rk = arithmetic::bitreverse(k, log_n as usize);
        if k < rk {
            a.swap(rk, k);
        }
    }

    //let start = start_measure(format!("twiddles {} ({})", a.len(), threads), false);
    // precompute twiddle factors
    let twiddles: Vec<_> = (0..(n / 2) as usize)
        .scan(Scalar::ONE, |w, _| {
            let tw = *w;
            *w *= &omega;
            Some(tw)
        })
        .collect();
    //stop_measure(start);

    if log_n <= log_threads {
        let mut chunk = 2_usize;
        let mut twiddle_chunk = (n / 2) as usize;
        for _ in 0..log_n {
            a.chunks_mut(chunk).for_each(|coeffs| {
                let (left, right) = coeffs.split_at_mut(chunk / 2);

                // case when twiddle factor is one
                let (a, left) = left.split_at_mut(1);
                let (b, right) = right.split_at_mut(1);
                let t = b[0];
                b[0] = a[0];
                a[0] += &t;
                b[0] -= &t;

                left.iter_mut()
                    .zip(right.iter_mut())
                    .enumerate()
                    .for_each(|(i, (a, b))| {
                        let mut t = *b;
                        t *= &twiddles[(i + 1) * twiddle_chunk];
                        *b = *a;
                        *a += &t;
                        *b -= &t;
                    });
            });
            chunk *= 2;
            twiddle_chunk /= 2;
        }
    } else {
        recursive_butterfly_arithmetic(a, n, 1, &twiddles)
    }
}

/// This perform recursive butterfly arithmetic
pub fn recursive_butterfly_arithmetic<Scalar: Field, G: FftGroup<Scalar>>(
    a: &mut [G],
    n: usize,
    twiddle_chunk: usize,
    twiddles: &[Scalar],
) {
    if n == 2 {
        let t = a[1];
        a[1] = a[0];
        a[0] += &t;
        a[1] -= &t;
    } else {
        let (left, right) = a.split_at_mut(n / 2);
        rayon::join(
            || recursive_butterfly_arithmetic(left, n / 2, twiddle_chunk * 2, twiddles),
            || recursive_butterfly_arithmetic(right, n / 2, twiddle_chunk * 2, twiddles),
        );

        // case when twiddle factor is one
        let (a, left) = left.split_at_mut(1);
        let (b, right) = right.split_at_mut(1);
        let t = b[0];
        b[0] = a[0];
        a[0] += &t;
        b[0] -= &t;

        left.iter_mut()
            .zip(right.iter_mut())
            .enumerate()
            .for_each(|(i, (a, b))| {
                let mut t = *b;
                t *= &twiddles[(i + 1) * twiddle_chunk];
                *b = *a;
                *a += &t;
                *b -= &t;
            });
    }
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
pub struct FFTData<F: arithmetic::Field> {
    pub n: usize,

    stages: Vec<FFTStage>,

    f_twiddles: Vec<Vec<F>>,
    inv_twiddles: Vec<Vec<F>>,
    //scratch: Vec<F>,
}

impl<F: arithmetic::Field> FFTData<F> {
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
pub fn butterfly_2<F: arithmetic::Field>(out: &mut [F], twiddles: &[F], stage_length: usize) {
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
fn butterfly_2_parallel<F: arithmetic::Field>(
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
pub fn butterfly_4<F: arithmetic::Field>(out: &mut [F], twiddles: &[F], stage_length: usize) {
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
pub fn butterfly_4_parallel<F: arithmetic::Field>(
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
fn recursive_fft_inner<F: arithmetic::Field>(
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

pub fn recursive_fft<F: arithmetic::Field>(data: &FFTData<F>, data_in: &mut Vec<F>, inverse: bool) {
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
