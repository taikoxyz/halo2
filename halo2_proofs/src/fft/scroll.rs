//! This module provides common utilities, traits and structures for group,
//! field and polynomial arithmetic.

use crate::arithmetic::{log2_floor, FftGroup};

use crate::multicore;
pub use ff::Field;
use group::{
    ff::{BatchInvert, PrimeField},
    Curve, Group as _, GroupOpsOwned, ScalarMulOwned,
};
pub use halo2curves::{CurveAffine, CurveExt};
use std::time::Instant;

/// A constant
pub const SPARSE_TWIDDLE_DEGREE: u32 = 10;

/// Dispatcher
pub fn best_fft_opt<Scalar: Field, G: FftGroup<Scalar>>(a: &mut [G], omega: Scalar, log_n: u32) {
    let threads = multicore::current_num_threads();
    let log_split = log2_floor(threads) as usize;
    let n = a.len() as usize;
    let sub_n = n >> log_split;
    let split_m = 1 << log_split;

    if sub_n >= split_m {
        parallel_fft(a, omega, log_n);
    } else {
        serial_fft(a, omega, log_n);
    }
}

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
    fn bitreverse(mut n: usize, l: usize) -> usize {
        let mut r = 0;
        for _ in 0..l {
            r = (r << 1) | (n & 1);
            n >>= 1;
        }
        r
    }

    let threads = multicore::current_num_threads();
    let log_threads = log2_floor(threads);
    let n = a.len() as usize;
    assert_eq!(n, 1 << log_n);

    for k in 0..n {
        let rk = bitreverse(k, log_n as usize);
        if k < rk {
            a.swap(rk, k);
        }
    }

    // precompute twiddle factors
    let twiddles: Vec<_> = (0..(n / 2) as usize)
        .scan(Scalar::ONE, |w, _| {
            let tw = *w;
            *w *= &omega;
            Some(tw)
        })
        .collect();

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

fn bitreverse(mut n: usize, l: usize) -> usize {
    let mut r = 0;
    for _ in 0..l {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    r
}

fn serial_fft<Scalar: Field, G: FftGroup<Scalar>>(a: &mut [G], omega: Scalar, log_n: u32) {
    let n = a.len() as u32;
    assert_eq!(n, 1 << log_n);

    for k in 0..n as usize {
        let rk = bitreverse(k, log_n as usize);
        if k < rk {
            a.swap(rk as usize, k as usize);
        }
    }

    let mut m = 1;
    for _ in 0..log_n {
        let w_m: Scalar = omega.pow_vartime(&[u64::from(n / (2 * m)), 0, 0, 0]);

        let mut k = 0;
        while k < n {
            let mut w = Scalar::ONE;
            for j in 0..m {
                let mut t = a[(k + j + m) as usize];
                t *= &w;
                a[(k + j + m) as usize] = a[(k + j) as usize];
                a[(k + j + m) as usize] -= &t;
                a[(k + j) as usize] += &t;
                w *= &w_m;
            }

            k += 2 * m;
        }

        m *= 2;
    }
}

fn serial_split_fft<Scalar: Field, G: FftGroup<Scalar>>(
    a: &mut [G],
    twiddle_lut: &[Scalar],
    twiddle_scale: usize,
    log_n: u32,
) {
    let n = a.len() as u32;
    assert_eq!(n, 1 << log_n);

    let mut m = 1;
    for _ in 0..log_n {
        let omega_idx = twiddle_scale * n as usize / (2 * m as usize); // 1/2, 1/4, 1/8, ...
        let low_idx = omega_idx % (1 << SPARSE_TWIDDLE_DEGREE);
        let high_idx = omega_idx >> SPARSE_TWIDDLE_DEGREE;
        let mut w_m = twiddle_lut[low_idx];
        if high_idx > 0 {
            w_m = w_m * twiddle_lut[(1 << SPARSE_TWIDDLE_DEGREE) + high_idx];
        }

        let mut k = 0;
        while k < n {
            let mut w = Scalar::ONE;
            for j in 0..m {
                let mut t = a[(k + j + m) as usize];
                t *= &w;
                a[(k + j + m) as usize] = a[(k + j) as usize];
                a[(k + j + m) as usize] -= &t;
                a[(k + j) as usize] += &t;
                w *= &w_m;
            }

            k += 2 * m;
        }

        m *= 2;
    }
}

fn split_radix_fft<Scalar: Field, G: FftGroup<Scalar>>(
    tmp: &mut [G],
    a: &[G],
    twiddle_lut: &[Scalar],
    n: usize,
    sub_fft_offset: usize,
    log_split: usize,
) {
    let split_m = 1 << log_split;
    let sub_n = n >> log_split;

    // we use out-place bitreverse here, split_m <= num_threads, so the buffer spase is small
    // and it's is good for data locality
    let tmp_filler_val = tmp[0];
    let mut t1 = vec![tmp_filler_val; split_m];
    for i in 0..split_m {
        t1[bitreverse(i, log_split)] = a[(i * sub_n + sub_fft_offset)];
    }
    serial_split_fft(&mut t1, twiddle_lut, sub_n, log_split as u32);

    let sparse_degree = SPARSE_TWIDDLE_DEGREE;
    let omega_idx = sub_fft_offset as usize;
    let low_idx = omega_idx % (1 << sparse_degree);
    let high_idx = omega_idx >> sparse_degree;
    let mut omega = twiddle_lut[low_idx];
    if high_idx > 0 {
        omega = omega * twiddle_lut[(1 << sparse_degree) + high_idx];
    }
    let mut w_m = Scalar::ONE;
    for i in 0..split_m {
        t1[i] *= &w_m;
        tmp[i] = t1[i];
        w_m = w_m * omega;
    }
}

/// Precalculate twiddles factors
pub fn generate_twiddle_lookup_table<F: Field>(
    omega: F,
    log_n: u32,
    sparse_degree: u32,
    with_last_level: bool,
) -> Vec<F> {
    let without_last_level = !with_last_level;
    let is_lut_len_large = sparse_degree > log_n;

    // dense
    if is_lut_len_large {
        let mut twiddle_lut = vec![F::ZERO; (1 << log_n) as usize];
        parallelize(&mut twiddle_lut, |twiddle_lut, start| {
            let mut w_n = omega.pow_vartime(&[start as u64, 0, 0, 0]);
            for twiddle_lut in twiddle_lut.iter_mut() {
                *twiddle_lut = w_n;
                w_n = w_n * omega;
            }
        });
        return twiddle_lut;
    }

    // sparse
    let low_degree_lut_len = 1 << sparse_degree;
    let high_degree_lut_len = 1 << (log_n - sparse_degree - without_last_level as u32);
    let mut twiddle_lut = vec![F::ZERO; (low_degree_lut_len + high_degree_lut_len) as usize];
    parallelize(
        &mut twiddle_lut[..low_degree_lut_len],
        |twiddle_lut, start| {
            let mut w_n = omega.pow_vartime(&[start as u64, 0, 0, 0]);
            for twiddle_lut in twiddle_lut.iter_mut() {
                *twiddle_lut = w_n;
                w_n = w_n * omega;
            }
        },
    );
    let high_degree_omega = omega.pow_vartime(&[(1 << sparse_degree) as u64, 0, 0, 0]);
    parallelize(
        &mut twiddle_lut[low_degree_lut_len..],
        |twiddle_lut, start| {
            let mut w_n = high_degree_omega.pow_vartime(&[start as u64, 0, 0, 0]);
            for twiddle_lut in twiddle_lut.iter_mut() {
                *twiddle_lut = w_n;
                w_n = w_n * high_degree_omega;
            }
        },
    );
    twiddle_lut
}

/// The parallel implementation
pub fn parallel_fft<Scalar: Field, G: FftGroup<Scalar>>(a: &mut [G], omega: Scalar, log_n: u32) {
    let n = a.len() as usize;
    assert_eq!(n, 1 << log_n);

    let log_split = log2_floor(multicore::current_num_threads()) as usize;
    let split_m = 1 << log_split;
    let sub_n = n >> log_split as usize;
    let twiddle_lut = generate_twiddle_lookup_table(omega, log_n, SPARSE_TWIDDLE_DEGREE, true);

    // split fft
    let tmp_filler_val = a[0];
    let mut tmp = vec![tmp_filler_val; n];
    multicore::scope(|scope| {
        let a = &*a;
        let twiddle_lut = &*twiddle_lut;
        for (chunk_idx, tmp) in tmp.chunks_mut(sub_n).enumerate() {
            scope.spawn(move |_| {
                let split_fft_offset = (chunk_idx * sub_n) >> log_split;
                for (i, tmp) in tmp.chunks_mut(split_m).enumerate() {
                    let split_fft_offset = split_fft_offset + i;
                    split_radix_fft(tmp, a, twiddle_lut, n, split_fft_offset, log_split);
                }
            });
        }
    });

    // shuffle
    parallelize(a, |a, start| {
        for (idx, a) in a.iter_mut().enumerate() {
            let idx = start + idx;
            let i = idx / sub_n;
            let j = idx % sub_n;
            *a = tmp[j * split_m + i];
        }
    });

    // sub fft
    let new_omega = omega.pow_vartime(&[split_m as u64, 0, 0, 0]);
    multicore::scope(|scope| {
        for a in a.chunks_mut(sub_n) {
            scope.spawn(move |_| {
                serial_fft(a, new_omega, log_n - log_split as u32);
            });
        }
    });

    // copy & unshuffle
    let mask = (1 << log_split) - 1;
    parallelize(&mut tmp, |tmp, start| {
        for (idx, tmp) in tmp.iter_mut().enumerate() {
            let idx = start + idx;
            *tmp = a[idx];
        }
    });
    parallelize(a, |a, start| {
        for (idx, a) in a.iter_mut().enumerate() {
            let idx = start + idx;
            *a = tmp[sub_n * (idx & mask) + (idx >> log_split)];
        }
    });
}

/// This simple utility function will parallelize an operation that is to be
/// performed over a mutable slice.
pub fn parallelize<T: Send, F: Fn(&mut [T], usize) + Send + Sync + Clone>(v: &mut [T], f: F) {
    let n = v.len();
    let num_threads = multicore::current_num_threads();
    let mut chunk = (n as usize) / num_threads;
    if chunk < num_threads {
        chunk = n as usize;
    }

    multicore::scope(|scope| {
        for (chunk_num, v) in v.chunks_mut(chunk).enumerate() {
            let f = f.clone();
            scope.spawn(move |_| {
                let start = chunk_num * chunk;
                f(v, start);
            });
        }
    });
}
