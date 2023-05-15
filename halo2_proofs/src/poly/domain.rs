//! This is a meta module for swapping different FFT implementations.

pub use crate::poly::domain_scroll::*;
//pub use crate::poly::domain_brecht::*;

/// TEMP
pub static mut FFT_TOTAL_TIME: usize = 0;

#[cfg(test)]
mod tests {
    use std::{
        env::{self, var},
        time::Instant,
    };

    use ff::Field;

    use crate::{
        arithmetic::{best_fft, best_fft_opt},
        multicore,
        plonk::{start_measure, stop_measure},
        poly::{EvaluationDomain, Rotation},
    };

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
    fn test_fft_scroll() {
        use halo2curves::bn256::Fr as Scalar;

        let max_log_n = 28;
        let min_log_n = 8;
        let a = (0..(1 << max_log_n))
            .into_iter()
            .map(|i| Scalar::from(i as u64))
            .collect::<Vec<_>>();

        println!("\n----------test FFT---------");
        for log_n in min_log_n..=max_log_n {
            let domain = EvaluationDomain::<Scalar>::new(1, log_n);
            let mut a0 = a[0..(1 << log_n)].to_vec();
            let mut a1 = a0.clone();

            // warm up & correct test
            best_fft(&mut a0, domain.omega, log_n);
            best_fft_opt(&mut a1, domain.omega, log_n);
            assert_eq!(a0, a1);

            let ori_time = Instant::now();
            best_fft(&mut a0, domain.omega, log_n);
            let ori_time = ori_time.elapsed();
            let ori_micros = f64::from(ori_time.as_micros() as u32);

            let opt_time = Instant::now();
            best_fft_opt(&mut a1, domain.omega, log_n);
            let opt_time = opt_time.elapsed();
            let opt_micros = f64::from(opt_time.as_micros() as u32);

            println!(
                "    [log_n = {}] ori_time: {:?}, opt_time: {:?}, speedup: {}",
                log_n,
                ori_time,
                opt_time,
                ori_micros / opt_micros
            );
        }
    }

    #[test]
    fn test_fft_brecht() {
        use crate::arithmetic::{eval_polynomial, lagrange_interpolate};
        use halo2curves::pasta::pallas::Scalar;
        use rand_core::OsRng;

        fn get_degree() -> usize {
            env::var("DEGREE")
                .unwrap_or_else(|_| "8".to_string())
                .parse()
                .expect("Cannot parse DEGREE env var as usize")
        }
        let k = get_degree() as u32;

        let domain = EvaluationDomain::<Scalar>::new(1, k);
        let n = domain.n as usize;

        let input = vec![Scalar::random(OsRng); n];
        /*let mut input = vec![Scalar::ZERO; n];
        for i in 0..n {
            input[i] = Scalar::random(OsRng);
        }*/

        let num_threads = multicore::current_num_threads();

        let mut a = input.clone();
        let start = start_measure(format!("best fft {} ({})", a.len(), num_threads), false);
        best_fft(&mut a, domain.omega, k);
        stop_measure(start);

        let mut b = input;
        let start = start_measure(
            format!("recursive fft {} ({})", a.len(), num_threads),
            false,
        );
        //recursive_fft(&domain.fft_data, &mut b, false);
        stop_measure(start);

        for i in 0..n {
            //println!("{}: {} {}", i, a[i], b[i]);
            assert_eq!(a[i], b[i]);
        }
    }

    #[test]
    fn test_fft() {
        test_fft_scroll();
        test_fft_brecht()
    }
}
