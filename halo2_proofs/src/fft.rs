//! Meta module for FFT

use std::env;

use ff::Field;

use crate::arithmetic::FftGroup;

use self::brecht::FFTData;

pub mod brecht;
pub(crate) mod orig;
pub(crate) mod scroll;

/// Read Environment Variable `FFT_MODE`
pub fn get_fft_mode() -> usize {
    env::var("FFT_MODE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("Cannot parse FFT_MODE env var as usize")
}

/// Read Environment Variable `DEGREE`
#[allow(dead_code)]
pub fn get_degree() -> usize {
    env::var("DEGREE")
        .unwrap_or_else(|_| "22".to_string())
        .parse()
        .expect("Cannot parse DEGREE env var as usize")
}

/// Dispatch to FFT implementation
pub fn dispatch<Scalar: Field, G: FftGroup<Scalar>>(
    a: &mut [G],
    omega: Scalar,
    log_n: u32,
    data: &FFTData<Scalar>,
    inverse: bool,
) {
    match env::var("FFT") {
        Ok(fft_impl) if fft_impl == "orig" || fft_impl.is_empty() => {
            dbg!("=== origFFT ===");
            orig::fft(a, omega, log_n, data, inverse)
        }
        Ok(fft_impl) if fft_impl == "brecht" => {
            dbg!("=== brechtFFT ===");
            brecht::fft(&mut vec![], omega, log_n, data, inverse)
        }
        Ok(fft_impl) if fft_impl == "scroll" => {
            dbg!("=== scrollFFT ===");
            scroll::fft(a, omega, log_n, data, inverse)
        }
        _ => panic!("Please specify environment variable FFT={{<empty string>,brecht,scroll}}"),
    }
}
