use std::env;

use ff::Field;

use crate::arithmetic::FftGroup;

pub(crate) mod brecht;
pub(crate) mod scroll;

pub fn get_fft_mode() -> usize {
    env::var("FFT_MODE")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("Cannot parse FFT_MODE env var as usize")
}

/// Dispatcher
pub fn dispatch<Scalar: Field, G: FftGroup<Scalar>>(a: &mut [G], omega: Scalar, log_n: u32) {
    match env::var("FFT") {
        Ok(fft_impl) if fft_impl == "brecht" => {
            dbg!("=== brechtFFT ===");
            brecht::best_fft(a, omega, log_n)
        }
        Ok(fft_impl) if fft_impl == "scroll" => {
            dbg!("=== scrollFFT ===");
            scroll::best_fft(a, omega, log_n)
        }
        Ok(fft_impl) => panic!("Unknown FFT implementation {fft_impl}"),
        _ => panic!("Please specify environment variable FFT"),
    }
}
