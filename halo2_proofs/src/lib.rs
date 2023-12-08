//! # halo2_proofs

#![cfg_attr(docsrs, feature(doc_cfg))]
// Build without warnings on stable 1.51 and later.
#![allow(unknown_lints)]
// Disable old lint warnings until our MSRV is at least 1.51.
#![allow(renamed_and_removed_lints)]
// Use the old lint name to build without warnings until our MSRV is at least 1.51.
#![allow(clippy::unknown_clippy_lints)]
// The actual lints we want to disable.
#![allow(
    clippy::op_ref,
    clippy::assign_op_pattern,
    clippy::too_many_arguments,
    clippy::suspicious_arithmetic_impl,
    clippy::many_single_char_names,
    clippy::same_item_push,
    clippy::upper_case_acronyms,
    clippy::uninit_vec
)]
#![deny(broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
// #![deny(unsafe_code)]
// Remove this once we update pasta_curves
#![allow(unused_imports)]
#![allow(clippy::derive_partial_eq_without_eq)]

#[cfg(feature = "counter")]
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "counter")]
use lazy_static::lazy_static;

#[cfg(feature = "counter")]
use std::sync::Mutex;

#[cfg(feature = "counter")]
use std::collections::BTreeMap;

#[cfg(feature = "counter")]
lazy_static! {
    static ref FFT_COUNTER: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
    static ref MSM_COUNTER: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
}

pub mod arithmetic;
pub mod circuit;
pub use halo2curves;
mod multicore;
pub mod plonk;
pub mod poly;
pub mod transcript;

pub mod dev;
mod helpers;
pub use helpers::SerdeFormat;
