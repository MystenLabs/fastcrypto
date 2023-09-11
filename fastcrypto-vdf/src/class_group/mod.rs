#[cfg(not(feature = "gmp"))]
pub mod num_bigint;

#[cfg(feature = "gmp")]
pub mod gmp;
