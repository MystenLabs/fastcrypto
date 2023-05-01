// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_export]
macro_rules! impl_base64_display_fmt {
    ($type:ty) => {
        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(f, "{}", Base64::encode(self.as_ref()))
            }
        }
    };
}

/// Returns the log base 2 of b. There is an exception: for `b == 0`, it returns 0.
pub fn log2_byte(b: u8) -> usize {
    if b == 0 {
        0
    } else {
        7 - b.leading_zeros() as usize
    }
}
