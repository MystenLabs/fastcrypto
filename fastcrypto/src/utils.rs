/// Returns the log base 2 of b. There is an exception: for `b == 0`, it returns 0.
pub fn log2_byte(b: u8) -> usize {
    if b == 0 {
        return 0;
    } else {
        7 - b.leading_zeros() as usize
    }
}
