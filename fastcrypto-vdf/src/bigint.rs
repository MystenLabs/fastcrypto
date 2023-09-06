use std::ops::AddAssign;

trait BigInt: AddAssign<&Self> + MulAssign<&Self> + From<Vec<u8>> + {

}