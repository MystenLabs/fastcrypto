use vdf::{VDF as OtherVDF, VDFParams};
use crate::error::{FastCryptoError, FastCryptoResult};

pub trait VDF {
    fn evaluate(&self, input: &[u8], difficulty: u64) -> FastCryptoResult<Vec<u8>>;
    fn verify(&self, input: &[u8], difficulty: u64, output: &[u8]) -> FastCryptoResult<bool>;
}

pub struct WesolowskiVDF {
    internal: vdf::WesolowskiVDF,
}

impl WesolowskiVDF {
    pub fn new(discriminant_bits: u16) -> Self {
        Self {
            internal: vdf::WesolowskiVDFParams(discriminant_bits).new(),
        }
    }
}

impl VDF for WesolowskiVDF {
    fn evaluate(&self, input: &[u8], difficulty: u64) -> FastCryptoResult<Vec<u8>> {
        self.internal.solve(input, difficulty).map_err(|_| FastCryptoError::InvalidInput)
    }

    fn verify(&self, input: &[u8], difficulty: u64, output: &[u8]) -> FastCryptoResult<bool> {
        self.internal.verify(input, difficulty, output).map_err(|_| FastCryptoError::InvalidInput).map(|_| true)
    }
}