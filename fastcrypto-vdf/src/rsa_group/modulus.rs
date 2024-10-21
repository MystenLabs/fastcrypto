// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;
use num_bigint::BigUint;
use num_integer::Integer;
use serde::Serialize;
use std::ops::Shr;
use std::str::FromStr;

#[derive(PartialEq, Eq, Debug, Serialize)]
pub struct RSAModulus {
    pub(super) value: BigUint,

    /// Precomputed value of `modulus / 2` for faster reduction.
    #[serde(skip)]
    pub(super) half: BigUint,
}

impl FromStr for RSAModulus {
    type Err = FastCryptoError;

    /// Parse an RSA modulus from a decimal string. The modulus is not validated, so it is the caller's
    /// responsibility to ensure that it is a valid RSA modulus.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BigUint::from_str(s)
            .map(Self::from)
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl From<BigUint> for RSAModulus {
    /// Create an RSA modulus from a [BigUint]. The modulus is not validated, so it is the caller's
    /// responsibility to ensure that it is a valid RSA modulus.
    fn from(value: BigUint) -> Self {
        let half = (&value).shr(1);
        Self { value, half }
    }
}

impl RSAModulus {
    /// Reduce the given value modulo this modulus. Further, if the value is greater than half of the
    /// modulus, the result is negated. This is to ensure that the result is in the subgroup
    /// <i>Z<sub>N</sub><sup>*</sup> / <±1></i>.
    pub(super) fn reduce(&self, value: BigUint) -> BigUint {
        self.ensure_in_subgroup(value.mod_floor(&self.value))
    }

    /// Assuming that `value < N`, this ensures that the given value is in the subgroup <i>Z<sub>N</sub><sup>*</sup> / <±1></i>.
    /// Panics if `value` is greater than or equal to `N`.
    pub(super) fn ensure_in_subgroup(&self, value: BigUint) -> BigUint {
        if value < self.half {
            value
        } else {
            &self.value - value
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::rsa_group::modulus::RSAModulus;
    use lazy_static::lazy_static;
    use std::str::FromStr;

    lazy_static! {
        /// Modulus from Google Certificate, GTS Root R1 (https://pki.goog/repository/) for testing.
        static ref GOOGLE_MODULUS_4096: RSAModulus = RSAModulus::from_str("742766292573789461138430713106656498577482106105452767343211753017973550878861638590047246174848574634573720584492944669558785810905825702100325794803983120697401526210439826606874730300903862093323398754125584892080731234772626570955922576399434033022944334623029747454371697865218999618129768679013891932765999545116374192173968985738129135224425889467654431372779943313524100225335793262665132039441111162352797240438393795570253671786791600672076401253164614309929080014895216439462173458352253266568535919120175826866378039177020829725517356783703110010084715777806343235841345264684364598708732655710904078855499605447884872767583987312177520332134164321746982952420498393591583416464199126272682424674947720461866762624768163777784559646117979893432692133818266724658906066075396922419161138847526583266030290937955148683298741803605463007526904924936746018546134099068479370078440023459839544052468222048449819089106832452146002755336956394669648596035188293917750838002531358091511944112847917218550963597247358780879029417872466325821996717925086546502702016501643824750668459565101211439428003662613442032518886622942136328590823063627643918273848803884791311375697313014431195473178892344923166262358299334827234064598421").unwrap();
        pub static ref GOOGLE_MODULUS_4096_REF: &'static RSAModulus = &GOOGLE_MODULUS_4096;

        /// Modulus from Amazon CA 1 (https://www.amazontrust.com/repository/AmazonRootCA1.pem) for testing.
        static ref AMAZON_MODULUS_2048: RSAModulus = RSAModulus::from_str("22529839904807742196558773392430766620630713202204326167346456925862066285712069978308045976033918808540171076811098215136401323342247576789054764683787147408289170989302937775178809187827657352584557953877946352196797789035355954596527030584944622221752357105572088106020206921431118198373122638305846252087992561841631797199384157902018140720267433956687491591657652730221337591680012205319549572614035105482287002884850178224609018864719685310905426619874727796905080238179726224664042154200651710137931048812546957419686875805576245376866031854569863410951649630469236463991472642618512857920826701027482532358669").unwrap();
        pub static ref AMAZON_MODULUS_2048_REF: &'static RSAModulus = &AMAZON_MODULUS_2048;
    }
}
