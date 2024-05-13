// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use num_bigint::BigInt;

use crate::class_group::discriminant::Discriminant;
use crate::class_group::QuadraticForm;
use crate::math::parameterized_group::ParameterizedGroupElement;

#[test]
fn test_composition() {
    // The order of the class group (the class number) for -223 is 7 (see https://mathworld.wolfram.com/ClassNumber.html).
    let discriminant = Discriminant::try_from(BigInt::from(-223)).unwrap();
    let mut g = QuadraticForm::generator(&discriminant);

    for _ in 1..=6 {
        assert_ne!(QuadraticForm::zero(&discriminant), g);
        g = g.compose(&QuadraticForm::generator(&discriminant));
    }
    assert_eq!(QuadraticForm::zero(&discriminant), g);
}

#[test]
fn test_qf_to_from_bytes() {
    let discriminant = Discriminant::try_from(BigInt::from(-223)).unwrap();
    let expected =
        QuadraticForm::hash_to_group_with_default_parameters(&[0, 1], &discriminant).unwrap();
    let bytes = bcs::to_bytes(&expected).unwrap();
    let actual = bcs::from_bytes(&bytes).unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_large_qf_to_from_bytes() {
    let discriminant = Discriminant::try_from(BigInt::from_str("-4080390101490206102067801750685552291425412528983716161454985565795560716833845004659207152503580931176637478422335625954692628868126419714053340412299850300602673802493259771830686596468801304317015718872352674945215883546019961626928140286675493693757393881479657605888983279619347902770789061953207866325747708864327315769009839190765716943013935708854055658243676903245686125751909996824976354309908771869043784640567352757672203749399825983258156684652782580603170228640173640869773628592618889352385821753919281706169861276929330689892675986265846043432389737049521845230769417696140636288030698887830215613149485135897148487896368642774768920061430225392365148291796645740474628778185683682893521776342856643134668770656709308404166182149870849376649591338267281149794078240401323227967073641261327798339424740171219484355109588337730742391198073121589465833677609362668436116144203312494461735357918360857667357985711").unwrap()).unwrap();
    assert_eq!(discriminant.bits(), 3072);

    let expected = QuadraticForm::generator(&discriminant);
    let bytes = bcs::to_bytes(&expected).unwrap();
    let actual = bcs::from_bytes(&bytes).unwrap();
    assert_eq!(expected, actual);

    let a_bytes = bcs::to_bytes(&expected.a.to_signed_bytes_be()).unwrap();
    let b_bytes = bcs::to_bytes(&expected.b.to_signed_bytes_be()).unwrap();
    let c_bytes = bcs::to_bytes(&expected.c.to_signed_bytes_be()).unwrap();

    assert_eq!(bytes[..a_bytes.len()], a_bytes);
    assert_eq!(bytes[a_bytes.len()..a_bytes.len() + b_bytes.len()], b_bytes);
    assert_eq!(bytes[a_bytes.len() + b_bytes.len()..], c_bytes);
}
