// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::math::parameterized_group::ParameterizedGroupElement;
use fastcrypto::groups::Doubling;
use fastcrypto::hash::{HashFunction, Keccak256};
use modulus::RSAModulus;
use num_bigint::BigUint;
use num_traits::One;
use serde::Serialize;
use std::ops::{Add, Mul};

/// When generating a random element, we sample uniformly 8 bytes larger than the modulus to limit the bias by 2^{-64}.
const BIAS_BYTES: usize = 16;

pub mod modulus;

/// This represents an element of the subgroup of an RSA group <i>Z<sub>N</sub><sup>*</sup> / <±1></i>
/// where <i>N</i> is the product of two large primes. See also [RSAModulus].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RSAGroupElement<'a> {
    value: BigUint,

    #[serde(skip)]
    modulus: &'a RSAModulus,
}

impl<'a> RSAGroupElement<'a> {
    /// Create a new RSA group element with the given value and modulus. The value will be reduced to
    /// the subgroup <i>Z<sub>N</sub><sup>*</sup> / <±1></i>, so it does not need to be in canonical
    /// representation.
    pub fn new(value: BigUint, modulus: &'a RSAModulus) -> Self {
        Self {
            value: modulus.reduce(value),
            modulus,
        }
    }

    /// Return the canonical representation of this group element.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Generate a random element of the subgroup <i>Z<sub>N</sub><sup>*</sup> / <±1></i>
    /// using the given seed. This is computed as
    ///
    /// `H(0 || inner_hash) || ... || H(k-1 || inner_hash)`
    ///
    /// interpreted as big-endian bytes, where H is the Keccak-256 hash function and
    ///
    /// `inner_hash = H(k || seed length || seed || modulus)`
    ///
    /// where `k` is the number of 32 byte chunks needed to sample `modulus size + [BIAS_BYTES]` bytes.
    pub fn from_seed(seed: &[u8], modulus: &'a RSAModulus) -> Self {
        // The number of 32-byte chunks needed to sample enough bytes.
        let minimum_bits = modulus.value.bits().div_ceil(8) as usize + BIAS_BYTES;
        let k = minimum_bits.div_ceil(Keccak256::OUTPUT_SIZE);

        // Compute inner_hash = H(k || seed length || seed || modulus)
        let mut hash = Keccak256::new();
        hash.update((k as u64).to_be_bytes());
        hash.update((seed.len() as u64).to_be_bytes());
        hash.update(seed);
        hash.update(modulus.value.to_bytes_be());
        let inner_hash = hash.finalize().digest;

        // Compute result = H(0 || inner_hash) | ... | H(k-1 || inner_hash) interpreted as big-endian bytes.
        let bytes: Vec<u8> = (0..k)
            .flat_map(|i| {
                let mut hash = Keccak256::new();
                hash.update((i as u64).to_be_bytes());
                hash.update(inner_hash);
                hash.finalize().digest
            })
            .collect();

        // The sampled number is almost surely larger than the modulus, but this is reduced in the constructor.
        Self::new(BigUint::from_bytes_be(&bytes), modulus)
    }
}

impl Add<&Self> for RSAGroupElement<'_> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        assert_eq!(self.modulus, rhs.modulus);
        Self::new(self.value.mul(&rhs.value), self.modulus)
    }
}

impl Doubling for RSAGroupElement<'_> {
    fn double(self) -> Self {
        Self::new(self.value.pow(2), self.modulus)
    }
}

impl<'a> ParameterizedGroupElement for RSAGroupElement<'a> {
    type ParameterType = &'a RSAModulus;

    fn zero(parameter: &Self::ParameterType) -> Self {
        Self::new(BigUint::one(), parameter)
    }

    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool {
        &self.modulus == parameter
    }
}

#[cfg(test)]
mod tests {
    use crate::math::parameterized_group::ParameterizedGroupElement;
    use crate::rsa_group::modulus::test::{AMAZON_MODULUS_2048_REF, GOOGLE_MODULUS_4096_REF};
    use crate::rsa_group::RSAGroupElement;
    use fastcrypto::groups::Doubling;
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_traits::One;
    use std::ops::{Add, Shr};
    use std::str::FromStr;

    #[test]
    fn test_group_ops() {
        // Add
        let zero = RSAGroupElement::zero(&GOOGLE_MODULUS_4096_REF);
        let element = RSAGroupElement::new(BigUint::from(7u32), &GOOGLE_MODULUS_4096_REF);
        let sum = element.clone().add(&zero);
        assert_eq!(&sum, &element);
        assert_eq!(
            sum,
            RSAGroupElement::new(BigUint::from(7u32), &GOOGLE_MODULUS_4096_REF)
        );

        // Double
        let expected_double = element.clone().add(&element);
        let double = element.double();
        assert_eq!(&double, &expected_double);
        assert_eq!(
            double,
            RSAGroupElement::new(BigUint::from(49u32), &GOOGLE_MODULUS_4096_REF)
        );

        // Double zero
        assert_eq!(
            RSAGroupElement::zero(&GOOGLE_MODULUS_4096_REF),
            RSAGroupElement::zero(&GOOGLE_MODULUS_4096_REF)
        );

        // +1 = -1 in this group
        let minus_one = RSAGroupElement::new(
            &GOOGLE_MODULUS_4096_REF.value - BigUint::one(),
            &GOOGLE_MODULUS_4096_REF,
        );
        let one = RSAGroupElement::new(BigUint::one(), &GOOGLE_MODULUS_4096_REF);
        assert_eq!(minus_one, one);

        // Regression tests
        let random_element = RSAGroupElement::from_seed(b"seed", &GOOGLE_MODULUS_4096_REF);
        assert_eq!(random_element.value, BigUint::from_str("330111943415406298137114804886674651165197855648164082097080652606171352183684280549096958773150625532414727703373627503658940072487313633154656577361304671427840905161185408677394162970933946682092927892571168197664488748677682183996395048370892051311971014051802845326978701283076292046488642348763784873317551146149011190137057672991645792260995801931073796671682037189630962843688595416727502402873638082949265292944452215455022677472653365313642851389141812337248589041000605839392153771291891744661945901410872652147967722739835300584026185898182743753948543877214718210234076507310521975396357453782414202138739720355951958949514320876683524763527766171841521084906147995043110332952563641259095519430815875644105976743452019401021990194860272848711274331838187388040850728024141901195369309573928196473385923387423200038487017089129352370374449974173743153234458478573302394617933866513896442666751017042726453588604746878374828365328004809091969396607455128973367140781335936126796889365981461799137642429761476599195890664770511827448118397964918242327244456257895752327128018737432971358938713978587586331762601818361911361737211884676289268456486024282837511218494874352224245521951813214740703112667974379104585871340981").unwrap());
        let other_random_element =
            RSAGroupElement::from_seed(b"other seed", &GOOGLE_MODULUS_4096_REF);
        assert_eq!(other_random_element.value, BigUint::from_str("32031241465426051554630410772258835357660907945035779331951329621285665798602020588418427181702810063791764171003201344872042403380195386053784363198884596882636424796031672799309845603971269243727585929280148920269225531183994688776076163684891981875988673798173206061126415368119059534842642343903087556184660324299384958639520879004834673508806009348757651015299319512371831933113982650113761790001189446059976331061185452462585235269008586672756860726762726536526385965063327108275703434137348078077650950728980725415828502063065024366478241305610237942240286771397051253587069947012999401397645883793558365906276433875146136629539814644826864224471783246483136719194555196801178462673727476028927536093437813602477988236055075037395196204365127689269380284413522561717979625407759455096911077055969555072459028560587079540101555479873100609520348381446869998640545938331739201353177802124036159750911443965544746704984918086383511626700961065657348388766343804915675971382530557273240526392858589928511012146392181015489876367889462126278653341490332031311110031241004788679555689253486610296573692589242569647092527997375458340690148744051277570590168971242394354111359341759247927972644600500479257077739284993202358754607997").unwrap());
        let product = random_element + &other_random_element;
        assert_eq!(product.value, BigUint::from_str("187791989164610742805372077314181567035161911805161455275554316799154916882326461689694996162922071984150549196717487412251668318272641371670980347412541171022373225989314642029241679275703249959367360976395795876069224488527863784706648850851895514791418793068902424501213519486995471582660469290745966009829556260649020574388860647858462525793601380202793004345464896932013583100366686015197877407359517667274331633364569269178492446392641451487638617482609320275910508209014763988464782239691538246643396487975138002432417211255116556839870867053049382575830094209297696989162729428214906949059201726477767850288796315719951925212096725322256245872733698182493641563337435027947993665727153736847323234410327802046222422687150709854746063195561020546731736400844321902937351332535456791628137171243232273862880568126376493101884389066810120592348676726357390574907814280554330620953532842288228316741852804427592841033899624008972450888283199503426335061922968730782756045040152173435797486557121786992301594341176900393001185041883348746846327298453583690698227522540990741710368677786519818806593785273958593254928277522344237501674142029413103702820600072848331957135552467069684995012835308217498607767611087002671096495592016").unwrap());

        // Modular reduction of new elements
        let large_number = BigUint::from_str("3036574726774676854074014207033343430612266081507239284282798782317571042227965037278950934156694735611210695484310361268558404608267193592214127172354047065735403268979111700392033047010804126832086391966439076431330350374247419917618297006262856696155226628618293034757242356020689237892332233440871475509280609912569923161406282048700185976978134392521001361425887597945020503850821184990626505486306603461873986703869036511634866702369526250399148024834067982831047337042153803607868763371956217428973526669465977516790908505225943570334171057954932061023400781214763048807711360233971697637040843540051164810073408390129527377426443433651590472389267133466042148959242653139526086412946070786720140657635835875713323699908265653879574906967349779294842580887092681914797921763005562279351709683336901191523161823487780857916850791672416252526865341826684661942406749371858482369032127708690896727803767069390093288584032378684194122410651316035020185762056183476958400919610941041023184947635820644508736415622905641385921660301201726207780865694936025072564059000891388970164247300478721858382388009195099408958892192194896015031243023477528739867472304200234331201318403377478375342123264777993278351523205958747379610474196811231241234").unwrap();
        let large_number_reduced = large_number.mod_floor(&GOOGLE_MODULUS_4096_REF.value);
        let large_number_as_group_element =
            RSAGroupElement::new(large_number.clone(), &GOOGLE_MODULUS_4096_REF);
        assert!(large_number_reduced >= (&GOOGLE_MODULUS_4096_REF.value).shr(1));
        assert_eq!(
            large_number_as_group_element.value,
            &GOOGLE_MODULUS_4096_REF.value - &large_number_reduced
        );
        assert_eq!(
            large_number_as_group_element,
            RSAGroupElement::new(large_number_reduced.clone(), &GOOGLE_MODULUS_4096_REF)
        );
    }

    #[test]
    fn test_is_in_group() {
        let element = RSAGroupElement::new(BigUint::from(7u32), &GOOGLE_MODULUS_4096_REF);
        assert!(element.is_in_group(&GOOGLE_MODULUS_4096_REF));
        assert!(!element.is_in_group(&AMAZON_MODULUS_2048_REF));
    }
}
