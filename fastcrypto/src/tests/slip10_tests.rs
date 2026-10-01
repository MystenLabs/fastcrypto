// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Encoding, Hex};
use crate::error::FastCryptoError;
use crate::slip10::{derive_hardened, Slip10MasterKey, MAX_SEED_LENGTH, MIN_SEED_LENGTH};

const SEED_1: &str = "000102030405060708090a0b0c0d0e0f";
const SEED_2: &str = concat!(
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2",
    "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
);

/// The complete ed25519 vectors from the SLIP-0010 spec. Matching them all
/// makes `derive_hardened(Slip10MasterKey::Ed25519, ..)` byte-identical to
/// `slip10_ed25519::derive_ed25519_private_key`, which hardcodes that key.
#[test]
fn ed25519_spec_vectors() {
    #[rustfmt::skip]
    const VECTORS: &[(&str, &[u32], &str, &str)] = &[
        (SEED_1, &[],
         "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
         "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"),
        (SEED_1, &[0],
         "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
         "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"),
        (SEED_1, &[0, 1],
         "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
         "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"),
        (SEED_1, &[0, 1, 2],
         "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
         "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"),
        (SEED_1, &[0, 1, 2, 2],
         "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
         "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"),
        (SEED_1, &[0, 1, 2, 2, 1000000000],
         "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
         "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"),
        (SEED_2, &[],
         "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
         "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"),
        (SEED_2, &[0],
         "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
         "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"),
        (SEED_2, &[0, 2147483647],
         "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
         "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4"),
        (SEED_2, &[0, 2147483647, 1],
         "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
         "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c"),
        (SEED_2, &[0, 2147483647, 1, 2147483646],
         "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
         "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72"),
        (SEED_2, &[0, 2147483647, 1, 2147483646, 2],
         "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
         "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d"),
    ];
    check_vectors(Slip10MasterKey::Ed25519, VECTORS);
}

/// The ML-DSA-65 paths from satoshilabs/slips#1968: chain codes from the
/// spec, node secrets pinned from this implementation.
#[test]
fn mldsa65_regression_vectors() {
    #[rustfmt::skip]
    const VECTORS: &[(&str, &[u32], &str, &str)] = &[
        (SEED_1, &[],
         "7e74b6275f92cc4fb2cbdac0c63cb5e7ac2bce1ded2b7dbc7bf2232f772578d5",
         "dbe1e4f588227dec9e2dc59a4534e7721bf3e977452f0193591603f79880795b"),
        (SEED_1, &[0],
         "d8b27c87ec212d6501629199262a9d0d66ec26deab313c26a474bc4ddd5dce7c",
         "ee139cc19250043529ae16f3d716208298deefa7cfd4a5a2d9af7ac6d6cac4a1"),
        (SEED_1, &[0, 1],
         "60219beef857bd0bc7870424c4f60464decb097a18ae37b035df22ebaa7515b9",
         "a14dd01ed1fc242b0613e1e0911cc67c1b4f790860649068bc1eda32c89a0e5d"),
        (SEED_1, &[0, 1, 2],
         "dc7b0e1379b3f1acd02d1e25f13d8bb16830ca68c73b00d900b9030a41d6a658",
         "5ec67a61dcd29fa73ab142c6bd54e745b4c47272f2339810bfe1f30a55342a26"),
        (SEED_1, &[0, 1, 2, 2],
         "565cb34027c3b54773f7f48e329bc86db7ffc6f618b112af6d59a3f82501e17a",
         "636c66df2469c084e524faa342810079b1e10c7ed92de94c10e8860695e6b56e"),
        (SEED_1, &[0, 1, 2, 2, 1000000000],
         "dc65d6cf4fa993c2f04fae2b41d70d8c5ba4c9d2042ea5720bf42a2315a6b7db",
         "3a7a1bdc57af0ee8a92da8ec4d900ecfeb269c13073127f032794af13f86c038"),
        (SEED_2, &[],
         "0e696f43f0e71c1c9febf61f43f10903385b78cee5871915472027b25ba755cc",
         "67c25895a02758460a9bd084aed3fb3db0ec33b85219d6723e356013da7a6714"),
        (SEED_2, &[0],
         "d977be3c8525364e155764ef76b985126d8f6be41b55e6e50a9915ae29f27a56",
         "e8bf8681f4a1a1d6c854e69b75fd0b39069b21ad983d74cf901dcb01985e9091"),
        (SEED_2, &[0, 2147483647],
         "45406bac7fc36390d89ac938bff6ca1ebf9fc6da2057d1580b26a8f2e25a0d2f",
         "4cfca7898c7bbb4a0bb7dc3d14a2d489eaaa87f2c4593985525d256f93cf8888"),
        (SEED_2, &[0, 2147483647, 1],
         "10ffddec3c4acf719afe528b1ced03e0f7d8555999c11b69376bd5ff4e04dbea",
         "969352513da88e996a133be855316dc3b46a0cd9792ff340c3bf5a06fa826c3f"),
        (SEED_2, &[0, 2147483647, 1, 2147483646],
         "3580d842e9d8d6a072b77d95e08b0a87648edfaec9bc25cee6c9127d1aa4a679",
         "ea4de14b6b31d080ad6dc5150642e59e79b83c4fdb90224b1c0d27a3240133da"),
        (SEED_2, &[0, 2147483647, 1, 2147483646, 2],
         "55a202d3f7803dd79e31c454e65eb7da49dee824b467bfed5204df980e71571d",
         "b73d5dd516a99ab278011406a328066f80f34c1ae878aa9fa5b92c4ef95a965f"),
    ];
    check_vectors(Slip10MasterKey::MlDsa65, VECTORS);
}

fn check_vectors(master_key: Slip10MasterKey, vectors: &[(&str, &[u32], &str, &str)]) {
    for (seed_hex, indexes, want_cc, want_secret) in vectors {
        let seed = Hex::decode(seed_hex).unwrap();
        let node = derive_hardened(master_key, &seed, indexes).unwrap();
        assert_eq!(
            Hex::encode(node.chain_code),
            *want_cc,
            "chain code, path {indexes:?}"
        );
        assert_eq!(
            Hex::encode(node.secret),
            *want_secret,
            "secret, path {indexes:?}"
        );
    }
}

/// Callers hold indexes both raw and pre-hardened (bip32 `ChildNumber`
/// carries the bit); the two must derive the same node.
#[test]
fn hardened_bit_idempotent() {
    let seed = Hex::decode(SEED_1).unwrap();
    let raw = derive_hardened(Slip10MasterKey::Ed25519, &seed, &[0, 1, 2]).unwrap();
    let pre = derive_hardened(
        Slip10MasterKey::Ed25519,
        &seed,
        &[0x8000_0000, 0x8000_0001, 0x8000_0002],
    )
    .unwrap();
    assert_eq!(raw.secret, pre.secret);
    assert_eq!(raw.chain_code, pre.chain_code);
}

/// The domain separation the master key exists for.
#[test]
fn master_key_separates_schemes() {
    let seed = Hex::decode(SEED_1).unwrap();
    let ed = derive_hardened(Slip10MasterKey::Ed25519, &seed, &[0]).unwrap();
    let pq = derive_hardened(Slip10MasterKey::MlDsa65, &seed, &[0]).unwrap();
    assert_ne!(ed.secret, pq.secret);
}

/// SLIP-0010 allows seeds of 128 to 512 bits; anything else is rejected
/// before any key material is derived.
#[test]
fn seed_length_bounds() {
    for master_key in [Slip10MasterKey::Ed25519, Slip10MasterKey::MlDsa65] {
        assert!(derive_hardened(master_key, &[1; MIN_SEED_LENGTH], &[0]).is_ok());
        assert!(derive_hardened(master_key, &[1; MAX_SEED_LENGTH], &[0]).is_ok());
        // `Slip10Node` is key material and has no `Debug`, hence no `unwrap_err`.
        assert!(matches!(
            derive_hardened(master_key, &[], &[0]),
            Err(FastCryptoError::InputTooShort(MIN_SEED_LENGTH))
        ));
        assert!(matches!(
            derive_hardened(master_key, &[1; MIN_SEED_LENGTH - 1], &[0]),
            Err(FastCryptoError::InputTooShort(MIN_SEED_LENGTH))
        ));
        assert!(matches!(
            derive_hardened(master_key, &[1; MAX_SEED_LENGTH + 1], &[0]),
            Err(FastCryptoError::InputTooLong(MAX_SEED_LENGTH))
        ));
    }
}
