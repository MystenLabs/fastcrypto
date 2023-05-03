// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

///! This module contains test vectors for all signature schemes supported by the sigs_cli tool.
pub mod sigs_cli_test_vectors {

    /// A test vector containing a signature over MSG encoded as a hex string.
    pub struct TestVector {
        pub name: &'static str,
        pub private: &'static str,
        pub public: &'static str,
        pub sig: &'static str,
    }

    pub const MSG: &str = "00010203";
    pub const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    const ED25519_TEST: TestVector = TestVector {
        name: "ed25519",
        private: "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d",
        public: "8c553335eee80b9bfa0c544a45fe63474a09dff9c4b0b33db2b662f934ea46c4",
        sig: "e929370aa36bef3a6b51594b6d96e0f389f09f28807e6b3a25d0ea93f56dd4659e15995f87545ab8f7f924bc18e0502fa689a57e57e931620b79a6c9ec7b3208",
    };

    const SECP256K1_TEST: TestVector = TestVector {
        name: "secp256k1",
        private: "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d",
        public: "033e99a541db69bd32040dfe5037fbf5210dafa8151a71e21c5204b05d95ce0a62",
        sig: "416a21d50b3c838328d4f03213f8ef0c3776389a972ba1ecd37b56243734eba208ea6aaa6fc076ad7accd71d355f693a6fe54fe69b3c168eace9803827bc9046",
    };

    const SECP256K1_RECOVERABLE_TEST: TestVector = TestVector {
        name: "secp256k1-rec",
        private: SECP256K1_TEST.private,
        public: SECP256K1_TEST.public,
        sig: "416a21d50b3c838328d4f03213f8ef0c3776389a972ba1ecd37b56243734eba208ea6aaa6fc076ad7accd71d355f693a6fe54fe69b3c168eace9803827bc904601",
    };

    const SECP256R1_TEST: TestVector = TestVector {
        name: "secp256r1",
        private: "3301e8d7e754db2cf57b0a4ca73f253c7053ad2bc5398777ba039b258e59ad9d",
        public: "035a8b075508c75f4a124749982a7d21f80d9a5f6893e41a9e955fe4c821e0debe",
        sig: "54d7d68b43d65f718f3a92041292a514987739c36158a836b2218c505ba0e17c661642e58c996ba78f0cca493690b89658d0da3b9333a9e4fcea9ebf13da64bd",
    };

    const SECP256R1_RECOVERABLE_TEST: TestVector = TestVector {
        name: "secp256r1-rec",
        private: SECP256R1_TEST.private,
        public: SECP256R1_TEST.public,
        sig: "54d7d68b43d65f718f3a92041292a514987739c36158a836b2218c505ba0e17c661642e58c996ba78f0cca493690b89658d0da3b9333a9e4fcea9ebf13da64bd01",
    };

    const BLS12381_MINSIG_TEST: TestVector = TestVector {
        name: "bls12381-minsig",
        private: "5fbaab9bd5ed88305581c2926a67ac56fd987ade7658335b1fa1acd258a6f337",
        public: "a57feae28362201f657ccf6cdaba629758beb0214942804d2c084967d76908fe46ce355e0e735bdde2705620c7cf4b3903177f62ba43ba39277d952d80afee4fdc439a3ce2ce6fd113196d7de7aff7d1683ed507a21e6920119c91980329925b",
        sig: "a09f9b16ac4cfeadfd4d69b940cf9ead098a7d9f0df0a11d07820cb1dbacda6e1d0631529b1070ec1d8eb29fbc76a807",
    };

    const BLS12381_MINPK_TEST: TestVector = TestVector {
        name: "bls12381-minpk",
        private: "5fbaab9bd5ed88305581c2926a67ac56fd987ade7658335b1fa1acd258a6f337",
        public: "83738acb2121bb33db5a178a0a56ec041ae3b3617c9f2615a4366b9e3aa4021f3bbfe02858a0a0659ef9e8312c7b7d0f",
        sig: "ae65a019350ebbb2280d52d19d1bed3fe804b753c1dd5ce7738ca47fa90110e668dc75b6f53972a1c812f135b099fd780bdf69f18952b777d32a865cbabce270a6af400223f9558161102348f79980537c10455355a54158b44bf62b5eef8c63",
    };

    pub const TEST_CASES: [TestVector; 7] = [
        ED25519_TEST,
        SECP256K1_TEST,
        SECP256K1_RECOVERABLE_TEST,
        SECP256R1_TEST,
        SECP256R1_RECOVERABLE_TEST,
        BLS12381_MINSIG_TEST,
        BLS12381_MINPK_TEST,
    ];
}
