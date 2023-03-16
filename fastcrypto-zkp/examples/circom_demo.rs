// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs::File};

use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction, WitnessCalculator};

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;

use ark_std::rand::thread_rng;
use num_bigint::BigInt;

type CircomInput = HashMap<String, Vec<num_bigint::BigInt>>;

fn verify_proof_with_r1cs(inputs: CircomInput, wasm_path: &str, r1cs_path: &str) {
    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Bn254>::new(wasm_path, r1cs_path).unwrap();

    // Insert our public inputs as key value pairs
    let mut builder = CircomBuilder::new(cfg);
    for (k, v) in inputs {
        for e in v {
            builder.push_input(&k, e);
        }
    }
    // Create an empty instance for setting it up
    let circom = builder.setup();

    // Run a trusted setup
    let mut rng = thread_rng();
    let params =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circom, &mut rng).unwrap();

    // Get the populated instance of the circuit with the witness
    let circom = builder.build().unwrap();

    let inputs = circom.get_public_inputs().unwrap();

    // Generate the proof
    let proof = Groth16::<Bn254>::prove(&params, circom, &mut rng).unwrap();

    // Check that the proof is valid
    let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();
    let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs).unwrap();
    assert!(verified);
}

fn verify_proof_without_r1cs(inputs: CircomInput, zkey_path: &str, wasm_path: &str) {
    let mut file = File::open(zkey_path).unwrap();
    let (params, matrices) = read_zkey(&mut file).unwrap();

    let mut wtns = WitnessCalculator::new(wasm_path).unwrap();

    let mut rng = thread_rng();
    use ark_std::UniformRand;
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;
    let rng = &mut rng;

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let full_assignment = wtns
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .unwrap();
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &params,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        full_assignment.as_slice(),
    )
    .unwrap();

    let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();
    let inputs = &full_assignment[1..num_inputs];
    let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, inputs).unwrap();

    assert!(verified);
}

fn main() {
    /* mycircuit example copied from https://github.com/gakonst/ark-circom */
    verify_proof_with_r1cs(
        HashMap::from([
            ("a".to_string(), vec![BigInt::from(3)]),
            ("b".to_string(), vec![BigInt::from(11)]),
        ]),
        "./examples/circom-inputs/mycircuit.wasm",
        "./examples/circom-inputs/mycircuit.r1cs",
    );
    println!("mycircuit with r1cs pass");

    verify_proof_without_r1cs(
        HashMap::from([
            ("a".to_string(), vec![BigInt::from(3)]),
            ("b".to_string(), vec![BigInt::from(11)]),
        ]),
        "./examples/circom-inputs/mycircuit.zkey",
        "./examples/circom-inputs/mycircuit.wasm",
    );
    println!("mycircuit without r1cs pass");

    verify_proof_with_r1cs(
        load_rsa_test_vector(),
        "./examples/circom-inputs/rsa_sha2.wasm",
        "./examples/circom-inputs/rsa_sha2.r1cs",
    );
    println!("rsa_sha2 with r1cs pass");

    // Commented because the size of zkey is too big for git
    // verify_proof_without_r1cs(
    //     load_rsa_test_vector(),
    //     "./circom-inputs/rsa_sha2.zkey",
    //     "./circom-inputs/rsa_sha2.wasm"
    // );
    // println!("rsa_sha2 without r1cs pass");
}

fn load_rsa_test_vector() -> CircomInput {
    let signature: Vec<u64> = vec![
        7147802607275642658,
        15577333482908311137,
        8554497539651460520,
        15249273760168451356,
        1393273989552256398,
        11089958655944049941,
        10591456032172199765,
        2335342757249459473,
        8336025561765630537,
        13252172616878338760,
        13109326872360562939,
        2686885245518713997,
        6608491802980430994,
        5012529043457126898,
        2078657532217325110,
        13306300692890002264,
        8614172926201479194,
        1689676805099170611,
        10290691072982548167,
        16506492336183114561,
        4668385444190909190,
        13247702821337111779,
        6886943854419847658,
        14109186297157297529,
        11449592486888529612,
        16188111621787678559,
        6901191095508160857,
        16000985115930218414,
        2699559607621511871,
        3043401216957656029,
        3972823842668936434,
        14433539567680664197,
    ];

    let modulus: Vec<u64> = vec![
        13201601703605019737,
        3105180630311405376,
        10674213731329952926,
        8859932086429166954,
        2985985604654853372,
        5812576696360944702,
        14466253622234018068,
        3413627959992405717,
        12543592204804631736,
        2112540841378563073,
        13836879701439409726,
        2467055072135046797,
        2789289658861274560,
        11183457292512218428,
        1678790129368918285,
        12604776924702623354,
        1023186928398738075,
        13874604535702843790,
        9170383777734919534,
        10172142195946120636,
        8232821389595270653,
        17527791760659271675,
        18239557468616943896,
        7284179943295855990,
        331408201522522826,
        9180229766078227923,
        1000842694280619245,
        12729605491450933452,
        5235217269677597244,
        15345138813548740705,
        8884864492787055437,
        14783373753312293031,
    ];

    let base_message: Vec<u64> = vec![
        10787603150316114092,
        13213410277675934618,
        11919946204020583925,
        17678436471734420583,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];

    HashMap::from([
        (
            "signature".to_string(),
            signature.into_iter().map(BigInt::from).collect(),
        ),
        (
            "modulus".to_string(),
            modulus.into_iter().map(BigInt::from).collect(),
        ),
        (
            "base_message".to_string(),
            base_message.into_iter().map(BigInt::from).collect(),
        ),
    ])
}
