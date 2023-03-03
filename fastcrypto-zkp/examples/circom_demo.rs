/* Examples copied from https://github.com/gakonst/ark-circom */

use std::{fs::File, collections::HashMap};

use ark_circom::{CircomConfig, CircomBuilder, read_zkey, WitnessCalculator, CircomReduction};

use ark_bn254::Bn254;

use ark_groth16::{generate_random_parameters, create_proof_with_reduction_and_matrices, 
                  create_random_proof, prepare_verifying_key, verify_proof};

use ark_std::rand::thread_rng;

fn verify_proof_with_zkey_with_r1cs() {
    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Bn254>::new(
        "./circom-inputs/mycircuit.wasm",
        "./circom-inputs/mycircuit.r1cs",
    ).unwrap();

    // Insert our public inputs as key value pairs
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // Create an empty instance for setting it up
    let circom = builder.setup();

    // Run a trusted setup
    let mut rng = thread_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();

    // Get the populated instance of the circuit with the witness
    let circom = builder.build().unwrap();

    let inputs = circom.get_public_inputs().unwrap();

    // Generate the proof
    let proof = create_random_proof(circom, &params, &mut rng).unwrap();

    // Check that the proof is valid
    let pvk = prepare_verifying_key(&params.vk);
    let verified = verify_proof(&pvk, &proof, &inputs).unwrap();
    assert!(verified);
    println!("circom_test pass");
}

fn verify_proof_with_zkey_without_r1cs() {
    let mut file = File::open("./circom-inputs/test.zkey").unwrap();
    let (params, matrices) = read_zkey(&mut file).unwrap();

    let mut wtns = WitnessCalculator::new("./circom-inputs/mycircuit.wasm").unwrap();
    let mut inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();
    let values = inputs.entry("a".to_string()).or_insert_with(Vec::new);
    values.push(3.into());

    let values = inputs.entry("b".to_string()).or_insert_with(Vec::new);
    values.push(11.into());

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
    let proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &params,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        full_assignment.as_slice(),
    )
    .unwrap();

    let pvk = prepare_verifying_key(&params.vk);
    let inputs = &full_assignment[1..num_inputs];
    let verified = verify_proof(&pvk, &proof, inputs).unwrap();

    assert!(verified);
    println!("verify_proof_with_zkey_without_r1cs pass");
}

fn main() {
    verify_proof_with_zkey_with_r1cs();
    verify_proof_with_zkey_without_r1cs();
}