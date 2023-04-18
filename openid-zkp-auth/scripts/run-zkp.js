const fs = require("fs");
const snarkjs = require("snarkjs");

const verifier = require('../js/verify');
const GOOGLE = require("../js/testvectors").google_extension;
const circuit = require("../js/circuit");
const utils = require("../js/utils");

const WASM_FILE_PATH = "./google/google_js/google.wasm";
const ZKEY_FILE_PATH = "./google/google.zkey";
const VKEY_FILE_PATH = "./google/google.vkey";
const PROOF_FILE_PATH = "./google/google.proof";
const AUX_INPUTS_FILE_PATH = "./google/aux.json";
const PUBLIC_INPUTS_FILE_PATH = "./google/public.json";

const MAX_JWT_LENGTH = 64*11;

const groth16Prove = async (inputs, wasm_file, zkey_file) => {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        inputs, 
        wasm_file, 
        zkey_file
    );

    return { proof, publicSignals };
}

const groth16Verify = async (proof, public_inputs, vkey_file) => {
    const vkey = JSON.parse(fs.readFileSync(vkey_file));

    const res = await snarkjs.groth16.verify(vkey, public_inputs, proof);

    if (res === true) {
        console.log("Verification OK");
    } else {
        console.error("Invalid Proof");
    }
}

// Generate a ZKP for a JWT. If a JWK is provided, the JWT is verified first (sanity check).
const zkOpenIDProve = async (jwt, jwk) => {
    // Check if the JWT is a valid OpenID Connect ID Token if a JWK is provided
    if (jwk) {
        console.log("Verifying JWT with JWK...");
        verifier.verifyJwt(jwt, jwk);
    }

    // Split the JWT into its three parts
    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;

    var inputs = await circuit.genJwtProofInputs(input, MAX_JWT_LENGTH, ["iss", "aud", "nonce"]);
    const masked_content = utils.applyMask(inputs["content"], inputs["mask"]);

    const crypto = require("crypto");
    const hash = BigInt("0x" + crypto.createHash("sha256").update(input).digest("hex"));

    const auxiliary_inputs = {
        "jwt_signature": signature,
        "masked_content": masked_content,
        "jwt_sha2_hash": [(hash / 2n**128n).toString(), (hash % 2n**128n).toString()],
        "payload_start_index": inputs["payload_start_index"],
        "payload_len": inputs["payload_len"],
        "eph_public_key": inputs["eph_public_key"].map(e => e.toString()),
        "max_epoch": inputs["max_epoch"],
        "num_sha2_blocks": inputs["num_sha2_blocks"]
    }

    // Generate ZKP
    console.log("Generating ZKP...");
    const { proof, publicSignals: public_signals } = await groth16Prove(inputs, WASM_FILE_PATH, ZKEY_FILE_PATH);
    utils.writeJSONToFile(proof, PROOF_FILE_PATH);
    utils.writeJSONToFile(public_signals, PUBLIC_INPUTS_FILE_PATH);
    utils.writeJSONToFile(auxiliary_inputs, AUX_INPUTS_FILE_PATH);

    return { 
        "zkproof": proof, 
        "public_inputs": public_signals,
        "auxiliary_inputs": auxiliary_inputs
    }
};

// Not a full implementation: only implements some of the checks. For a full implementation, see the Authenticator code in Rust. 
const zkOpenIDVerify = async (proof) => {
    const { zkproof, public_inputs, auxiliary_inputs: auxiliary_inputs } = proof; 

    // Verify ZKP
    console.log("Verifying ZKP...");
    await groth16Verify(zkproof, public_inputs, VKEY_FILE_PATH);

    verifier.verifyOpenIDProof(public_inputs, auxiliary_inputs, MAX_JWT_LENGTH);
}

// Check if the script was called directly
if (require.main === module) {
    // Read the input string from the command line arguments
    var jwt = process.argv[2];

    if (!jwt) { // this is an optional argument (for now)
        console.log("Using the default JWT..");
        jwt = GOOGLE["jwt"];
    }

    const publicKeyPath = process.argv[3];
    var jwk;

    if (!publicKeyPath) {
        console.log("Using the default JWK..");
        jwk = GOOGLE["jwk"];
    }
    else { // this is an optional argument
        // Read the JWK from the file
        fs.readFile(publicKeyPath, "utf8", (err, jwkJson) => {
            if (err) {
                console.error("Error reading JWK:", err.message);
                process.exit(1);
            }
            jwk = JSON.parse(jwkJson);
        });
    }

    // Call the processing function with the input string
    (async () => {
        try {
            const proof = await zkOpenIDProve(jwt, jwk);

            // Print the output to the console

            console.log("--------------------");

            // Verify the proof
            await zkOpenIDVerify(proof);

            process.exit(0);
        } catch (error) {
            console.error("Error in processJWT:", error);
        }
    })();
}

module.exports = zkOpenIDProve;
