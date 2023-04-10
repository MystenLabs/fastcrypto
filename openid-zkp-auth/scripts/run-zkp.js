const fs = require("fs");
const snarkjs = require("snarkjs");

const jwtverifier = require('../js/jwtverifier');
const GOOGLE = require("../js/testvectors").google_extension;
const circuit = require("../js/circuit");
const utils = require("../js/utils");

const WASM_FILE_PATH = "./google/google_js/google.wasm";
const ZKEY_FILE_PATH = "./google/google.zkey";
const VKEY_FILE_PATH = "./google/google.vkey";

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
        jwtverifier(jwt, jwk);
    }

    // Split the JWT into its three parts
    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;

    var inputs = await circuit.genJwtProofInputs(input, MAX_JWT_LENGTH, ["iss", "aud", "nonce"]);
    const masked_content = utils.applyMask(inputs["content"], inputs["mask"]);

    const auxilary_inputs = {
        "jwt_signature": signature,
        "masked_content": masked_content,
    }

    // Generate ZKP
    console.log("Generating ZKP...");
    const { proof, publicSignals } = await groth16Prove(inputs, WASM_FILE_PATH, ZKEY_FILE_PATH);

    return { 
        "zkproof": proof, 
        "public_inputs": publicSignals,
        "auxilary_inputs": auxilary_inputs
    }
};

// Not a full implementation: only implements some of the checks. For a full implementation, see the Authenticator code in Rust. 
const zkOpenIDVerify = async (proof) => {
    const { zkproof, public_inputs, auxilary_inputs } = proof;

    // Verify ZKP
    console.log("Verifying ZKP...");
    await groth16Verify(zkproof, public_inputs, VKEY_FILE_PATH);

    const { jwt_signature, masked_content } = auxilary_inputs;

    // Extract last_block from public_inputs
    const last_block = 11;

    utils.checkMaskedContent(masked_content, last_block, MAX_JWT_LENGTH);
}

// Check if the script was called directly
if (require.main === module) {
    // Read the input string from the command line arguments
    const jwt = process.argv[2];

    if (!jwt) {
        console.error("Please provide a string as input.");
        process.exit(1);
    }

    const publicKeyPath = process.argv[3];
    var jwk = GOOGLE["jwk"];

    if (publicKeyPath) { // this is an optional argument
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
            console.log("Proof:", proof);

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
