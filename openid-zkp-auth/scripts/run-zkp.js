const fs = require("fs");
const snarkjs = require("snarkjs");

const verifier = require('../js/verify');
const circuit = require("../js/circuitutils");
const utils = require("../js/utils");
const constants = require("../js/constants");

const GOOGLE = require("../test/testvectors").google;
const TWITCH = require("../test/testvectors").twitch;

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
        throw new Error("Invalid Proof");
    }
}

// Generate a ZKP for a JWT. If a JWK is provided, the JWT is verified first (sanity check).
const zkOpenIDProve = async (jwt, claimsToReveal, provider, jwk="", write_to_file=false) => {
    // Check if the JWT is a valid OpenID Connect ID Token if a JWK is provided
    if (jwk) {
        console.log("Verifying JWT with JWK...");
        verifier.verifyJwt(jwt, jwk);
    }

    // Split the JWT into its three parts
    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;

    if (!(provider in constants)) {
        throw new Error("Invalid provider. Not in constants.js");
    }
    const maxContentLen = constants[provider].maxContentLen;
    const maxSubLen = constants[provider].maxSubstrLen;
    var [inputs, auxiliary_inputs] = await circuit.genJwtProofUAInputs(input, maxContentLen, claimsToReveal, maxSubLen);
    auxiliary_inputs = Object.assign({}, auxiliary_inputs, {
        "jwt_signature": signature,
    });

    // Generate ZKP
    console.log("Generating ZKP...");
    const WASM_FILE_PATH = `./${provider}/${provider}_js/${provider}.wasm`;
    const ZKEY_FILE_PATH = `./${provider}/${provider}.zkey`;
    const { proof, publicSignals: public_signals } = await groth16Prove(inputs, WASM_FILE_PATH, ZKEY_FILE_PATH);

    if (write_to_file) {
        const PROOF_FILE_PATH = `./${provider}/${provider}.proof`;
        const AUX_INPUTS_FILE_PATH = `./${provider}/aux.json`;
        const PUBLIC_INPUTS_FILE_PATH = `./${provider}/public.json`;

        console.log("Writing proof...");
        utils.writeJSONToFile(proof, PROOF_FILE_PATH);
        utils.writeJSONToFile(public_signals, PUBLIC_INPUTS_FILE_PATH);
        utils.writeJSONToFile(auxiliary_inputs, AUX_INPUTS_FILE_PATH);
    }

    return { 
        "zkproof": proof, 
        "public_inputs": public_signals,
        "auxiliary_inputs": auxiliary_inputs
    }
};

// Not a full implementation: only implements some of the checks. 
// For a full implementation, see the Authenticator code in Rust. 
const zkOpenIDVerify = async (proof, provider) => {
    const { zkproof, public_inputs, auxiliary_inputs: auxiliary_inputs } = proof; 

    // Verify ZKP
    console.log("Verifying ZKP...");
    const VKEY_FILE_PATH = `./${provider}/${provider}.vkey`;
    await groth16Verify(zkproof, public_inputs, VKEY_FILE_PATH);

    const maxContentLen = constants[provider].maxContentLen;
    verifier.verifyOpenIDProof(public_inputs, auxiliary_inputs, maxContentLen);
}

// Check if the script was called directly
if (require.main === module) {
    var provider = process.argv[2];
    if (!provider) {
        console.log("Using the default provider..");
        provider = "google";
    } else if (provider !== "google" && provider !== "twitch") {
        console.error("Invalid provider:", provider);
        process.exit(1);
    }

    // Read the input string from the command line arguments
    var jwt = process.argv[3];

    if (!jwt) { // this is an optional argument (for now)
        console.log("Using the default JWT..");
        if (provider === "google") {
            jwt = GOOGLE["jwt"];
        } else if (provider === "twitch") {
            jwt = TWITCH["jwt"];
        }
    }

    const publicKeyPath = process.argv[4];
    var jwk;

    if (!publicKeyPath) {
        console.log("Using the default JWK..");
        if (provider === "google") {
            jwk = GOOGLE["jwk"];
        } else if (provider === "twitch") {
            jwk = TWITCH["jwk"];
        }
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
            const proof = await zkOpenIDProve(jwt, ["iss", "aud", "nonce"], provider, jwk, write_to_file=true);

            // Print the output to the console

            console.log("--------------------");

            // Verify the proof
            await zkOpenIDVerify(proof, provider);

            process.exit(0);
        } catch (error) {
            console.error("Error in processJWT:", error);
        }
    })();
}

// module.exports = {
//     zkOpenIDProve: zkOpenIDProve,
//     zkOpenIDVerify: zkOpenIDVerify
// }