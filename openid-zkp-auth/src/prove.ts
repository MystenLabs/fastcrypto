const snarkjs = require("snarkjs");

import fs from 'fs';
import * as circuit from './circuitutils';
import { constants, PartialZKLoginSig } from './common';
import * as utils from './utils';
import * as verifier from './verify';
import { GOOGLE, TWITCH } from "../testvectors/realJWTs";
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { JWK } from 'jwk-to-pem';

const claimsToReveal = constants.claimsToReveal;

const ARTIFACTS_DIR = "./artifacts";
const PROJ_NAME = "zklogin";
const PROOF_DIR = ARTIFACTS_DIR + "/proof";

const groth16Prove = async (inputs: any, wasm_file: string, zkey_file: string) => {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        inputs, 
        wasm_file, 
        zkey_file
    );

    return { proof, publicSignals };
}

const groth16Verify = async (proof: any, public_inputs: any, vkey_file: string) => {
    const vkey = JSON.parse(fs.readFileSync(vkey_file, 'utf-8'));

    const res = await snarkjs.groth16.verify(vkey, public_inputs, proof);

    if (res === true) {
        console.log("Verification OK");
    } else {
        throw new Error("Invalid Proof");
    }
}

// Generate a ZKP for a JWT. If a JWK is provided, the JWT is verified first (sanity check).
async function zkOpenIDProve(
    jwt: string,
    ephPK: bigint,
    maxEpoch: number,
    jwtRand: bigint,
    userPIN: bigint, 
    keyClaim='sub',
    jwk?: JWK,
    write_to_file=false
): Promise<PartialZKLoginSig> {
    // Check if the JWT is a valid OpenID Connect ID Token if a JWK is provided
    if (typeof jwk !== 'undefined') {
        console.log("Verifying JWT with JWK...");
        verifier.verifyJwt(jwt, jwk);
    }

    console.time('prove');
    // Split the JWT into its three parts
    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;

    const maxContentLen = constants.maxContentLen;
    const maxExtClaimLen = constants.maxExtClaimLen;
    const maxKeyClaimNameLen = constants.maxKeyClaimNameLen;
    const maxKeyClaimValueLen = constants.maxKeyClaimValueLen;

    var [inputs, auxiliary_inputs] = await circuit.genJwtProofUAInputs(
        input, maxContentLen, maxExtClaimLen, maxKeyClaimNameLen, maxKeyClaimValueLen, keyClaim,
        claimsToReveal, ephPK, maxEpoch, jwtRand, userPIN
    );
    auxiliary_inputs.jwt_signature = signature;

    // Generate ZKP
    console.log("Generating ZKP...");
    const WASM_FILE_PATH = `${ARTIFACTS_DIR}/${PROJ_NAME}_js/${PROJ_NAME}.wasm`;
    const ZKEY_FILE_PATH = `${ARTIFACTS_DIR}/${PROJ_NAME}.zkey`;
    const { proof, publicSignals: public_signals } = await groth16Prove(inputs, WASM_FILE_PATH, ZKEY_FILE_PATH);

    console.timeEnd('prove');
    if (write_to_file) {
        const PROOF_FILE_PATH = `${PROOF_DIR}/zkp.json`;
        const AUX_INPUTS_FILE_PATH = `${PROOF_DIR}/aux.json`;
        const PUBLIC_INPUTS_FILE_PATH = `${PROOF_DIR}/public.json`;

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
const zkOpenIDVerify = async (proof: PartialZKLoginSig) => {
    const { zkproof, public_inputs, auxiliary_inputs: auxiliary_inputs } = proof; 

    // Verify ZKP
    console.log("Verifying ZKP...");
    console.time('zk verify');
    const VKEY_FILE_PATH = `${ARTIFACTS_DIR}/${PROJ_NAME}.vkey`;
    await groth16Verify(zkproof, public_inputs, VKEY_FILE_PATH);
    console.timeEnd('zk verify');

    const maxContentLen = constants.maxContentLen;
    verifier.verifyOpenIDProof(public_inputs, auxiliary_inputs, maxContentLen);
}

type CliArgs = {
    provider: string;
    jwt: string;
    eph_public_key: string;
    max_epoch: string;
    jwt_rand: string;
    user_pin: string;
    key_claim_name: string;
    public_key_path: string;
};

if (require.main === module) {
    const argv = yargs(hideBin(process.argv))
        .option('provider', {
            alias: 'p',
            type: 'string',
            description: 'Specify the provider',
            default: 'google',
            choices: ['google', 'twitch']
        })
        .option('jwt', {
            alias: 'j',
            type: 'string',
            description: 'JWT token'
        })
        .option('eph_public_key', {
            alias: 'e',
            type: 'string',
            description: 'Ephemeral public key',
            default: constants.dev.ephPK,
        })
        .option('max_epoch', {
            alias: 'm',
            type: 'string',
            description: 'Max epoch',
            default: constants.dev.maxEpoch,
        })
        .option('jwt_rand', {
            alias: 'r',
            type: 'string',
            description: 'JWT rand',
            default: constants.dev.jwtRand,
        })
        .option('user_pin', {
            alias: 'u',
            type: 'string',
            description: 'User PIN',
            default: constants.dev.pin,
        })
        .option('key_claim_name', {
            alias: 'k',
            type: 'string',
            description: 'Key claim name',
            default: 'sub',
        })
        .option('public_key_path', {
            alias: 'pk',
            type: 'string',
            description: 'Public key path',
        })
        .help()
        .argv as unknown as CliArgs;

    argv.jwt = argv.jwt || (argv.provider === "google" ? GOOGLE["jwt"] : TWITCH["jwt"]);

    let jwk: JWK | undefined;
    if (!argv.public_key_path) {
        jwk = (argv.provider === "google") ? GOOGLE.jwk : TWITCH.jwk;
    } else {
        fs.readFile(argv.public_key_path, "utf8", (err, jwkJson) => {
            if (err) {
                console.error("Error reading JWK:", err.message);
                process.exit(1);
            }
            jwk = JSON.parse(jwkJson);
        });
    }

    console.log(`Provider -> ${argv.provider}`);
    console.log(`JWT -> ${argv.jwt}`);
    console.log(`Ephemeral public key -> ${argv.eph_public_key}`);
    console.log(`Max epoch -> ${argv.max_epoch}`);
    console.log(`JWT rand -> ${argv.jwt_rand}`);
    console.log(`User PIN -> ${argv.user_pin}`);
    console.log(`Key claim name -> ${argv.key_claim_name}`);
    console.log(`Public key path -> ${argv.public_key_path}`);

    (async () => {
        try {
            const proof = await zkOpenIDProve(argv.jwt, BigInt(argv.eph_public_key), Number(argv.max_epoch),
                BigInt(argv.jwt_rand), BigInt(argv.user_pin), argv.key_claim_name, jwk, true);
            console.log("--------------------");

            // Verify the proof
            await zkOpenIDVerify(proof);

            process.exit(0);
        } catch (error) {
            console.error("Error in processJWT:", error);
        }
    })();
}