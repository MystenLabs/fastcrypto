const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const b64utils = require("../js/b64utils");
const circuitutils = require("../js/circuitutils");
const constants = require('../js/constants');
const test = require("../js/test");
const utils = require("../js/utils");
const verifier = require('../js/verify');

const GOOGLE = require("./testvectors").google;
const FB = require("./testvectors").facebook;

const checkMaskedContent = require("../js/verify").checkMaskedContent;

// Generates new circuit for a given JWT 
async function genCircuit(jwt, jwtMaxLen) {
    const [_, payload, __] = jwt.split('.');
    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const sub_claim = utils.getClaimString(decoded_payload, "sub");
    const sub_in_b64 = utils.removeDuplicates(b64utils.getAllExtendedBase64Variants(sub_claim));

    const circuit = await test.genMain(
        path.join(__dirname, "..", "circuits", "jwt_proof.circom"),
        "JwtProof", [
            jwtMaxLen,
            sub_in_b64.map(e => e[0].split('').map(c => c.charCodeAt())),
            sub_in_b64.length,
            sub_in_b64[0][0].length,
            sub_in_b64.map(e => e[1])
        ]
    );

    return circuit;
}

async function genCircuitUA(jwtMaxLen, maxOptions, maxSubLength) {
    return await test.genMain(
        path.join(__dirname, "..", "circuits", "jwt_proof_ua.circom"), "JwtProofUA", [
            jwtMaxLen,
            maxOptions,
            maxSubLength
        ]
    );
}

// Tests a given circuit with the given JWT
async function genJwtProof(jwt, jwtMaxLen, claimsToReveal, circuit) {
    const [header, payload, _] = jwt.split('.');
    const input = header + '.' + payload;
    var inputs = await circuitutils.genJwtProofInputs(input, jwtMaxLen, claimsToReveal);
    // utils.writeJSONToFile(inputs, "inputs.json");

    const w = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(w);

    // Check masked content
    const masked_content = utils.applyMask(inputs["content"], inputs["mask"]);
    checkMaskedContent(
        masked_content,
        inputs["num_sha2_blocks"],
        inputs["payload_start_index"],
        inputs["payload_len"],
        jwtMaxLen
    );
}

async function genJwtProofUA(jwt, jwtMaxLen, claimsToReveal, maxSubLength, circuit){
    const [header, payload, _] = jwt.split('.');
    const input = header + '.' + payload;
    var inputs = await circuitutils.genJwtProofUAInputs(
        input, 
        jwtMaxLen, 
        claimsToReveal,
        maxSubLength
    );
    utils.writeJSONToFile(inputs, "inputs.json");

    const w = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(w);
}

describe("JWT Proof", function() {
    describe("Google", async function() {
        it("Verify JWT with JWK", async function() {
            verifier.verifyJwt(GOOGLE["jwt"], GOOGLE["jwk"]);
        });

        it.only("(User-specific) Prove", async function() {
            const circuit = await genCircuit(GOOGLE["jwt"], constants.google.jwtMaxLen);
            await genJwtProof(
                GOOGLE["jwt"],
                constants.google.jwtMaxLen,
                constants.google.claimsToReveal,
                circuit
            );
        });

        it("(User-agnostic) Prove", async function() {
            const circuit = await genCircuitUA(
                constants.google.jwtMaxLen,
                constants.nOptions,
                constants.google.maxSubstrLen
            );
            await genJwtProofUA(
                GOOGLE["jwt"],
                constants.google.jwtMaxLen,
                constants.google.claimsToReveal,
                constants.google.maxSubstrLen,
                circuit
            );
        });
    });

    // TODO: To be updated after pairwise IDs are supported
    it("Facebook", async function() {
        const circuit = await genCircuit(FB["jwt"], 64 * 14);
        await genJwtProof(FB["jwt"], 64 * 14, ["iss", "aud", "nonce"], circuit, FB["jwk"]);
    });
});

describe("Tests with crafted JWTs", () => {
    const header = {
        "alg":"RS256",
        "kid":"827917329",
        "typ":"JWT"
    };
    const payload = { // Resembles Google's JWT
        iss: 'google.com',
        azp: 'example.com',
        aud: 'example.com',
        sub: '4840061',
        nonce: 'abcd',
        iat: 4,
        exp: 4,
        jti: 'a8a0728a'
    };

    // const b64header = utils.trimEndByChar(Buffer.from(header, 'base64url').toString('base64url'), '=');
    // const b64payload = utils.trimEndByChar(Buffer.from(payload, 'base64url').toString('base64url'), '=');
    const jwt = utils.constructJWT(header, payload);

    const jwtMaxLen = 64 * 6;

    before(async () => {
        console.log("JWT: " + jwt);
        circuit = await genCircuit(jwt, jwtMaxLen);
    });

    it("No change", async function() {
        await genJwtProof(
            jwt,
            jwtMaxLen,
            ["iss", "aud", "nonce"],
            circuit
        );
    });

    it("Sub claim comes first!", async function() {
        const new_payload = {
            sub: '4840061',
            iss: 'google.com',
            azp: 'example.com',
            aud: 'example.com',
            nonce: 'abcd',
            iat: 4,
            exp: 4,
            jti: 'a8a0728a'
        };
        const new_jwt = utils.constructJWT(header, new_payload);
        await genJwtProof(
            new_jwt,
            jwtMaxLen,
            ["iss", "aud", "nonce"],
            circuit
        );
    });

    it("Sub claim comes last!", async function() {
        const new_payload = {
            iss: 'google.com',
            azp: 'example.com',
            aud: 'example.com',
            nonce: 'abcd',
            iat: 4,
            exp: 4,
            jti: 'a8a0728a',
            sub: '4840061'
        };
        const new_jwt = utils.constructJWT(header, new_payload);
        await genJwtProof(
            new_jwt,
            jwtMaxLen,
            ["iss", "aud", "nonce"],
            circuit
        );
    });

    it("Order of claims is jumbled!", async function() {
        const new_payload = {
            iat: 4,
            iss: 'google.com',
            aud: 'example.com',
            jti: 'a8a0728a',
            exp: 4,
            sub: '4840061',
            azp: 'example.com',
            nonce: 'abcd',
        };
        const new_jwt = utils.constructJWT(header, new_payload);
        await genJwtProof(
            new_jwt,
            jwtMaxLen,
            ["iss", "aud", "nonce"],
            circuit
        );
    });

    it("(Fail) Sub claim has invalid value!", async () => {
        const failing_cases = ['4840062', '3840061', '48', '48400610', '04840061'];
        for (var i = 0; i < failing_cases.length; i++) {
            const sub = failing_cases[i];
            const new_payload = {
                iss: 'google.com',
                azp: 'example.com',
                aud: 'example.com',
                nonce: 'abcd',
                iat: 4,
                exp: 4,
                jti: 'a8a0728a',
                sub: sub
            };
            const new_jwt = utils.constructJWT(header, new_payload);
            try {
                await genJwtProof(
                    new_jwt,
                    jwtMaxLen,
                    ["iss", "aud", "nonce"],
                    circuit
                );
            } catch (error) {
                assert.include(error.message, 'Error in template B64SubstrExists');
            }
        }
    });
});