const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const expect = chai.expect;

const jwtutils = require("../js/jwtutils");
const circuitutils = require("../js/circuitutils");
const constants = require('../js/constants');
const test = require("../js/test");
const utils = require("../js/utils");
const verify = require('../js/verify');

async function genCircuit(maxContentLen, maxSubLength) {
    return await test.genMain(
        path.join(__dirname, "..", "circuits", "jwt_proof_ua.circom"), "JwtProofUA", [
            maxContentLen,
            maxSubLength
        ]
    );
}

async function genProof(jwt, maxContentLen, claimsToReveal, maxSubLength, circuit, nTamper = false, tamperedClaim = ''){
    const [header, payload, _] = jwt.split('.');
    const input = header + '.' + payload;
    var [inputs, auxiliary_inputs] = await circuitutils.genJwtProofUAInputs(
        input, 
        maxContentLen, 
        claimsToReveal,
        maxSubLength
    );
    if (nTamper) { // Tamper with some inputs for testing purposes
        inputs["subject_id"] = utils.padWithZeroes(tamperedClaim.split('').map(c => c.charCodeAt()), maxSubLength);
        inputs["sub_length_ascii"] = tamperedClaim.length;
    }
    utils.writeJSONToFile(inputs, "inputs.json");

    const w = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(w);

    const masked_content = utils.applyMask(inputs["content"], inputs["mask"]);
    verify.checkMaskedContent(
        masked_content,
        inputs["num_sha2_blocks"],
        inputs["payload_start_index"],
        inputs["payload_len"],
        maxContentLen
    );

    return [inputs, auxiliary_inputs];
}

describe("JWT Proof", function() {
    const GOOGLE = require("./testvectors").google;
    const TWITCH = require("./testvectors").twitch;
        
    const test_vectors = {
        google: {
            jwt: GOOGLE["jwt"],
            jwk: GOOGLE["jwk"],
            maxContentLen: constants.google.maxContentLen,
            claimsToReveal: constants.google.claimsToReveal,
            maxSubstrLen: constants.google.maxSubstrLen
        }, 
        twitch: {
            jwt: TWITCH["jwt"],
            jwk: TWITCH["jwk"],
            maxContentLen: constants.twitch.maxContentLen,
            claimsToReveal: constants.twitch.claimsToReveal,
            maxSubstrLen: constants.twitch.maxSubstrLen
        }
    }

    for (const [provider, constants] of Object.entries(test_vectors)) {
        describe(provider, async function() {
            it("Verify JWT with JWK", async function() {
                verify.verifyJwt(constants["jwt"], constants["jwk"]);
            });

            it("Prove", async function() {
                const circuit = await genCircuit(
                    constants["maxContentLen"],
                    constants["maxSubstrLen"]
                );
                await genProof(
                    constants["jwt"],
                    constants["maxContentLen"],
                    constants["claimsToReveal"],
                    constants["maxSubstrLen"],
                    circuit
                );
            });
        });
    }
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
    const claim_string = '"sub":"4840061",';
    const sub_commitment = '6621753577113798222817846331081670375939652571040388319046768774068537034346';
    const pin = 123456789;

    // const b64header = utils.trimEndByChar(Buffer.from(header, 'base64url').toString('base64url'), '=');
    // const b64payload = utils.trimEndByChar(Buffer.from(payload, 'base64url').toString('base64url'), '=');
    const jwt = test.constructJWT(header, payload);

    const maxContentLen = 64 * 6;
    const maxSubLength = 21;

    before(async () => {
        expect(jwtutils.getClaimString(JSON.stringify(payload), "sub")).equals(claim_string);
        expect(claim_string.length).at.most(maxSubLength);
        expect((await utils.commitSubID(claim_string.slice(0, -1), pin, maxSubLength)).toString()).equals(sub_commitment);
        console.log("JWT: ", jwt);
        circuit = await genCircuit(maxContentLen, maxSubLength);
    });

    it("No change", async function() {
        const [_, aux] = await genProof(
            jwt,
            maxContentLen,
            ["iss", "aud", "nonce"],
            maxSubLength,
            circuit
        );
        expect(aux["sub_id_com"]).equals(sub_commitment);
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
        const new_jwt = test.constructJWT(header, new_payload);
        const [_, aux] = await genProof(
            new_jwt,
            maxContentLen,
            ["iss", "aud", "nonce"],
            maxSubLength,
            circuit
        );
        expect(aux["sub_id_com"]).equals(sub_commitment);
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
        const new_jwt = test.constructJWT(header, new_payload);
        const [_, aux] = await genProof(
            new_jwt,
            maxContentLen,
            ["iss", "aud", "nonce"],
            maxSubLength,
            circuit
        );
        expect(aux["sub_id_com"]).equals(sub_commitment);
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
        const new_jwt = test.constructJWT(header, new_payload);
        const [_, aux] = await genProof(
            new_jwt,
            maxContentLen,
            ["iss", "aud", "nonce"],
            maxSubLength,
            circuit
        );
        expect(aux["sub_id_com"]).equals(sub_commitment);
    });

    it("(Fail) Sub claim has invalid value!", async () => {
        const failing_cases = [
            '4840062', 
            '3840061', 
            '48', 
            '48400610', 
            '04840061',
            4840061 // Number
        ];
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
            const new_jwt = test.constructJWT(header, new_payload);
            // console.log(JSON.stringify(new_payload));
            // console.log("New JWT: ", new_jwt);

            // The on-chain address should be different
            const [_, aux] = await genProof(
                new_jwt,
                maxContentLen,
                ["iss", "aud", "nonce"],
                maxSubLength,
                circuit
            );
            expect(aux["sub_id_com"]).not.equals(sub_commitment);

            // Fake the subject_id array to match sub_commitment
            try {
                await genProof(
                    new_jwt,
                    maxContentLen,
                    ["iss", "aud", "nonce"],
                    maxSubLength,
                    circuit,
                    true,
                    claim_string
                );
                assert.fail("Should have failed");
            } catch (error) {
                assert.include(error.message, 'Error in template ASCIISubstrExistsInB64');
            }
        }
    });
});