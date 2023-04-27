const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const crypto = require("crypto");
const jose = require("jose");

const circuit_utils = require("../js/circuitutils");
const utils = require("../js/utils");
const b64utils = require("../js/b64utils");
const test = require("../js/test");
const GOOGLE = require("./testvectors").google;
const FB = require("./testvectors").facebook;
const checkMaskedContent = require("../js/verify").checkMaskedContent;

const inWidth = "../js/constants".inWidth;
const outWidth = "../js/constants".outWidth;

// Generates new circuit for a given JWT 
genCircuit = (async (jwt, inCount) => {
    const [_, payload, __] = jwt.split('.');
    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const sub_claim = utils.getClaimString(decoded_payload, "sub");
    const sub_in_b64 = utils.removeDuplicates(b64utils.getAllExtendedBase64Variants(sub_claim));

    const circuit = await test.genMain(
        path.join(__dirname, "..", "circuits", "jwt_proof.circom"),
        "JwtProof", [
            inCount, 
            sub_in_b64.map(e => e[0].split('').map(c => c.charCodeAt())),
            sub_in_b64.length, 
            sub_in_b64[0][0].length,
            sub_in_b64.map(e => e[1])
        ]
    );

    return circuit;
});

// Tests a given circuit with the given JWT
genJwtProof = (async (jwt, inCount, claimsToReveal, circuit, jwk = "") => {
    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;
    var inputs = await circuit_utils.genJwtProofInputs(input, inCount, claimsToReveal, inWidth, outWidth);
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
        inCount
    );

    // Check signature
    if (jwk) {
        const pubkey = await jose.importJWK(jwk);
        assert.isTrue(crypto.createVerify('RSA-SHA256')
                            .update(input)
                            .verify(pubkey, Buffer.from(signature, 'base64url')),
                            "Signature does not correspond to hash");    
    }
})

describe("JWT Proof", function() {
    it("Google", async function() {
        const circuit = await genCircuit(GOOGLE["jwt"], 64 * 11);
        await genJwtProof(GOOGLE["jwt"], 64 * 11, ["iss", "aud", "nonce"], circuit, GOOGLE["jwk"]);
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

    const inCount = 64 * 6;

    before(async () => {
        console.log("JWT: " + jwt);
        circuit = await genCircuit(jwt, inCount);
    });

    it("No change", async function() {
        await genJwtProof(
            jwt,
            inCount,
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
            inCount,
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
            inCount,
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
            inCount,
            ["iss", "aud", "nonce"],
            circuit
        );
    });

    it.only("(Fail) Sub claim has invalid value!", async () => {
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
                    inCount,
                    ["iss", "aud", "nonce"],
                    circuit
                );
            } catch (error) {
                assert.include(error.message, 'Error in template B64SubstrExists');
            }
        }
    });
});