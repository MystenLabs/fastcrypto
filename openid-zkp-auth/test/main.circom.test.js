const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const expect = chai.expect;

const jwtutils = require("../js/jwtutils");
const circuitutils = require("../js/circuitutils");
const constants = require('../js/constants');
const devVars = constants.dev;
const utils = require("../js/utils");
const verify = require('../js/verify');

const testutils = require("./testutils");

async function genCircuit(
    maxContentLen = constants.maxContentLen,
    maxExtClaimLen = constants.maxExtClaimLen,
    maxKeyClaimNameLen = constants.maxKeyClaimNameLen,
) {
    return await testutils.genMain(
        path.join(__dirname, "../circuits", "jwt_proof_ua.circom"), "JwtProofUA", [
            maxContentLen,
            maxExtClaimLen,
            maxKeyClaimNameLen
        ]
    );
}

async function genProof(
    circuit, jwt, keyClaimName = "sub",
    maxContentLen = constants.maxContentLen, maxExtClaimLen = constants.maxExtClaimLen,
    maxKeyClaimNameLen = constants.maxKeyClaimNameLen, maxKeyClaimValueLen = constants.maxKeyClaimValueLen,
    claimsToReveal = constants.claimsToReveal, ephPK = devVars.ephPK,
    maxEpoch = devVars.maxEpoch, jwtRand = devVars.jwtRand, userPIN = devVars.pin
) {
    const [header, payload, _] = jwt.split('.');
    const input = header + '.' + payload;
    var [inputs, auxiliary_inputs] = await circuitutils.genJwtProofUAInputs(
        input, 
        maxContentLen,
        maxExtClaimLen,
        maxKeyClaimNameLen,
        maxKeyClaimValueLen,
        keyClaimName,
        claimsToReveal,
        ephPK, 
        maxEpoch,
        jwtRand,
        userPIN
    );
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
    const GOOGLE = require("../testvectors").google;
    const TWITCH = require("../testvectors").twitch;

    const test_vectors = {
        google: {
            jwt: GOOGLE["jwt"],
            jwk: GOOGLE["jwk"]
        },
        twitch: {
            jwt: TWITCH["jwt"],
            jwk: TWITCH["jwk"]
        }
    }

    for (const [provider, constants] of Object.entries(test_vectors)) {
        describe(provider, async function() {
            it.skip("Verify JWT with JWK", async function() {
                verify.verifyJwt(constants["jwt"], constants["jwk"]);
            });

            it("Prove w/ sub", async function() {
                const circuit = await genCircuit();
                await genProof(
                    circuit,
                    constants["jwt"]
                );
            });

            it("Prove w/ email", async function() {
                const circuit = await genCircuit();
                await genProof(
                    circuit,
                    constants["jwt"],
                    "email"
                );
            });
        });
    }
});

// Stringify and convert to base64. 
// Note: Signature is omitted as this function is only meant for testing.
function constructJWT(header, payload) {
    header = JSON.stringify(header);
    payload = JSON.stringify(payload);
    const b64header = Buffer.from(header).toString('base64url');
    const b64payload = Buffer.from(payload).toString('base64url');

    if (b64header.slice(-1) === '=' || b64payload.slice(-1) === '=') {
        throw new Error("Unexpected '=' in base64url string");
    }

    return b64header + "." + b64payload + ".";
}

describe("Tests with crafted JWTs", () => { 
    const header = {
        "alg":"RS256",
        "kid":"827917329",
        "typ":"JWT"
    };
    const claim_string = '"sub":"4840061",';
    const pin = devVars.pin;
    const nonce = "GCwq2zCuqtsa1BhaAc2SElwUoYv8jKhE6vs6Vmepu2M";
    const payload = { // Resembles Google's JWT
        iss: 'google.com',
        azp: 'example.com',
        aud: 'example.com',
        sub: '4840061',
        email: 'example@gmail.com',
        nonce: nonce,
        iat: 4,
        exp: 4,
        jti: 'a8a0728a'
    };

    const jwt = constructJWT(header, payload);
    const maxContentLen = 64 * 6;
    const maxExtClaimLen = constants.maxExtClaimLen;
    const maxKeyClaimNameLen = constants.maxKeyClaimNameLen;
    const maxKeyClaimValueLen = constants.maxKeyClaimValueLen;

    const seed_sub = 3933397123257831927251308270714554907807704888576094124721682124818019353989n;
    const seed_email = 1973999242154691951111604273911528395925144468932358877866874679764640280443n;

    before(async () => {
        expect(jwtutils.getExtendedClaim(JSON.stringify(payload), "sub")).equals(claim_string);
        expect(claim_string.length).at.most(maxExtClaimLen);
        expect(await circuitutils.computeNonce()).equals(nonce);
        expect(payload.sub.length).at.most(maxKeyClaimValueLen);
        expect(await utils.deriveAddrSeed(payload.sub, pin, maxKeyClaimValueLen)).equals(seed_sub);
        expect(payload.email.length).at.most(maxKeyClaimValueLen);
        expect(await utils.deriveAddrSeed(payload.email, pin, maxKeyClaimValueLen)).equals(seed_email);
        console.log("JWT: ", jwt);
    });

    beforeEach(async () => {
        circuit = await genCircuit(maxContentLen, maxExtClaimLen, maxKeyClaimNameLen);
    });

    it("No change", async function() {
        const [_, aux] = await genProof(
            circuit,
            jwt,
            "sub",
            maxContentLen
        );
        expect(aux["addr_seed"]).equals(seed_sub);
    });

    it("Sub claim comes first!", async function() {
        const new_payload = {
            sub: '4840061',
            iss: 'google.com',
            azp: 'example.com',
            aud: 'example.com',
            nonce: nonce,
            iat: 4,
            exp: 4,
            jti: 'a8a0728a'
        };
        const new_jwt = constructJWT(header, new_payload);
        const [_, aux] = await genProof(
            circuit,
            new_jwt,
            "sub",
            maxContentLen
        );
        expect(aux["addr_seed"]).equals(seed_sub);
    });

    it("Sub claim comes last!", async function() {
        const new_payload = {
            iss: 'google.com',
            azp: 'example.com',
            aud: 'example.com',
            nonce: nonce,
            iat: 4,
            exp: 4,
            jti: 'a8a0728a',
            sub: '4840061'
        };
        const new_jwt = constructJWT(header, new_payload);
        const [_, aux] = await genProof(
            circuit,
            new_jwt,
            "sub",
            maxContentLen
        );
        expect(aux["addr_seed"]).equals(seed_sub);
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
            nonce: nonce,
        };
        const new_jwt = constructJWT(header, new_payload);
        const [_, aux] = await genProof(
            circuit,
            new_jwt,
            "sub",
            maxContentLen
        );
        expect(aux["addr_seed"]).equals(seed_sub);
    });

    it("(Fail) Nonce has invalid value!", async () => {
        const new_payload = {
            sub: '4840061',
            iss: 'google.com',
            azp: 'example.com',
            aud: 'example.com',
            nonce: 'JMi6c_3qXn1H8UX5la1P6YDwThkN5LZxqagTyjfiYwU', // incorrect nonce
            iat: 4,
            exp: 4,
            jti: 'a8a0728a'
        };
        const new_jwt = constructJWT(header, new_payload);
        try {
            const [b64header, b64payload,] = new_jwt.split('.');
            var [inputs, ] = await circuitutils.genJwtProofUAInputs(
                b64header + '.' + b64payload, 
                maxContentLen, 
                maxExtClaimLen,
                maxKeyClaimNameLen,
                maxKeyClaimValueLen,
                "sub",
                constants.claimsToReveal, 
                devVars.ephPK, 
                devVars.maxEpoch, 
                devVars.jwtRand, 
                devVars.pin,
                false // set to false to turn off JS sanity checks
            );
            await circuit.calculateWitness(inputs, true);
        } catch (error) {
            assert.include(error.message, 'Error in template NonceChecker');
        }
    });

    it("No change w/ email", async function() {
        const [_, aux] = await genProof(
            circuit,
            jwt,
            "email",
            maxContentLen
        );
        expect(aux["addr_seed"]).equals(seed_email);
    });
});