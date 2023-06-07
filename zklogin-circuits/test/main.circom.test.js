const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const expect = chai.expect;

const jwtutils = require("../js/src/jwtutils");
const circuitutils = require("../js/src/circuitutils");
const constants = require('../js/src/common').constants;
const devVars = constants.dev;
const utils = require("../js/src/utils");
const verify = require('../js/src/verify');

const testutils = require("./testutils");

const circuit_constants = require('../js/src/common').circuit_params;
const dev_inputs = {
    unsigned_jwt: "",
    eph_public_key: constants.dev.ephPK,
    max_epoch: constants.dev.maxEpoch,
    jwt_rand: constants.dev.jwtRand,
    user_pin: constants.dev.pin,
    key_claim_name : "sub",
}

async function genCircuit(params = circuit_constants) {
    return await testutils.genMain(
        path.join(__dirname, "../circuits", "zklogin.circom"), "ZKLogin", [
            params.max_padded_unsigned_jwt_len,
            params.max_extended_key_claim_len,
            params.max_key_claim_name_len
        ]
    );
}

async function genProof(
    circuit, I, P = circuit_constants
) {
    var [inputs, auxiliary_inputs] = await circuitutils.genZKLoginInputs(I, P);
    utils.writeJSONToFile(inputs, "inputs.json");

    const w = await circuit.calculateWitness(inputs, true);
    await circuit.checkConstraints(w);

    verify.verifyAuxInputs(
        auxiliary_inputs,
        P.max_padded_unsigned_jwt_len
    );

    return [inputs, auxiliary_inputs];
}

describe("JWT Proof", function() {
    const GOOGLE = require("../js/testvectors/realJWTs").GOOGLE;
    const TWITCH = require("../js/testvectors/realJWTs").TWITCH;

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

    for (const [provider, values] of Object.entries(test_vectors)) {
        describe(provider, async function() {
            it.skip("Verify JWT with JWK", async function() {
                verify.verifyJwt(values["jwt"], values["jwk"]);
            });

            it("Prove w/ sub", async function() {
                const circuit = await genCircuit();
                const I = {
                    ...dev_inputs,
                    unsigned_jwt: jwtutils.removeSig(values["jwt"])
                }
                await genProof(circuit, I);
            });

            it("Prove w/ email", async function() {
                const circuit = await genCircuit();
                const I = {
                    ...dev_inputs,
                    unsigned_jwt: jwtutils.removeSig(values["jwt"]),
                    key_claim_name: "email" 
                }
                await genProof(circuit, I);
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
    const unsigned_jwt = jwtutils.removeSig(jwt);

    const test_params = {
        ...circuit_constants,
        "max_padded_unsigned_jwt_len": 64 * 6,
    }

    const seed_sub = 3933397123257831927251308270714554907807704888576094124721682124818019353989n;
    const seed_email = 1973999242154691951111604273911528395925144468932358877866874679764640280443n;

    before(async () => {
        expect(jwtutils.getExtendedClaim(JSON.stringify(payload), "sub")).equals(claim_string);
        expect(claim_string.length).at.most(test_params.max_extended_key_claim_len);
        expect(await circuitutils.computeNonce()).equals(nonce);
        expect(payload.sub.length).at.most(test_params.max_key_claim_value_len);
        expect(await utils.deriveAddrSeed(payload.sub, pin, test_params.max_key_claim_value_len)).equals(seed_sub);
        expect(payload.email.length).at.most(test_params.max_key_claim_value_len);
        expect(await utils.deriveAddrSeed(payload.email, pin, test_params.max_key_claim_value_len)).equals(seed_email);
        console.log("JWT: ", jwt);
    });

    beforeEach(async () => {
        circuit = await genCircuit(test_params);
    });

    it("No change", async function() {
        const inputs = {
            ...dev_inputs,
            unsigned_jwt: unsigned_jwt,
        };
        console.log("Inputs: ", inputs);
        const [_, aux] = await genProof(
            circuit,
            inputs,
            test_params
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
        const inputs = {
            ...dev_inputs,
            unsigned_jwt: jwtutils.removeSig(new_jwt),
        };
        const [_, aux] = await genProof(
            circuit,
            inputs,
            test_params
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
        const inputs = {
            ...dev_inputs,
            unsigned_jwt: jwtutils.removeSig(new_jwt),
        };
        const [_, aux] = await genProof(
            circuit,
            inputs,
            test_params
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
        const inputs = {
            ...dev_inputs,
            unsigned_jwt: jwtutils.removeSig(new_jwt),
        };
        const [_, aux] = await genProof(
            circuit,
            inputs,
            test_params
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
            const inputs = {
                ...dev_inputs,
                unsigned_jwt: jwtutils.removeSig(new_jwt),
            }

            var [zk_inputs, ] = await circuitutils.genZKLoginInputs(
                inputs,
                test_params,
                false // set to false to turn off JS sanity checks
            );
            await circuit.calculateWitness(zk_inputs, true);
        } catch (error) {
            assert.include(error.message, 'Error in template NonceChecker');
        }
    });

    // TODO: Test with an email of length 50
    it("No change w/ email", async function() {
        const inputs = {
            ...dev_inputs,
            unsigned_jwt: jwtutils.removeSig(jwt),
            key_claim_name: "email",
        };
        const [_, aux] = await genProof(
            circuit,
            inputs,
            test_params
        );
        expect(aux["addr_seed"]).equals(seed_email);
    });
});