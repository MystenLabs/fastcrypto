const chai = require("chai");
const assert = chai.assert;

const circuit = require("../js/circuitutils");
const utils = require("../js/utils");
const jwtutils = require("../js/jwtutils");
const verify = require("../js/verify");

const GOOGLE1 = require("./testvectors").google.jwt;
const GOOGLE2 = require("./testvectors").google_old.jwt;
const FB = require("./testvectors").facebook.jwt;

function getAllClaims(jwt) {
    const payload = Buffer.from(jwt.split('.')[1], 'base64url').toString();
    const json = JSON.parse(payload);
    return Object.keys(json);
}

function maskTesting(jwt, claimsToReveal, print=false) {
    if (print) console.log("Reveal:", claimsToReveal);
    var mask = circuit.genJwtMask(jwt, claimsToReveal);
    if (print) console.log("Mask:", mask.join(''));

    var masked_jwt = utils.applyMask(new Uint8Array(Buffer.from(jwt)) , mask);
    masked_jwt = Buffer.from(masked_jwt).toString();
    if (print) console.log("Masked JWT:", masked_jwt);

    const header_length = masked_jwt.indexOf('.');
    if (header_length == -1) throw new Error("Invalid header length");

    const encoded_header = masked_jwt.slice(0, header_length);
    // const extracted_header = Buffer.from(encoded_header, 'base64url').toString('utf8');
    if (encoded_header !== jwt.split('.')[0]) {
        console.log("header", encoded_header, "\njwt", jwt.split('.')[0]);
        throw new Error("Header not found in masked JWT");
    }

    const encoded_payload = masked_jwt.slice(header_length + 1);
    const extracted_claims = verify.extractClaims(encoded_payload);

    // We just check that each full claim string is present (somewhere) in the masked JWT. In practice, these would need to parsed out.
    // Note that some claims might not be at the start of an extracted_claim, e.g., if consecutive claims are being revealed.
    for (const claim of claimsToReveal) {
        const claim_string = jwtutils.getClaimString(Buffer.from(jwt.split('.')[1], 'base64url').toString(), claim);
        if (!extracted_claims.some(e => e.includes(claim_string))) {
            console.log("Can't find claim", claim, "in", extracted_claims);
            throw new Error("Claim not found in masked JWT");
        }
    }

    // First character of each extracted_claim must be either '{' or ',' or '"'
    for (const claim of extracted_claims) {
        if (!['{', ',', '"'].includes(claim[0])) {
            console.log("Invalid claim", claim);
            throw new Error("Invalid claim");
        }
    }

    if (print) console.log("Extracted claims:", extracted_claims);
    if (print) console.log('\n');
    return extracted_claims;
}

function subsets(array) {
    return array.reduce(
        (subsets, value) => subsets.concat(
            subsets.map(set => [value, ...set])
        ),
        [[]]
    );
}

describe("Masking with dummy JWTs", function() {
    // Creates a JWT-like string from a header and payload
    const constructJWT = (header, payload) => {
        jwt = utils.trimEndByChar(Buffer.from(header).toString('base64url'), '=') 
                    + '.' + utils.trimEndByChar(Buffer.from(payload).toString('base64url'), '=');
        return jwt;
    }

    it(("#1"), function() {
        header = '{"kid":abc}';
        payload = '{"iss":123,"azp":"gogle","iat":7890,"exp":101112}';

        // Create a JWT
        jwt = constructJWT(header, payload);

        // Test for all possible subsets of claims
        const claims = getAllClaims(jwt);
        assert.deepEqual(claims.sort(), ["iss", "azp", "iat", "exp"].sort());
        for (const subset of subsets(claims)) {
            maskTesting(jwt, subset);
        }
    });

    it(("#2"), function() {
        header = '{"kid":abc}';
        payload = '{"iss":1234,"azp":"gogle","iat":7890,"exp":101112}';
        jwt = constructJWT(header, payload);
        const claims = getAllClaims(jwt);
        for (const subset of subsets(claims)) {
            maskTesting(jwt, subset);
        }
    });

    it(("#3"), function() {
        header = '{"kid":abc}';
        payload = '{"iss":12345,"azp":"gogle","iat":7890,"exp":101112}';
        jwt = constructJWT(header, payload);
        const claims = getAllClaims(jwt);
        for (const subset of subsets(claims)) {
            maskTesting(jwt, subset);
        }
    });
})

describe("Masking with real JWTs", function() {
    it("Google", function() {
        const jwt = GOOGLE1.split('.').slice(0,2).join('.');
        const claims = getAllClaims(jwt);
        assert.deepEqual(claims.sort(), [
            'iss',   'azp',
            'aud',   'sub',
            'nonce', 'iat',
            'exp',   'jti'
          ].sort());
        for (const subset of subsets(claims)) {
            maskTesting(jwt, subset);
        }
    });

    it("Google again", function() {
        const jwt = GOOGLE2.split('.').slice(0,2).join('.');
        const claims = getAllClaims(jwt);
        for (const subset of subsets(claims)) {
            maskTesting(jwt, subset);
        }
    });

    it("Facebook", function() {
        const jwt = FB.split('.').slice(0,2).join('.');
        const claims = getAllClaims(jwt);
        assert.deepEqual(claims.sort(), [
            'aud',         'exp',
            'family_name', 'given_name',
            'iat',         'iss',
            'jti',         'name',
            'nonce',       'picture',
            'sub'
          ].sort());
        for (const subset of subsets(claims)) {
            maskTesting(jwt, subset);
        }
    });
});