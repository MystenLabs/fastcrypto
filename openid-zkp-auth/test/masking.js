const chai = require("chai");
const assert = chai.assert;

const circuit = require("../js/circuit");
const utils = require("../js/utils");
const verify = require("../js/verify");

const GOOGLE1 = require("../js/testvectors").google_extension.jwt;
const GOOGLE2 = require("../js/testvectors").google_playground.jwt;

function maskTesting(jwt, claimsToHide) {
    console.log("Hide:", claimsToHide);
    var mask = circuit.genJwtMask(jwt, claimsToHide);
    console.log(mask.join(''));

    var masked_jwt = utils.applyMask(new Uint8Array(Buffer.from(jwt)) , mask);
    masked_jwt = Buffer.from(masked_jwt).toString();
    console.log(masked_jwt);

    const header_length = masked_jwt.indexOf('.');
    if (header_length == -1) throw new Error("Invalid header length");

    const encoded_header = masked_jwt.slice(0, header_length);
    // const extracted_header = Buffer.from(encoded_header, 'base64').toString('utf8');
    if (encoded_header !== jwt.split('.')[0]) {
        console.log("header", encoded_header, "\njwt", jwt.split('.')[0]);
        throw new Error("Header not found in masked JWT");
    }

    const encoded_payload = masked_jwt.slice(header_length + 1);
    const extracted_claims = verify.extractClaims(encoded_payload);
    for (const claim of claimsToHide) {
        const claim_string = utils.getClaimString(Buffer.from(jwt.split('.')[1], 'base64').toString(), claim);
        if (!extracted_claims.some(e => e.includes(claim_string))) {
            console.log("Can't find claim", claim, "in", extracted_claims);
            throw new Error("Claim not found in masked JWT");
        }
    }
    console.log('\n');
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

describe("Masking with dummy JWTs", () => {
    // Creates a JWT-like string from a header and payload
    const constructJWT = (header, payload) => {
        jwt = utils.trimEndByChar(Buffer.from(header).toString('base64'), '=') 
                    + '.' + utils.trimEndByChar(Buffer.from(payload).toString('base64'), '=');
        return jwt;
    }

    it(("#1"), () => {
        header = '{"kid":abc}';
        payload = '{"iss":123,"azp":"gogle","iat":7890,"exp":101112}';
        console.log(header + '.' + payload);

        // Create a JWT
        jwt = constructJWT(header, payload);
        console.log(jwt);

        // Test for all possible subsets of claims
        const claims = ["iss", "azp", "iat", "exp"];
        for (const subset of subsets(claims)) {
            maskTesting(jwt, subset);
        }
    });
})

describe("Masking with real JWTs", () => {

    it("Google", () => {
        const input = GOOGLE1.split('.').slice(0,2).join('.');
        maskTesting(input, ["iss", "iat", "exp", "aud"]);
    });

    it.only("Google again", () => {
        const input = GOOGLE2.split('.').slice(0,2).join('.');
        maskTesting(input, ["iss", "iat", "exp", "aud"]);
    })
});