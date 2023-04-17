const chai = require("chai");
const assert = chai.assert;

const circuit = require("../js/circuit");
const utils = require("../js/utils");
const verify = require("../js/verify");

const GOOGLE_JWT = require("../js/testvectors").google_extension.jwt;

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
    console.log(extracted_claims);
    for (const claim of claimsToHide) {
        if (!extracted_claims.some(e => e.indexOf(claim) !== -1)) {
            console.log("Can't find claim", claim, "in", extracted_claims);
            throw new Error("Claim not found in masked JWT");
        }
    }
    console.log('\n');
}

function subsets(array) {
    return array.reduce(
        (subsets, value) => subsets.concat(
            subsets.map(set => [value, ...set])
        ),
        [[]]
    );
}

describe.only("Masking with dummy JWTs", () => {
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

        // Mask the JWT
        const claims = ["iss", "azp", "iat", "exp"];

        for (const subset of subsets(claims)) {
            maskTesting(jwt, subset);
        }
    });
})

describe("Masking with real JWTs", () => {
    const input = GOOGLE_JWT.split('.').slice(0,2).join('.');

    it("JWT masking", () => {
        const mask = circuit.genJwtMask(input, ["iss", "aud", "iat", "exp"]);
        const masked_input = utils.applyMask(input, mask);
    
        const claims = masked_input.split(/=+/).filter(e => e !== '');        
        console.log("claims", claims);
    
        const payloadIndex = input.split('.')[0].length + 1;
    
        var searchFromPos = payloadIndex;
        for (const claim of claims) {
            const claimIndex = input.indexOf(claim, searchFromPos);
            assert.isTrue(claimIndex >= payloadIndex, "String not found in input");
    
            // convert to base64 taking into account the payload index
            const claimB64Offset = (claimIndex - payloadIndex) % 4;
            const claimUTF8 = utils.b64decode(claim, claimB64Offset);
            console.log(claimIndex, claimB64Offset, claimUTF8);
    
            searchFromPos = claimIndex + claim.length;
        }
    
        // assert.equal(claims.length, 2, "Incorrect number of claims");
        // assert.include(claims[0], '"iss":"https://accounts.google.com"', "Does not contain iss claim");
        // assert.include(claims[1], '"iat":1679674145', "Does not contain iat claim");
        // assert.include(claims[2], '"exp":1679677745', "Does not contain exp claim");
    });

    it("JWT masking edge cases", async() => {
        var header = '{"kid":abc}';
        var payload = '{"iss":123,"azp":456,"iat":7890,"exp":101112}';
        console.log(header + '.' + payload);

        // Create a JWT
        var jwt = utils.trimEndByChar(Buffer.from(header).toString('base64'), '=') 
                    + '.' + utils.trimEndByChar(Buffer.from(payload).toString('base64'), '=');
        console.log(jwt);

        var mask = circuit.genJwtMask(jwt, ["exp"]);
        console.log(mask.join(''));

        const masked_jwt = utils.applyMask(new Uint8Array(Buffer.from(jwt)) , mask);
        console.log(masked_jwt);
        console.log(Buffer.from(masked_jwt).toString());

        // var consecutiveClaims = ["iss"];
        // const circuitOutputClaims = encoded_jwt.split('').map((c, i) => mask[i] == 1 ? c : ' ').join('').split(/\s+/).filter(e => e !== '');
        
        // assert.equal(circuitOutputClaims.length, consecutiveClaims.length);

        // console.log(circuitOutputClaims, startOffsets);

        // // Each element corresponds to a non-consecutive claim
        // var claims = [];
        // for (const [i, c] of circuitOutputClaims.entries()) {
        //     claims.push(Buffer.from('0'.repeat(startOffsets[i]) + c, 'base64').toString().slice(startOffsets[i]));
        // }
        // console.log(claims, "claims");
        // assert.equal(claims.length, 1);

        // assert.equal(claims[0], '"azp":456,', "Does not contain azp claim");
    });
});