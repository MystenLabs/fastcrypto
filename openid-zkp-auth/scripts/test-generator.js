/** 
 * Masked content tests
 * 
 * Generating test vectors that have valid ZKPs but play with the revealed claims (order).
 * The set of claims to reveal is fixed, i.e., ["iss", "aud", "nonce"].
 */

const utils = require('../js/utils');
const zkOpenIDProve = require('./run-zkp').zkOpenIDProve;
const zkOpenIDVerify = require('./run-zkp').zkOpenIDVerify;

// Stringify and convert to base64
constructJWT = (header, payload) => {
    header = JSON.stringify(header);
    payload = JSON.stringify(payload);
    return utils.trimEndByChar(Buffer.from(header).toString('base64url'), '=') 
                + '.' + utils.trimEndByChar(Buffer.from(payload).toString('base64url'), '=') + '.';
}

const header = {
    "alg":"RS256",
    "kid":"827917329",
    "typ":"JWT"
};

const sub = require('../test/testvectors').google.payload.sub;
const claimsToReveal = ["iss", "aud", "nonce"];

const basic = { // Resembles Google's JWT
    iss: 'google.com',
    azp: 'example.com',
    aud: 'example.com',
    sub: sub,
    nonce: 'abcd',
    iat: 4,
    exp: 4,
    jti: 'a8a0728a'
};

// The order of all claims is jumbled
const random_order = {
    jti: 'a8a0728a',
    azp: 'example.com',
    aud: 'example.com',
    nonce: 'abcd',
    iat: 4,
    iss: 'google.com',
    exp: 4,
    sub: sub,
};

// All revealed claims are consecutive
const consecutive = {
    azp: 'example.com',
    sub: sub,
    iss: 'google.com',
    aud: 'example.com',
    nonce: 'abcd',
    iat: 4,
    exp: 4,
    jti: 'a8a0728a'
};

const genAll = async () => {
    for (var payload of [basic, random_order, consecutive]) {
        const jwt = constructJWT(header, payload);
        console.log("Crafted JWT: " + jwt);
        const proof = await zkOpenIDProve(jwt, claimsToReveal);
        await zkOpenIDVerify(proof);
        console.log("\n");
    }
};

// Check if the script was called directly
if (require.main === module) {
    (async () => {
        try {
            await genAll();
            process.exit(0);
        }
        catch (err) {
        }
    })();
}