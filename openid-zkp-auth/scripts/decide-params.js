const jwtutils = require("../js/jwtutils");

// JWT header + JWT payload + SHA2 padding 
function computeNumSHA2Blocks(jwt) {
    const header = jwt.split('.')[0];
    const payload = jwt.split('.')[1];

    const jwtMaxLen = header.length + payload.length;

    const L = jwtMaxLen * 8;
    const K = (512 + 448 - (L % 512 + 1)) % 512;

    const paddingLen = 1 + K + 64;

    if ((L + paddingLen) % 512 !== 0) {
        throw new Error("Shouldn't happen... Invalid implementation");
    }

    return (L + paddingLen) / 512;
}

function computeSubLen(jwt) {
    const payload = Buffer.from(jwt.split('.')[1], 'base64url').toString();
    return jwtutils.getClaimString(payload, "sub").length;
}

function computeAudLen(jwt) {
    const payload = Buffer.from(jwt.split('.')[1], 'base64url').toString();
    return jwtutils.getClaimString(payload, "aud").length;
}

function decide(jwt, buffer1, buffer2) {
    const p1 = computeNumSHA2Blocks(jwt);
    // TODO: Move to ceil?
    const maxSHA2Blocks = Math.floor(p1 * (1 + buffer1));
    console.log(`SHA2 blocks: ${p1}, Max SHA2 blocks: ${maxSHA2Blocks}`);

    const p2 = computeSubLen(jwt);
    var maxSubLen = Math.floor(p2 * (1 + buffer2));

    // Round maxSubLen to the nearest multiple of 3
    maxSubLen = Math.ceil(maxSubLen / 3) * 3;
    console.log(`Sub length: ${p2}, Max sub length: ${maxSubLen}`);

    const p3 = computeAudLen(jwt);
    var maxAudLen = Math.floor(p3 * (1 + buffer2));

    // Round maxAudLen to the nearest multiple of 3
    maxAudLen = Math.ceil(maxAudLen / 3) * 3;
    console.log(`Aud length: ${p3}, Max aud length: ${maxAudLen}`);
}

const GOOGLE = require("../test/testvectors").google;
const TWITCH = require("../test/testvectors").twitch;
const BUFFER1 = 0.15; // 15 percent
const BUFFER2 = 0.15; // 15 percent

if (require.main === module) {
    console.log("GOOGLE");
    decide(GOOGLE.jwt, BUFFER1, BUFFER2);

    console.log("TWITCH");
    decide(TWITCH.jwt, BUFFER1, BUFFER2);
}