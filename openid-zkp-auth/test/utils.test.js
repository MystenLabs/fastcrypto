const chai = require("chai");
const assert = chai.assert;
const crypto = require("crypto");

const circuit = require("../js/circuit");
const utils = require("../js/utils");
const b64utils = require("../js/b64utils");

describe("Circuit Utilities", () => {
    it("Buffer to/from bit array works as expected", async () => {
        const input = crypto.randomBytes(20*32).toString("hex");
        
        const bits = utils.buffer2BitArray(Buffer.from(input));
        const buffer = utils.bitArray2Buffer(bits);
        
        assert.equal(input, buffer.toString());
    });
    
    it("rfc4634#4.1 padding conforms: L % 512 = 0", async () => {
        const input = crypto.randomBytes(512/8/2).toString("hex");
        
        const bits = utils.buffer2BitArray(Buffer.from(input));
        const padded = circuit.padMessage(bits);
        
        assert.equal(bits.length, 512);
        assert.equal(padded.length, 1024); // Padding a 448+-bit message requires an additional block
        assert.equal(1, padded.slice(-512, -511)); // Padding begins with 1
        assert.equal(bits.length, parseInt(padded.slice(-64).join(''), 2)); // base2(L)
    });
    
    it("rfc4634#4.1 padding conforms: L % 512 = 65", async () => {
        const input = crypto.randomBytes(512/8/2).toString("hex");
        
        const bits = utils.buffer2BitArray(Buffer.from(input)).slice(0, 447);
        const padded = circuit.padMessage(bits);
        
        assert.equal(bits.length, 447);
        assert.equal(padded.length, 512);
        assert.equal(1, padded.slice(-65, -64)); // Padding begins with 1
        assert.equal(bits.length, parseInt(padded.slice(-64).join(''), 2));
    });
    
    it("rfc4634#4.1 padding conforms: L % 512 = 100", async () => {
        const input = crypto.randomBytes(512/8/2).toString("hex");
        
        const bits = utils.buffer2BitArray(Buffer.from(input)).slice(0, 412);
        const padded = circuit.padMessage(bits);
        
        assert.equal(bits.length, 412);
        assert.equal(padded.length, 512);
        assert.equal(1, padded.slice(-100, -99)); // Padding begins with 1
        assert.equal(bits.length, parseInt(padded.slice(-64).join(''), 2));
    });
});

// Returns the index of the claim in the Base64 encoded payload. 
// Implemented via getAllExtendedBase64Variants.
// Does the same job as b64utils.indicesOfB64 which implements it via a different approach.
function indicesOfB64(payload, claim) {
    const decoded_payload = Buffer.from(payload, 'base64').toString();
    const claim_kv_pair = utils.getClaimString(decoded_payload, claim);
    const substr_b64_array = b64utils.getAllExtendedBase64Variants(claim_kv_pair);
    
    for (const [j, extended_substr] of [
        ',' + claim_kv_pair + ',',
        ',' + claim_kv_pair + '}',
        '{' + claim_kv_pair + ','
    ].entries()) {
        const i = decoded_payload.indexOf(extended_substr);
        if (i !== -1) {
            const start = payload.indexOf(substr_b64_array[3 * j + i % 3][0]);
            return [start, start + substr_b64_array[3 * j + i % 3][0].length - 1];
        }
    }
    return -1;
}

describe("Base64 tests", () => {
    it("getAllExtendedBase64Variants and indicesOfB64", () => {
        const sub_claim = '"sub":45678';
        [
            '{"sub":45678,"iss":12345}', // At the start
            '{"iss":12345,"sub":45678}', // At the end
            '{"iss":12345,"sub":45678,"aud":"https://example.com"}' // In the middle
        ].forEach(input => {
            assert.isTrue(input.includes(sub_claim));
            assert.deepEqual(sub_claim, utils.getClaimString(input, "sub"));
            const [myStart, myEnd] = indicesOfB64(Buffer.from(input).toString('base64'), "sub");
            assert.isTrue(myStart !== -1);

            const [start, end] = b64utils.indicesOfB64(Buffer.from(input).toString('base64'), "sub");
            assert.deepEqual(myStart, start);
            assert.deepEqual(myEnd, end);
        });
    })

    it("sub claim finding in Google JWT", () => {
        const jwt = require('../js/testvectors').google_extension.jwt;
        const payload = jwt.split('.')[1];
        const [start, _] = indicesOfB64(payload, "sub");
        assert.isTrue(start !== -1);
    });

    it("getAllBase64Variants, len(substr) % 3 == 0", () => {
        const input = '"saaab"';
        const extendedInput = ',' + input + ':';
        assert.isTrue(extendedInput.length % 3 === 0);

        const variants = b64utils.getAllBase64Variants(extendedInput).map(v => v[0]);
        assert.deepEqual(Buffer.from('0' + variants[0] + '0', 'base64').toString().slice(1, -1), input);
        assert.deepEqual(Buffer.from('00' + variants[1], 'base64').toString().slice(2), input);
        assert.deepEqual(Buffer.from(variants[2] + '00', 'base64').toString().slice(0, -2), input);

        [
            '{"iss":12345,"saaab":456}', // A JWT where j % 3 == 0
            '{"iss":123,"saaab":456}', // A JWT where j % 3 == 1
            '{"iss":1234,"saaab":456}', // // A JWT where j % 3 == 2
        ].forEach((jwt, i) => {
            const j = jwt.indexOf(extendedInput);
            assert.deepEqual(j % 3, i);

            const jwt_b64 = Buffer.from(jwt).toString('base64');
            assert.isTrue(jwt_b64.includes(variants[i]));
        });
    })

    it("getAllBase64Variants, len(substr) % 3 == 1", () => {
        const input = '"sub"';
        const extendedInput = ',' + input + ':';
        assert.isTrue(extendedInput.length % 3 === 1);

        const variants = b64utils.getAllBase64Variants(extendedInput).map(v => v[0]);
        assert.deepEqual(Buffer.from(variants[0], 'base64').toString().slice(1), input);
        assert.deepEqual(Buffer.from('00' + variants[1] + '00', 'base64').toString().slice(2, -2), input);
        assert.deepEqual(Buffer.from(variants[2], 'base64').toString().slice(0, -1), input);

        [
            '{"iss":12345,"sub":456}', // A JWT where j % 3 == 0
            '{"iss":123,"sub":456}', // A JWT where j % 3 == 1
            '{"iss":1234,"sub":456}', // // A JWT where j % 3 == 2
        ].forEach((jwt, i) => {
            const j = jwt.indexOf(extendedInput);
            assert.deepEqual(j % 3, i);

            const jwt_b64 = Buffer.from(jwt).toString('base64');
            assert.isTrue(jwt_b64.includes(variants[i]));
        });
    });

    it("getAllBase64Variants, len(substr) % 3 == 2", () => {
        const input = '"soob"';
        const extendedInput = ',' + input + ':';
        assert.isTrue(extendedInput.length % 3 === 2);

        const variants = b64utils.getAllBase64Variants(extendedInput).map(v => v[0]);

        assert.deepEqual(Buffer.from(variants[0] + '00', 'base64').toString().slice(1, -2), input);
        assert.deepEqual(Buffer.from('00' + variants[1], 'base64').toString().slice(2, -1), input);
        assert.deepEqual(Buffer.from(variants[2].slice(1, -1), 'base64').toString(), input);

        [
            '{"iss":12345,"soob":456}', // A JWT where j % 3 == 0
            '{"iss":123,"soob":456}', // A JWT where j % 3 == 1
            '{"iss":1234,"soob":456}', // // A JWT where j % 3 == 2
        ].forEach((jwt, i) => {
            const j = jwt.indexOf(extendedInput);
            assert.deepEqual(j % 3, i);

            const jwt_b64 = Buffer.from(jwt).toString('base64');
            assert.isTrue(jwt_b64.includes(variants[i]));
        });
    });

    it("decodeMaskedB64", () => {
        const b64str = "eyJraWQiOmFiY30";
        // decoded = {"kid":abc}
        const decoded = Buffer.from(b64str, 'base64').toString('utf8');

        const decodeMaskedB64 = require("../js/b64utils").decodeMaskedB64;
        assert.deepEqual(decodeMaskedB64(b64str, 0), decoded);
        assert.deepEqual(decodeMaskedB64(b64str.slice(1), 1), decoded.slice(1)); // omit 1 char
        assert.deepEqual(decodeMaskedB64(b64str.slice(2), 2), decoded.slice(2)); // omit 2 chars
        assert.deepEqual(decodeMaskedB64(b64str.slice(3), 3), decoded.slice(3)); // omit 3 chars
    })
});