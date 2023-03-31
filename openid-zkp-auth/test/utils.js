const chai = require("chai");
const assert = chai.assert;
const crypto = require("crypto");

const circuit = require("../js/circuit");
const utils = require("../js/utils");

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

    // TODO: Improve tests.
    it("String matching, len(substr) % 3 == 0", () => {
        const input0 = 'saab';
        const extendedInput0 = '"' + input0 + '"';
        assert.isTrue(extendedInput0.length % 3 === 0);
        const variants = utils.getAllBase64Variants(extendedInput0);

        assert.deepEqual(Buffer.from('0' + variants[0] + '0', 'base64').toString().slice(1, -1), input0);
        assert.deepEqual(Buffer.from('00' + variants[1], 'base64').toString().slice(2), input0);
        assert.deepEqual(Buffer.from(variants[2] + '00', 'base64').toString().slice(0, -2), input0);

        {
            const input = 'sub';
            const extendedInput = '"' + input + '"';
            assert.isTrue(extendedInput.length % 3 === 2);

            const variants = utils.getAllBase64Variants(extendedInput);

            assert.deepEqual(Buffer.from(variants[0] + '00', 'base64').toString().slice(1, -2), input);
            assert.deepEqual(Buffer.from('00' + variants[1], 'base64').toString().slice(2, -1), input);
            assert.deepEqual(Buffer.from(variants[2].slice(1, -1), 'base64').toString(), input);
        }
    })

    it("String matching, len(substr) % 3 == 1", () => {
        const input = '"sub"';
        const extendedInput = ',' + input + ':';
        assert.isTrue(extendedInput.length % 3 === 1);

        const variants = utils.getAllBase64Variants(extendedInput);

        assert.deepEqual(Buffer.from(variants[0], 'base64').toString().slice(1), input);
        assert.deepEqual(Buffer.from('00' + variants[1] + '00', 'base64').toString().slice(2, -2), input);
        assert.deepEqual(Buffer.from(variants[2], 'base64').toString().slice(0, -1), input);

        { // Test with a JWT where idx % 3 == 1
            const jwt = '{"iss":123,"sub":456}';
            const idx = jwt.indexOf(extendedInput);
            assert.isTrue(idx !== -1 && idx % 3 === 1);

            const encoded = Buffer.from(jwt).toString('base64');
            assert.isTrue(encoded.includes(variants[idx % 3]));
        }
        {// Test with a JWT where idx % 3 == 2
            const jwt = '{"iss":1234,"sub":456}';
            const idx = jwt.indexOf(extendedInput);
            assert.isTrue(idx !== -1 && idx % 3 === 2);

            const encoded = Buffer.from(jwt).toString('base64');
            assert.isTrue(encoded.includes(variants[idx % 3]));
        }
        {// Test with a JWT where idx % 3 == 0
            const jwt = '{"iss":12345,"sub":456}';
            const idx = jwt.indexOf(extendedInput);
            assert.isTrue(idx !== -1 && idx % 3 === 0);

            const encoded = Buffer.from(jwt).toString('base64');
            assert.isTrue(encoded.includes(variants[idx % 3]));
        }
    });
});
