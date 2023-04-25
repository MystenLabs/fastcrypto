const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const {toBigIntBE} = require('bigint-buffer');

const utils = require("../js/utils");
const test = require("../js/test");

describe("Base64 checks", () => {

    // create a map between base64 representation and the characters
    const base64Map = {};
    for (let i = 0; i < 26; i++) {
        base64Map[i] = String.fromCharCode(65 + i);
    }
    for (let i = 26; i < 52; i++) {
        base64Map[i] = String.fromCharCode(97 + i - 26);
    }
    for (let i = 52; i < 62; i++) {
        base64Map[i] = String.fromCharCode(48 + i - 52);
    }
    base64Map[62] = "+";
    base64Map[63] = "/";

    before(async() => {
        cir = await test.genMain(path.join(__dirname, "..", "circuits", "base64.circom"), "B64URLToBits");
        await cir.loadSymbols();
    });

    it("Should convert all valid base64 url characters", async () => {
        const input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        for (let i = 0; i < input.length; i++) {
            const witness = await cir.calculateWitness({ "in": toBigIntBE(Buffer.from(input[i])) });
            const output = utils.getWitnessArray(witness, cir.symbols, "main.out");
            const actual = output.reduce((acc, cur) => acc * 2n + cur, 0n);
            // console.log(toBigIntBE(Buffer.from(input[i])), actual, output, input[i]);
            assert.deepEqual(base64Map[actual], base64Map[i]);
        }
    })

    it("Should fail for non-base64 characters", async () => {
        const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        const asciiBase64 = base64.split('').map(x => toBigIntBE(Buffer.from(x)));

        // generate all possible 8-bit values that are not valid base64 characters
        for (let i = 0; i < 256; i++) {
            if (!asciiBase64.includes(BigInt(i))) {
                try {
                    const witness = await cir.calculateWitness({ "in": i });
                    await cir.checkConstraints(witness);
                } catch (error) {
                    assert.include(error.message, "Error in template B64URLToBits");
                }
            }
        }

        // fails for other non-base64 values as well
        for (let i of [-256, -1, 256, 2**19]) {
            try {
                const witness = await cir.calculateWitness({ "in": i });
                await cir.checkConstraints(witness);
            } catch (error) {
                assert.include(error.message, "Error in template B64URLToBits");
            }
        }
    })
})