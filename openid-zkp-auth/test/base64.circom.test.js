const path = require("path");
const assert = require("chai").assert;

const utils = require("../js/utils");
const test = require("../js/test");
const jwtutils = require("../js/jwtutils");

describe("Base64 checks", () => {
    before(async() => {
        cir = await test.genMain(path.join(__dirname, "..", "circuits", "base64.circom"), "B64URLToBits");
        await cir.loadSymbols();
    });

    it("Should convert all valid base64 url characters", async () => {
        const input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        for (let i = 0; i < input.length; i++) {
            const witness = await cir.calculateWitness({ "in": input.charCodeAt(i) });
            const output = utils.getWitnessArray(witness, cir.symbols, "main.out");
            assert.deepEqual(output.map(Number), jwtutils.base64UrlCharTo6Bits(input.charAt(i)));
        }
    })

    it("Should fail for non-base64 characters", async () => {
        const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        const ascii = base64.split('').map(x => x.charCodeAt(0));

        // generate all possible 8-bit values that are not valid base64 characters
        for (let i = 0; i < 256; i++) {
            if (!ascii.includes(i)) {
                const witness = await cir.calculateWitness({ "in": i });
                const output = utils.getWitnessArray(witness, cir.symbols, "main.out");
                assert.deepEqual(output, [ 0n, 0n, 0n, 0n, 0n, 0n ]);
            }
        }
    })
})