const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const crypto = require("crypto");

const {toBigIntBE} = require('bigint-buffer');

const utils = require("../js/utils");
const circuit = require("../js/circuitutils");

const testutils = require("./testutils");
const { inWidth } = require("../js/constants");

describe("Unsafe SHA256", () => {
    const nBlocks = 4;
    const nWidth = 8;
    const nCount = nBlocks * 512 / nWidth;

    const outWidth = 128;
    const outCount = 256 / outWidth;

    const bytesToBlock = 512/8; // 64
    var cir;

    before(async() => {
        cir = await testutils.genMain(
            path.join(__dirname, "../circuits/helpers", "sha256.circom"),
            "Sha2_wrapper",
            [nWidth, nCount, outWidth, outCount]
        );
        await cir.loadSymbols();
    });

    async function test(i, expected_num_sha2_blocks) {
        const input = crypto.randomBytes(i * bytesToBlock);

        const hash = crypto.createHash("sha256").update(input).digest("hex");

        var inputs = circuit.genSha256Inputs(input, nCount, nWidth);
        inputs["in"] = inputs["in"].map(bits => toBigIntBE(utils.bitArray2Buffer(bits)));

        assert.equal(inputs["num_sha2_blocks"], expected_num_sha2_blocks);
        console.log(`num_sha2_blocks = ${inputs["num_sha2_blocks"]}`);

        const witness = await cir.calculateWitness(inputs, true);

        const hash2 = testutils.getWitnessBuffer(witness, cir.symbols, "main.hash", outWidth).toString("hex");
        console.log(`hash = ${hash2}`);

        assert.equal(hash2, hash);
    }

    it(`Hashing produces expected output for 0.5 block`, async () => {
        await test(0.5, 1); // num_sha2_blocks = 1
    });

    it(`Hashing produces expected output for 1 block`, async () => {
        await test(1, 2);
    });

    it(`Hashing produces expected output for 2 blocks`, async () => {
        await test(2, 3);
    });

    it(`Corner case: num_sha2_blocks = nBlocks`, async () => {
        await test(nBlocks - 1, nBlocks);
    });

    it(`Fails when the last byte is non-zero`, async () => {
        const input = crypto.randomBytes(1 * bytesToBlock);

        var inputs = circuit.genSha256Inputs(input, nCount, nWidth);
        inputs["in"] = inputs["in"].map(bits => toBigIntBE(utils.bitArray2Buffer(bits)));
        inputs["in"][inputs["in"].length - 1] = 1n; // Make the last byte non-zero

        try {
            await cir.calculateWitness(inputs, true);
            assert.fail("Should have thrown an error");
        } catch (e) {
            assert.include(e.message, "Error in template Sha2_wrapper");
        }
    });

    it(`Fails when the first byte post SHA2-padding is non-zero`, async () => {
        const input = crypto.randomBytes(1 * bytesToBlock);

        var inputs = circuit.genSha256Inputs(input, nCount, nWidth);
        inputs["in"] = inputs["in"].map(bits => toBigIntBE(utils.bitArray2Buffer(bits)));

        var num_sha2_blocks = inputs["num_sha2_blocks"];
        inputs["in"][num_sha2_blocks * 512 / nWidth] = 1n; // Make the first byte post SHA2-padding non-zero

        try {
            await cir.calculateWitness(inputs, true);
            assert.fail("Should have thrown an error");
        } catch (e) {
            assert.include(e.message, "Error in template Sha2_wrapper");
        }
    });
});