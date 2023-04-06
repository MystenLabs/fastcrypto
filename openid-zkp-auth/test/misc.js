const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const crypto = require("crypto");
const jose = require("jose");
const {toBigIntBE} = require('bigint-buffer');

const tester = require("circom_tester").wasm;

const circuit = require("../js/circuit");
const utils = require("../js/utils");
const test = require("../js/test");

describe("Num2BitsBE", () => {
    before (async () => {
        cir = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Num2BitsBE", [8]);
        await cir.loadSymbols();
    });

    it ("Check 0", async () => {
        const witness = await cir.calculateWitness({"in": 0}, true);
        await cir.checkConstraints(witness);
        const out = utils.getWitnessArray(witness, cir.symbols, "main.out");
        assert.deepEqual(out, [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    });

    it ("Check 1", async () => {
        const witness = await cir.calculateWitness({"in": 1}, true);
        await cir.checkConstraints(witness);
        const out = utils.getWitnessArray(witness, cir.symbols, "main.out");
        assert.deepEqual(out, [0n, 0n, 0n, 0n, 0n, 0n, 0n, 1n]);
    });

    it ("Check 255", async () => {
        const witness = await cir.calculateWitness({"in": 255}, true);
        await cir.checkConstraints(witness);
        const out = utils.getWitnessArray(witness, cir.symbols, "main.out");
        assert.deepEqual(out, [1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n]);
    });

    it ("Check 256: must throw an error", async () => {
        try {
            const witness = await cir.calculateWitness({"in": 256}, true);
            await cir.checkConstraints(witness);
            assert.fail();
        } catch (_) {
        }
    });

    it ("Check -1: must throw an error", async () => {
        try {
            const witness = await cir.calculateWitness({"in": -1}, true);
            await cir.checkConstraints(witness);
            assert.fail();
        } catch (_) {
        }
    });
})

describe("Bits2NumBE", () => {
    before (async () => {
        cir = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Bits2NumBE", [8]);
        await cir.loadSymbols();
    });

    it ("Check 0", async () => {
        const witness = await cir.calculateWitness({"in": [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]}, true);
        await cir.checkConstraints(witness);
        const out = utils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(out, 0n);
    });

    it ("Check 1", async () => {
        const witness = await cir.calculateWitness({"in": [0n, 0n, 0n, 0n, 0n, 0n, 0n, 1n]}, true);
        await cir.checkConstraints(witness);
        const out = utils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(out, 1n);
    });

    it ("Check 255", async () => {
        const witness = await cir.calculateWitness({"in": [1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n]}, true);
        await cir.checkConstraints(witness);
        const out = utils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(out, 255n);
    });
});

describe("Miscellaneous checks", () => {
    it("Fixed circuit extracts correct value", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "SliceFixed", [6, 2]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4,5,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "offset": 1 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n]);
    });
})
