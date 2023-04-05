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

describe("Miscellaneous checks", () => {
    it("Check ExpandInitialOffsets", async () => {
        cir = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "ExpandInitialOffsets");
        await cir.loadSymbols();

        {// 0
            const witness = await cir.calculateWitness({"in": [0, 0]}, true);
            const out = utils.getWitnessArray(witness, cir.symbols, "main.out").map(e => Number(e) - '0');
            assert.deepEqual(out, [0, 1, 2, 3]);
        }

        {// 1
            const witness = await cir.calculateWitness({"in": [1, 0]}, true);
            const out = utils.getWitnessArray(witness, cir.symbols, "main.out").map(e => Number(e) - '0');
            assert.deepEqual(out, [1, 2, 3, 0]);
        }

        {// 2
            const witness = await cir.calculateWitness({"in": [0, 1]}, true);
            const out = utils.getWitnessArray(witness, cir.symbols, "main.out").map(e => Number(e) - '0');
            assert.deepEqual(out, [2, 3, 0, 1]);
        }

        {// 3
            const witness = await cir.calculateWitness({"in": [1, 1]}, true);
            const out = utils.getWitnessArray(witness, cir.symbols, "main.out").map(e => Number(e) - '0');
            assert.deepEqual(out, [3, 0, 1, 2]);
        }
    });

    it("Fixed circuit extracts correct value", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "SliceFixed", [6, 2]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4,5,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "offset": 1 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n]);
    });
    
    it("Checking Packer", async () => {
        { // Case 0: input and output should be same
            cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 4, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4];
            const witness = await cir_fixed.calculateWitness({ "in": input });
            
            const out = utils.getWitnessArray(witness, cir.symbols, "main.out").map(e => Number(e) - '0');
            assert.deepEqual(out, [1, 2, 3, 4]);
        }

        { // Case 1: Output width is multiple of input width
            cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 8, 2]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4];
            const witness = await cir_fixed.calculateWitness({ "in": input });
            
            const out = utils.getWitnessArray(witness, cir.symbols, "main.out").map(e => Number(e) - '0');
            assert.deepEqual(out[0], 18);
            assert.deepEqual(out[1], 52);
        }

        { // Case 2: Output width is not a multiple of input width
            cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 6, 3]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4];
            const witness = await cir_fixed.calculateWitness({ "in": input });
            
            const out = utils.getWitnessArray(witness, cir.symbols, "main.out").map(e => Number(e) - '0');
            assert.deepEqual(out[0], 4);
            assert.deepEqual(out[1], 35);
            assert.deepEqual(out[2], 16)
        }

        { // Case 3: Edge case - just one input
            cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [1, 1, 6, 1]);
            await cir_fixed.loadSymbols();
            input = [1];
            const witness = await cir_fixed.calculateWitness({ "in": input });
            
            const out = utils.getWitnessArray(witness, cir.symbols, "main.out").map(e => Number(e) - '0');
            assert.deepEqual(out[0], 32);
        }

        { // Case 3: Edge case - just one output
            cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 16, 1]);
            await cir_fixed.loadSymbols();
            input = [1, 2, 3, 4];
            const witness = await cir_fixed.calculateWitness({ "in": input });
            
            const out = utils.getWitnessArray(witness, cir.symbols, "main.out").map(e => Number(e) - '0');
            assert.deepEqual(out[0], 4660);
        }
    });
})
