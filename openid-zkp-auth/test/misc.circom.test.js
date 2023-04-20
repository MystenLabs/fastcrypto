const chai = require("chai");
const path = require("path");
const assert = chai.assert;

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

describe("Packer checks", () => {
    it("Checking Packer Case 0: input and output should be same", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 4, 4]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = utils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out, [1, 2, 3, 4]);
    });

    it("Checking Packer Case 1: Output width is multiple of input width", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 8, 2]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = utils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out[0], 18);
        assert.deepEqual(out[1], 52);
    });

    it("Checking Packer Case 2: Output width is not a multiple of input width", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 6, 3]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = utils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out[0], 4);
        assert.deepEqual(out[1], 35);
        assert.deepEqual(out[2], 16)
    });

    it("Checking Packer Case 3: Edge case - just one input", async () => {  
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [1, 1, 6, 1]);
        await cir_fixed.loadSymbols();
        input = [1];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = utils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out[0], 32);
    });

    it("Checking Packer Case 4: Edge case - just one output", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 16, 1]);
        await cir_fixed.loadSymbols();
        input = [1, 2, 3, 4];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = utils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out[0], 4660);
    });

    // it("Checking Packer Case 5: Assert fail for myOutCount != outCount", async () => {
    //     { 
    //         try {
    //             cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 16, 2]);
    //             await cir_fixed.loadSymbols();
    //             input = [7,1,8,2];
    //             const witness = await cir_fixed.calculateWitness({ "in": input });
    //             await cir_fixed.checkConstraints(witness);
    //             assert.fail();
    //         } catch (error) {
    //             console.log(error);
    //         }
    //     }
    // });

    it("Checking Packer Case 6: Another test of correct padding", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "Packer", [4, 4, 7, 3]);
        await cir_fixed.loadSymbols();
        input = [7,1,8,2];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = utils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out[0], 56);
        assert.deepEqual(out[1], 96);
        assert.deepEqual(out[2], 64);
    });
});

describe("RemainderMod4 checks", () => {
    it("Positive + Negative cases", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "misc.circom"), "RemainderMod4", [3]);
        await cir_fixed.loadSymbols();
        inputs = [1,2,3,4,5,6,7];
        for (let i = 0; i < inputs.length; i++) { // Should pass
            const witness = await cir_fixed.calculateWitness({ "in": inputs[i] });
            await cir_fixed.checkConstraints(witness);
            const out = utils.getWitnessValue(witness, cir_fixed.symbols, "main.out");
            assert.deepEqual(out, BigInt(inputs[i] % 4));
        }

        try {
            const witness = await cir_fixed.calculateWitness({ "in": 8 });
            await cir_fixed.checkConstraints(witness);
            assert.fail();
        } 
        catch (_) {
            // console.log("Caught error!");
            // console.log(error);
        }
    })
})