const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const utils = require("../js/src/utils");

const testutils = require("./testutils");

describe("Num2BitsBE(8)", () => {
    beforeEach(async () => {
        cir = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "Num2BitsBE", [8]);
        await cir.loadSymbols();
    });

    it ("Check 0", async () => {
        const witness = await cir.calculateWitness({"in": 0}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessArray(witness, cir.symbols, "main.out");
        assert.deepEqual(out, [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    });

    it ("Check 1", async () => {
        const witness = await cir.calculateWitness({"in": 1}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessArray(witness, cir.symbols, "main.out");
        assert.deepEqual(out, [0n, 0n, 0n, 0n, 0n, 0n, 0n, 1n]);
    });

    it ("Check 255", async () => {
        const witness = await cir.calculateWitness({"in": 255}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessArray(witness, cir.symbols, "main.out");
        assert.deepEqual(out, [1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n]);
    });

    it("Check 256: must throw an error", async () => {
        try {
            const witness = await cir.calculateWitness({"in": 256}, true);
            await cir.checkConstraints(witness);
            assert.fail("Should have failed");
        } catch (error) {
            assert.include(error.message, "Error in template Num2BitsBE");
        }
    });

    it ("Check -1: must throw an error", async () => {
        try {
            const witness = await cir.calculateWitness({"in": -1}, true);
            await cir.checkConstraints(witness);
            assert.fail("Should have failed");
        } catch (error) {
            assert.include(error.message, "Error in template Num2BitsBE");
        }
    });
})

describe("Num2BitsBE(256)", async () => {
    const L = 256;
    const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

    cir = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "Num2BitsBE", [L]);
    await cir.loadSymbols();
    const crypto = require("crypto");
    const num = BigInt("0x" + crypto.randomBytes(32).toString('hex')) % P;

    const witness = await cir.calculateWitness({"in": num}, true);
    await cir.checkConstraints(witness);
    const out = testutils.getWitnessArray(witness, cir.symbols, "main.out").map(x => Number(x));
    assert.equal(out.length, L);

    const out1 = (num % P).toString(2).padStart(L, '0').split('').map(x => Number(x));
    assert.equal(out1.length, L);

    assert.deepEqual(out, out1);
})

// Note: Although it is an offical circuit, tests for illustrative purposes and my own sanity
describe("Num2Bits", () => {
    beforeEach(async () => {
        cir = await testutils.genMain(path.join(__dirname, "../node_modules/circomlib/circuits", "bitify.circom"), "Num2Bits", [8]);
        await cir.loadSymbols();
    });

    it ("Check 0", async () => {
        const witness = await cir.calculateWitness({"in": 0}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessArray(witness, cir.symbols, "main.out");
        assert.deepEqual(out, [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    });

    it ("Check 1", async () => {
        const witness = await cir.calculateWitness({"in": 1}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessArray(witness, cir.symbols, "main.out");
        assert.deepEqual(out, [1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
    });

    it ("Check 255", async () => {
        const witness = await cir.calculateWitness({"in": 255}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessArray(witness, cir.symbols, "main.out");
        assert.deepEqual(out, [1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n]);
    });

    it("Check 256: must throw an error", async () => {
        try {
            const witness = await cir.calculateWitness({"in": 256}, true);
            await cir.checkConstraints(witness);
            assert.fail("Should have failed");
        } catch (error) {
            assert.include(error.message, "Error in template Num2Bits");
        }
    });

    it ("Check -1: must throw an error", async () => {
        try {
            const witness = await cir.calculateWitness({"in": -1}, true);
            await cir.checkConstraints(witness);
            assert.fail("Should have failed");
        } catch (error) {
            assert.include(error.message, "Error in template Num2Bits");
        }
    });
});

describe("Bits2NumBE", () => {
    before (async () => {
        cir = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "Bits2NumBE", [8]);
        await cir.loadSymbols();
    });

    it ("Check 0", async () => {
        const witness = await cir.calculateWitness({"in": [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(out, 0n);
    });

    it ("Check 1", async () => {
        const witness = await cir.calculateWitness({"in": [0n, 0n, 0n, 0n, 0n, 0n, 0n, 1n]}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(out, 1n);
    });

    it ("Check 255", async () => {
        const witness = await cir.calculateWitness({"in": [1n, 1n, 1n, 1n, 1n, 1n, 1n, 1n]}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(out, 255n);
    });
});

describe("Segments2NumBE", () => {
    before (async () => {
        cir = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "Segments2NumBE", [8, 3]);
        await cir.loadSymbols();
    });

    it ("Check 0", async () => {
        const witness = await cir.calculateWitness({"in": [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(out, 0n);
    });

    it ("Check 8", async () => {
        const witness = await cir.calculateWitness({"in": [0n, 0n, 0n, 0n, 0n, 0n, 1n, 0n]}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(out, 8n);
    });

    it ("Check 511", async () => {
        const witness = await cir.calculateWitness({"in": [0n, 0n, 0n, 0n, 0n, 7n, 7n, 7n]}, true);
        await cir.checkConstraints(witness);
        const out = testutils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(out, 511n);
    });
})

describe("ConvertBase checks", () => {
    it("Checking ConvertBase Case 0: input and output should be same", async () => {
        cir_fixed = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "ConvertBase", [4, 4, 4, 4]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out, [1, 2, 3, 4]);
        assert.deepEqual(out, utils.pack(input, 4, 4).map(Number));
    });

    it("Checking ConvertBase Case 1: Output width is multiple of input width", async () => {
        cir_fixed = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "ConvertBase", [4, 4, 8, 2]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out, [18, 52]);
        assert.deepEqual(out, utils.pack(input, 4, 8).map(Number));
    });

    it("Checking ConvertBase Case 2: Output width is not a multiple of input width", async () => {
        cir_fixed = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "ConvertBase", [4, 4, 6, 3]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out, [4, 35, 16]);
        assert.deepEqual(out, utils.pack(input, 4, 6).map(Number));
    });

    it("Checking ConvertBase Case 3: Edge case - just one input", async () => {  
        cir_fixed = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "ConvertBase", [1, 1, 6, 1]);
        await cir_fixed.loadSymbols();
        input = [1];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out, [32]);
        assert.deepEqual(out, utils.pack(input, 1, 6).map(Number));
    });

    it("Checking ConvertBase Case 4: Edge case - just one output", async () => {
        cir_fixed = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "ConvertBase", [4, 4, 16, 1]);
        await cir_fixed.loadSymbols();
        input = [1, 2, 3, 4];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out, [4660]);
        assert.deepEqual(out, utils.pack(input, 4, 16).map(Number));
    });

    it("Checking ConvertBase Case 5: Assert fail for myOutCount != outCount", async () => {
        try {
            cir_fixed = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "ConvertBase", [4, 4, 16, 2]);
            assert.fail("Should have failed");
        } catch (error) {
            assert.include(error.message, "assert(myOutCount == outCount)");
        }
    });

    it("Checking ConvertBase Case 6: Another test of correct padding", async () => {
        cir_fixed = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "ConvertBase", [4, 4, 7, 3]);
        await cir_fixed.loadSymbols();
        input = [7,1,8,2];
        const witness = await cir_fixed.calculateWitness({ "in": input });
        
        const out = testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out").map(e => Number(e) - '0');
        assert.deepEqual(out, [56, 96, 64]);
        assert.deepEqual(out, utils.pack(input, 4, 7).map(Number));
    });
});

describe("RemainderMod4 checks", () => {
    it("Positive + Negative cases", async () => {
        cir_fixed = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "RemainderMod4", [3]);
        await cir_fixed.loadSymbols();
        inputs = [1,2,3,4,5,6,7];
        for (let i = 0; i < inputs.length; i++) { // Should pass
            const witness = await cir_fixed.calculateWitness({ "in": inputs[i] });
            await cir_fixed.checkConstraints(witness);
            const out = testutils.getWitnessValue(witness, cir_fixed.symbols, "main.out");
            assert.deepEqual(out, BigInt(inputs[i] % 4));
        }

        try {
            const witness = await cir_fixed.calculateWitness({ "in": 8 });
            await cir_fixed.checkConstraints(witness);
            assert.fail("Should have failed");
        } 
        catch (error) {
            assert.include(error.message, 'Error in template Num2Bits', error.message); // Num2Bits does the length check
        }
    })
});

describe("DivideMod2Power checks", () => {
    it("With 2^2 = 4", async () => {
        circuit = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "DivideMod2Power", [4, 2]);
        await circuit.loadSymbols();

        for (let i = 0; i < 16; i++) {
            const w = await circuit.calculateWitness({ "in": i });
            await circuit.checkConstraints(w);
            const quotient = testutils.getWitnessValue(w, circuit.symbols, "main.quotient");
            const remainder = testutils.getWitnessValue(w, circuit.symbols, "main.remainder");

            assert.deepEqual(quotient, BigInt(Math.floor(i / 4)));
            assert.deepEqual(remainder, BigInt(i % 4));
        }
    })
})

describe("Number to bit vector checks", () => {
    it("OneBitVector", async () => {
        circuit = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "OneBitVector", [4]);
        await circuit.loadSymbols();

        // Success
        for (let i = 0; i < 4; i++) {
            const w = await circuit.calculateWitness({ "index": i });
            await circuit.checkConstraints(w);
            var ans = [0n, 0n, 0n, 0n];
            ans[i] = 1n;
            assert.sameOrderedMembers(
                testutils.getWitnessArray(w, circuit.symbols, "main.out"), ans
            );
        }

        // Failure
        for (let i of [-1, 4, 8]) {
            try {
                const w = await circuit.calculateWitness({ "index": i });
                await circuit.checkConstraints(w);
                assert.fail("Should have failed");
            } catch (error) {
                assert.include(error.message, 'Error in template OneBitVector', error.message);
            }
        }
    })

    it("GTBitVector", async () => {
        circuit = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "GTBitVector", [4]);
        await circuit.loadSymbols();

        // Success
        for (let i = 0; i < 4; i++) {
            const w = await circuit.calculateWitness({ "index": i });
            await circuit.checkConstraints(w);
            var ans = [0n, 0n, 0n, 0n];
            for (let j = i + 1; j < 4; j++) {
                ans[j] = 1n;
            }
            assert.sameOrderedMembers(
                testutils.getWitnessArray(w, circuit.symbols, "main.out"), ans
            );
        }

        // Failure
        for (let i of [-1, 4, 5, 8]) {
            try {
                const w = await circuit.calculateWitness({ "index": i });
                await circuit.checkConstraints(w);
                assert.fail(`Should have failed: index = ${i}`);
            } catch (error) {
                assert.include(error.message, 'Error in template GTBitVector', error.message);
            }
        }
    })

    it("LTBitVector", async () => {
        circuit = await testutils.genMain(path.join(__dirname, "../circuits/helpers", "misc.circom"), "LTBitVector", [4]);
        await circuit.loadSymbols();

        // Success
        for (let i = 1; i <= 4; i++) {
            const w = await circuit.calculateWitness({ "index": i });
            await circuit.checkConstraints(w);
            var ans = [0n, 0n, 0n, 0n];
            for (let j = 0; j < i; j++) {
                ans[j] = 1n;
            }
            assert.sameOrderedMembers(
                testutils.getWitnessArray(w, circuit.symbols, "main.out"), ans
            );
        }

        // Failure
        for (let i of [-1, 0, 5, 8]) {
            try {
                const w = await circuit.calculateWitness({ "index": i });
                await circuit.checkConstraints(w);
                assert.fail("Should have failed");
            } catch (error) {
                assert.include(error.message, 'Error in template LTBitVector', error.message);
            }
        }
    })
});

describe("RangeCheck", () => {
    async function genCircuit(nBits, max) {
        return await testutils.genMain(
            path.join(__dirname, "../circuits/helpers", "misc.circom"), 
            "RangeCheck", 
            [nBits, max]
        );
    }

    it("Positive", async () => {
        var nBits = 4;
        var max = 8;

        circuit = await genCircuit(nBits, max);

        for (var i = 0; i <= max; i++) {
            const w = await circuit.calculateWitness({ "in": 0});
            await circuit.checkConstraints(w);    
        }
    })

    describe("Negative", async () => {
        var nBits = 4;
        var max = 8;

        before(async () => {
            circuit = await genCircuit(nBits, max);
        });

        it("max < in < 2^nBits", async () => {
            for (var i of [9, 10, 11, 15]) { // 
                try {
                    const w = await circuit.calculateWitness({ "in": i});
                    await circuit.checkConstraints(w);
                    assert.fail("Should have failed");
                } catch (error) {
                    assert.include(error.message, 'Error in template RangeCheck');
                }
            }
        });

        it("in < 0", async () => {
            for (var i of [-1, -2, -3, -4]) {
                try {
                    const w = await circuit.calculateWitness({ "in": i});
                    await circuit.checkConstraints(w);
                    assert.fail("Should have failed");
                } catch (error) {
                    assert.include(error.message, 'Error in template RangeCheck');
                }
            }
        });

        it("in >= 2^nBits", async () => {
            for (var i of [16, 17, 18, 19, 20]) {
                try {
                    const w = await circuit.calculateWitness({ "in": i});
                    await circuit.checkConstraints(w);
                    assert.fail("Should have failed");
                } catch (error) {
                    assert.include(error.message, 'Error in template RangeCheck');
                }
            }
        });
    });
});