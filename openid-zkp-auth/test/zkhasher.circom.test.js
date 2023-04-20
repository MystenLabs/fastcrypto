const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const utils = require("../js/utils");
const test = require("../js/test");

describe("Poseidon hash", () => {
    before (async () => {
        const buildPoseidon = require("circomlibjs").buildPoseidon;
        poseidon = await buildPoseidon();
        circuit_path = path.join(__dirname, "..", "circuits", "zkhasher.circom");
    });

    it("Hashes a single value", async () => {
        cir = await test.genMain(circuit_path, "Hasher", [1]);
        await cir.loadSymbols();
        input = [1];
        
        const witness = await cir.calculateWitness({ "in": input });
        
        assert.equal(utils.getWitnessValue(witness, cir.symbols, "main.out"), 
                     utils.poseidonHash(input, poseidon));
    });

    it("Hashes two values", async () => {
        cir = await test.genMain(circuit_path, "Hasher", [2]);
        await cir.loadSymbols();
        input = [1, 2];
        
        const witness = await cir.calculateWitness({ "in": input });
        
        assert.equal(utils.getWitnessValue(witness, cir.symbols, "main.out"), 
                     utils.poseidonHash(input, poseidon));
    });

    it("Hashes 15 values", async () => {
        cir = await test.genMain(circuit_path, "Hasher", [15]);
        await cir.loadSymbols();
        input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        const expected_hash = utils.poseidonHash(input, poseidon);
        
        const witness = await cir.calculateWitness({ "in": input });
        
        assert.equal(utils.getWitnessValue(witness, cir.symbols, "main.out"), expected_hash);
    });

    it("Hashes 16 values", async () => {
        cir = await test.genMain(circuit_path, "Hasher", [16]);
        await cir.loadSymbols();
        input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        const expected_hash = utils.poseidonHash(input, poseidon);
        
        const witness = await cir.calculateWitness({ "in": input });
        
        assert.equal(utils.getWitnessValue(witness, cir.symbols, "main.out"), expected_hash);
    });

    it("Hashes 30 values", async () => {
        cir = await test.genMain(circuit_path, "Hasher", [30]);
        await cir.loadSymbols();
        input = [];
        for (let i = 0; i < 30; i++) {
            input.push(i);
        }
        const expected_hash = utils.poseidonHash(input, poseidon);
        
        const witness = await cir.calculateWitness({ "in": input });
        
        assert.equal(utils.getWitnessValue(witness, cir.symbols, "main.out"), expected_hash);
    });
});

describe("Nonce hash checks", () => {
    const P = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

    it("", async () => {
        cir = await test.genMain(
            path.join(__dirname, "..", "node_modules", "circomlib", "circuits", "poseidon.circom"), 
            "Poseidon", [4]);
        await cir.loadSymbols();

        const ephPubKey = BigInt("0x" + crypto.randomBytes(32).toString('hex'));
        const maxEpoch = 100;
        const randomness = BigInt("0x" + crypto.randomBytes(31).toString('hex'));

        assert.isFalse(ephPubKey < P);
        assert.isTrue(randomness < P);

        const ephPubKey_0 = ephPubKey % 2n**128n;
        const ephPubKey_1 = ephPubKey / 2n**128n;

        assert.isTrue(ephPubKey_0 < P);
        assert.isTrue(ephPubKey_1 < P);

        poseidon = await buildPoseidon();
        F = poseidon.F;
        const nonceExpected = F.toObject(poseidon([ephPubKey_0, ephPubKey_1, maxEpoch, randomness]));

        const witness = await cir.calculateWitness({inputs: [ephPubKey_0, ephPubKey_1, maxEpoch, randomness]}, true);

        const nonceActual = utils.getWitnessValue(witness, cir.symbols, "main.out");

        assert.deepEqual(nonceActual, nonceExpected);
    });
});
