const chai = require("chai");
const crypto = require("crypto");
const path = require("path");
const assert = chai.assert;

const utils = require("../js/utils");

const testutils = require("./testutils");

const buildPoseidon = require("circomlibjs").buildPoseidon;

const poseidonlite = require("poseidon-lite");

const poseidonNumToHashFN = [
    undefined,
    poseidonlite.poseidon1,
    poseidonlite.poseidon2,
    poseidonlite.poseidon3,
    poseidonlite.poseidon4,
    poseidonlite.poseidon5,
    poseidonlite.poseidon6,
    poseidonlite.poseidon7,
    poseidonlite.poseidon8,
    poseidonlite.poseidon9,
    poseidonlite.poseidon10,
    poseidonlite.poseidon11,
    poseidonlite.poseidon12,
    poseidonlite.poseidon13,
    poseidonlite.poseidon14,
    poseidonlite.poseidon15,
];

function litePoseidonHash(inputs) {
    const hashFN = poseidonNumToHashFN[inputs.length];
    if (hashFN) {
        return hashFN(inputs);
    } else if (inputs.length <= 30) {
        const hash1 = litePoseidonHash(inputs.slice(0, 15));
        const hash2 = litePoseidonHash(inputs.slice(15));
        return litePoseidonHash([hash1, hash2]);
    } else {
        throw new Error(
            `Yet to implement: Unable to hash a vector of length ${inputs.length}`
        );
    }
}

describe("Zk-friendly hashing (Poseidon) tests", () => {
    const P = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    const circuit_path = path.join(__dirname, "../circuits/helpers", "hasher.circom");

    before(async () => {
        poseidon = await buildPoseidon();
    });

    it("Hashes a single value", async () => {
        cir = await testutils.genMain(circuit_path, "Hasher", [1]);
        await cir.loadSymbols();
        input = [1];
        const expected_hash = utils.poseidonHash(input, poseidon);

        const witness = await cir.calculateWitness({ "in": input });
        
        assert.deepEqual(testutils.getWitnessValue(witness, cir.symbols, "main.out"), expected_hash);
        assert.deepEqual(litePoseidonHash(input), expected_hash);
    });

    it("Hashes two values", async () => {
        cir = await testutils.genMain(circuit_path, "Hasher", [2]);
        await cir.loadSymbols();
        input = [1, 2];
        const expected_hash = utils.poseidonHash(input, poseidon);
        
        const witness = await cir.calculateWitness({ "in": input });
        
        assert.deepEqual(testutils.getWitnessValue(witness, cir.symbols, "main.out"), expected_hash);
        assert.deepEqual(litePoseidonHash(input), expected_hash);
    });

    it("Hashes 15 values", async () => {
        cir = await testutils.genMain(circuit_path, "Hasher", [15]);
        await cir.loadSymbols();
        input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        const expected_hash = utils.poseidonHash(input, poseidon);
        
        const witness = await cir.calculateWitness({ "in": input });
        
        assert.deepEqual(testutils.getWitnessValue(witness, cir.symbols, "main.out"), expected_hash);
        assert.deepEqual(litePoseidonHash(input), expected_hash);
    });

    it("Hashes 16 values", async () => {
        cir = await testutils.genMain(circuit_path, "Hasher", [16]);
        await cir.loadSymbols();
        input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        const expected_hash = utils.poseidonHash(input, poseidon);
        
        const witness = await cir.calculateWitness({ "in": input });
        
        assert.deepEqual(testutils.getWitnessValue(witness, cir.symbols, "main.out"), expected_hash);
        assert.deepEqual(litePoseidonHash(input), expected_hash);
    });

    it("Hashes 30 values", async () => {
        cir = await testutils.genMain(circuit_path, "Hasher", [30]);
        await cir.loadSymbols();
        input = [];
        for (let i = 0; i < 30; i++) {
            input.push(i);
        }
        const expected_hash = utils.poseidonHash(input, poseidon);
        
        const witness = await cir.calculateWitness({ "in": input });
        
        assert.deepEqual(testutils.getWitnessValue(witness, cir.symbols, "main.out"), expected_hash);
        assert.deepEqual(litePoseidonHash(input), expected_hash);
    });

    it("Nonce test", async () => {
        cir = await testutils.genMain(circuit_path, "Hasher", [4]);
        await cir.loadSymbols();

        const ephPubKey = BigInt("0x" + crypto.randomBytes(32).toString('hex'));
        const maxEpoch = 100;
        const randomness = BigInt("0x" + crypto.randomBytes(31).toString('hex'));

        assert.isTrue(randomness < P);

        // Breaking it into two chunks to avoid overflow in case ephPubKey > P
        const ephPubKey_0 = ephPubKey % 2n**128n;
        const ephPubKey_1 = ephPubKey / 2n**128n;

        assert.isTrue(ephPubKey_0 < P);
        assert.isTrue(ephPubKey_1 < P);

        const nonceExpected = utils.poseidonHash([ephPubKey_0, ephPubKey_1, maxEpoch, randomness], poseidon);
        const witness = await cir.calculateWitness({in: [ephPubKey_0, ephPubKey_1, maxEpoch, randomness]}, true);
        const nonceActual = testutils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.deepEqual(nonceActual, nonceExpected);
    });
});
