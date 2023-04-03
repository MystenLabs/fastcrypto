const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const crypto = require("crypto");

const buildPoseidon = require("circomlibjs").buildPoseidon;

const utils = require("../js/utils");
const test = require("../js/test");

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
