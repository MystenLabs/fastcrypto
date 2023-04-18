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
