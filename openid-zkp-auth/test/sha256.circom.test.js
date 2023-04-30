const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const crypto = require("crypto");

const circuit = require("../js/circuitutils");
const utils = require("../js/utils");
const test = require("../js/test");

// TODO: Add tests for SHA2_wrapper

describe("Unsafe SHA256", () => {
    const nBlocks = 20;
    const hexBytesToBlock = 512/8/2;
    var cir;
    
    before(async() => {
        cir = await test.genMain(path.join(__dirname, "..", "circuits", "sha256.circom"), "Sha256_unsafe", [nBlocks]);
        await cir.loadSymbols();
    });

    it("Hashing produces expected output for filled blocks", async () => {
        const input = crypto.randomBytes((nBlocks * hexBytesToBlock)-32).toString("hex");
        const hash = crypto.createHash("sha256").update(input).digest("hex");

        const inputs = circuit.genSha256Inputs(input, nBlocks);
        
        const witness = await cir.calculateWitness(inputs, true);
        
        const hash2 = utils.getWitnessBuffer(witness, cir.symbols, "main.out").toString("hex");
        
        assert.equal(hash2, hash);
    });
    
    it("Hashing produces expected output for partial last block", async () => {
        const input = crypto.randomBytes((nBlocks * hexBytesToBlock)-100).toString("hex");
        const hash = crypto.createHash("sha256").update(input).digest("hex");

        const inputs = circuit.genSha256Inputs(input, nBlocks);
        
        const witness = await cir.calculateWitness(inputs, true);
        
        const hash2 = utils.getWitnessBuffer(witness, cir.symbols, "main.out").toString("hex");
        
        assert.equal(hash2, hash);
    });
    
    it("Hashing produces expected output for less than nBlocks blocks", async () => {
        const input = crypto.randomBytes((nBlocks-8) * hexBytesToBlock).toString("hex");
        const hash = crypto.createHash("sha256").update(input).digest("hex");

        const inputs = circuit.genSha256Inputs(input, nBlocks);
        
        const witness = await cir.calculateWitness(inputs, true);
        
        const hash2 = utils.getWitnessBuffer(witness, cir.symbols, "main.out").toString("hex");
        
        assert.equal(hash2, hash);
    });
});
