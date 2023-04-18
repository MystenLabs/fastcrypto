const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const utils = require("../js/utils");
const test = require("../js/test");

describe("Miscellaneous checks", () => {
    it("Fixed circuit extracts correct value", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), "SliceFixed", [6, 2]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4,5,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n]);
    });
})