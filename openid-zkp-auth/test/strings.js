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

describe("Strings checks", () => {
    it("SliceFixed(6, 2)", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), "SliceFixed", [6, 2]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4,5,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n]);
    });

    it("SliceFixed(6, 6)", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), "SliceFixed", [6, 6]);
        await cir_fixed.loadSymbols();
        input = [3,1,5,9,2,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 0 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [3n, 1n, 5n, 9n, 2n, 6n]);
    });

    it("SliceFixed(6, 0)", async () => {
        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), "SliceFixed", [6, 0]);
        await cir_fixed.loadSymbols();
        input = [3,1,5,9,2,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 0 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), []);
    });

    
    // substr <- subValue = [
    //     [76,67,74,122,100,87,73,105,79,105,73,120,77,84,65,48,78,106,77,
    //      48,78,84,73,120,78,106,99,122,77,68,77,49,79,84,103,122,79,68,77,105],
    //     [119,105,99,51,86,105,73,106,111,105,77,84,69,119,78,68,89,122,
    //      78,68,85,121,77,84,89,51,77,122,65,122,78,84,107,52,77,122,103,122,73,105],
    //     [73,110,78,49,89,105,73,54,73,106,69,120,77,68,81,50,77,122,81,49,77,106,69,50,
    //      78,122,77,119,77,122,85,53,79,68,77,52,77,121,73,115]
    // ],
    // substrLen <- subValueLength = 40,
    // substrExpOffsets <- subOffsets = [0,2,0],
    // inCount = 704

    // string[704] = content[i]
    // startIndex = payload_index
    // substrIndex = sub_claim_index

    it("CheckIfB64StringExists", async () => {
        substr = [
                [1, 2, 3, 4],
                [3, 1, 5, 9],
                [2, 7, 1, 8]
        ];
        substrLen = 4;
        substrExpOffsets = [2, 2, 2];
        inCount = 10;

        cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
            "CheckIfB64StringExists", [substr, substrLen, substrExpOffsets, inCount]);
        await cir_fixed.loadSymbols();
        string = [5, 4, 2, 7, 1, 8, 9, 6, 2, 3];
        startIndex = 0;
        substrIndex = 2;
        
        const witness = await cir_fixed.calculateWitness(
            { "string": string, "startIndex": startIndex, "substrIndex": substrIndex });
    });

})

