const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const b64utils = require("../js/b64utils");
const utils = require("../js/utils");
const test = require("../js/test");

describe("Strings checks", () => {
    const file = path.join(__dirname, "..", "circuits", "strings.circom");

    it("SliceFixed(6, 2)", async () => {
        cir_fixed = await test.genMain(file, "SliceFixed", [6, 2]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4,5,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n]);
    });

    it("SliceFixed(6, 6)", async () => {
        cir_fixed = await test.genMain(file, "SliceFixed", [6, 6]);
        await cir_fixed.loadSymbols();
        input = [3,1,5,9,2,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 0 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [3n, 1n, 5n, 9n, 2n, 6n]);
    });

    it("SliceFixed(6, 0)", async () => {
        cir_fixed = await test.genMain(file, "SliceFixed", [6, 0]);
        await cir_fixed.loadSymbols();
        input = [3,1,5,9,2,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 0 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), []);
    });

    it("Slice(6, 4), 2", async () => {
        cir_fixed = await test.genMain(file, "Slice", [6, 4]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4,5,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 2 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n, 0n, 0n]);
    });
    
    it("Slice(6, 4), 4", async () => {
        cir_fixed = await test.genMain(file, "Slice", [6, 4]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4,5,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 4 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n, 4n, 5n]);
    });

    it("Slice outside", async () => {
        cir_fixed = await test.genMain(file, "Slice", [6, 4]);
        await cir_fixed.loadSymbols();
        input = [1,2,3,4,5,6];
        
        const witness = await cir_fixed.calculateWitness({ "in": input, "index": 4, "length": 4 });
        
        assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [5n, 6n, 0n, 0n]);
    });
})

describe("B64SubstrExists", () => {
    it("Dummy string", async () => {
        substr = [
                [1, 2, 3, 4],
                [3, 1, 5, 9],
                [2, 7, 1, 8]
        ];
        numSubstrs = 3;
        substrLen = 4;
        substrExpOffsets = [2, 2, 2];
        inCount = 10;

        {
            cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
                "B64SubstrExists", [substr, numSubstrs, substrLen, substrExpOffsets, inCount]);
            string = [5, 4, 2, 7, 1, 8, 9, 6, 2, 3];
            startIndex = 0;
            substrIndex = 2;
        
            await cir_fixed.calculateWitness(
                { "inputString": string, "payloadIndex": startIndex, "substringIndex": substrIndex });
        }
        
       {
            maxSubstrLen = 6;
            substr = [ // Padding must be zeroes
                [1, 2, 3, 4, 0, 0],
                [3, 1, 5, 9, 0, 0],
                [2, 7, 1, 8, 0, 0]
            ];
            cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
                "B64SubstrExistsAlt", [numSubstrs, maxSubstrLen, inCount]);

            string = [5, 4, 2, 7, 1, 8, 9, 6, 2, 3];
            startIndex = 0;
            substrIndex = 2;
        
            await cir_fixed.calculateWitness({
                "substringArray": substr,
                "substringLength": substrLen,
                "offsets": substrExpOffsets,
                "inputString": string,
                "payloadIndex": startIndex,
                "substringIndex": substrIndex
            });
       } 
    });

    describe("Real base64 string", () => {
        const sub_claim = '"sub":"4840061"';
        const sub_in_b64 = utils.removeDuplicates(b64utils.getAllExtendedBase64Variants(sub_claim));
        const header = "Iei.";

        it("Start", async () => {
            const jwt = header + utils.trimEndByChar(Buffer.from(JSON.stringify({
                "sub": "4840061",
                "iat": 1614787200,
                "exp": 1614787200
            })).toString('base64url'), '=');
            const index = jwt.indexOf(sub_in_b64[6][0]);
            assert.equal(index, header.length);

            circuit = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
            "B64SubstrExists", [
                sub_in_b64.map(e => e[0].split('').map(c => c.charCodeAt())),
                sub_in_b64.length,
                sub_in_b64[0][0].length,
                sub_in_b64.map(e => e[1]),
                jwt.length
            ]);

            const witness = await circuit.calculateWitness({
                "inputString": jwt.split('').map(c => c.charCodeAt()),
                "payloadIndex": header.length,
                "substringIndex": index
            });
    
            await circuit.checkConstraints(witness);
        });

        it("End", async () => {
            for (const [i, iat] of [10, 100, 1].entries()) {
                const jwt = header + utils.trimEndByChar(Buffer.from(JSON.stringify({
                    "iat": iat,
                    "sub": "4840061"
                })).toString('base64url'), '=');    

                const index = jwt.indexOf(sub_in_b64[3 + i][0]);
                assert.notDeepEqual(index, -1);

                circuit = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
                "B64SubstrExists", [
                    sub_in_b64.map(e => e[0].split('').map(c => c.charCodeAt())),
                    sub_in_b64.length,
                    sub_in_b64[0][0].length,
                    sub_in_b64.map(e => e[1]),
                    jwt.length
                ]);
    
                const witness = await circuit.calculateWitness({
                    "inputString": jwt.split('').map(c => c.charCodeAt()),
                    "payloadIndex": header.length,
                    "substringIndex": index
                });                    
                await circuit.checkConstraints(witness);
            }
        });

        it("Middle", async () => {
            for (const [i, iat] of [10, 100, 1].entries()) {
                const jwt = utils.trimEndByChar(Buffer.from(JSON.stringify({
                    "iat": iat,
                    "sub": "4840061",
                    "exp": 1614787200
                })).toString('base64url'), '=');

                const index = jwt.indexOf(sub_in_b64[i][0]);
                assert.notDeepEqual(index, -1);

                circuit = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
                "B64SubstrExists", [
                    sub_in_b64.map(e => e[0].split('').map(c => c.charCodeAt())),
                    sub_in_b64.length,
                    sub_in_b64[0][0].length,
                    sub_in_b64.map(e => e[1]),
                    jwt.length
                ]);
    
                const witness = await circuit.calculateWitness({
                    "inputString": jwt.split('').map(c => c.charCodeAt()),
                    "payloadIndex": header.length,
                    "substringIndex": index
                });                    
                await circuit.checkConstraints(witness);
            }
        });
    });
});