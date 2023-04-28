const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const b64utils = require("../js/b64utils");
const utils = require("../js/utils");
const test = require("../js/test");

describe("Slices", () => {
    const file = path.join(__dirname, "..", "circuits", "strings.circom");

    describe("Fixed length", () => {
        it("(6, 2)", async () => {
            cir_fixed = await test.genMain(file, "SliceFixed", [6, 2]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1 });
            
            assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n]);
        });
    
        it("(6, 6)", async () => {
            cir_fixed = await test.genMain(file, "SliceFixed", [6, 6]);
            await cir_fixed.loadSymbols();
            input = [3,1,5,9,2,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 0 });
            
            assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [3n, 1n, 5n, 9n, 2n, 6n]);
        });
    
        it("Corner case: outputLength = 0", async () => {
            cir_fixed = await test.genMain(file, "SliceFixed", [6, 0]);
            await cir_fixed.loadSymbols();
            input = [3,1,5,9,2,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 0 });
            
            assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), []);
        });
    
        it("Fails when OOB: index >= inputLength", async () => {
            cir_fixed = await test.genMain(file, "SliceFixed", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [3,1,5,9,2,6];
            
            try {
                await cir_fixed.calculateWitness({ "in": input, "index": 6 });
            } catch (e) {
                assert.include(e.message, "Error in template SliceFixed");
            }            
        });

        it("Slice outside: index + outputLength > inputLength", async () => {
            cir_fixed = await test.genMain(file, "SliceFixed", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [3,1,5,9,2,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 4 });
            
            assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 6n, 0n, 0n]);
        });
    })

    describe("Variable length", () => {
        it("(6, 4), 2", async () => {
            cir_fixed = await test.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 2 });
            
            assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n, 0n, 0n]);
        });
        
        it("Corner case: length = 0", async () => {
            cir_fixed = await test.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];

            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 0 });

            assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [0n, 0n, 0n, 0n]);
        });

        it("Corner case: length = outputLength", async () => {
            cir_fixed = await test.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 4 });
            
            assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n, 4n, 5n]);
        });

        it("Fails when OOB: index >= inputLength", async () => {
            cir_fixed = await test.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            try {
                await cir_fixed.calculateWitness({ "in": input, "index": 6, "length": 4 });
            } catch (e) {
                assert.include(e.message, "Error in template Slice");
            }
        });

        it("Fails when OOB: length > outputLength", async () => {
            cir_fixed = await test.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            try {
                await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 5 });
            } catch (e) {
                assert.include(e.message, "Error in template Slice");
            }
        });

        it("Slice outside: index + length > inputLength", async () => {
            cir_fixed = await test.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 4, "length": 4 });
            assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [5n, 6n, 0n, 0n]);
        });

        it("Slice outside:  inputLength >= index + length > outputLength", async () => {
            cir_fixed = await test.genMain(file, "Slice", [8, 6]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6,7,8];
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 4, "length": 4 });
            assert.sameOrderedMembers(utils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [5n, 6n, 7n, 8n, 0n, 0n]);
        });
    });
})

describe("B64SubstrExists and B64SubstrExistsAlt", () => {
    describe("Dummy string", async () => {
        substr = [
                [1, 2, 3, 4],
                [3, 1, 5, 9],
                [2, 7, 1, 8]
        ];
        numSubstrs = 3;
        substrLen = 4;
        substrExpOffsets = [2, 2, 2];
        inCount = 10;

        it("Main", async () => {
            cir_fixed = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
                "B64SubstrExists", [substr, numSubstrs, substrLen, substrExpOffsets, inCount]);
            string = [5, 4, 2, 7, 1, 8, 9, 6, 2, 3];
            startIndex = 0;
            substrIndex = 2;
        
            await cir_fixed.calculateWitness({
                "inputString": string,
                "payloadIndex": startIndex,
                "substringIndex": substrIndex,
                "selector": 2
            });
        });
        
        it("Alt", async () => {
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
                "offsetArray": substrExpOffsets,
                "inputString": string,
                "payloadIndex": startIndex,
                "substringIndex": substrIndex,
                "selector": 2 // substr[2]
            });
        });
    });

    describe("Real (base64) string", () => {
        const sub_claim = '"sub":"4840061"';
        const A = utils.removeDuplicates(b64utils.getAllExtendedBase64Variants(sub_claim));
        const num_options = A.length;
        const sub_in_b64 = A.map(e => e[0].split('').map(c => c.charCodeAt()));
        const option_length = A[0][0].length;
        const offsets = A.map(e => e[1]);

        const header = "Iei.";

        async function run(jwt, index, expected) {
            circuit = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
            "B64SubstrExists", [
                sub_in_b64,
                num_options,
                option_length,
                offsets,
                jwt.length
            ]);

            const witness = await circuit.calculateWitness({
                "inputString": jwt.split('').map(c => c.charCodeAt()),
                "selector": expected,
                "payloadIndex": header.length,
                "substringIndex": index
            });
    
            await circuit.checkConstraints(witness);            
        }

        async function runAlt1(jwt, index, expected) {
            circuit = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
            "B64SubstrExistsAlt", [
                num_options,
                option_length,
                jwt.length
            ]);

            const witness = await circuit.calculateWitness({
                "substringArray": sub_in_b64,
                "substringLength": option_length,
                "offsetArray": offsets,
                "inputString": jwt.split('').map(c => c.charCodeAt()),
                "payloadIndex": header.length,
                "substringIndex": index,
                "selector": expected
            });
    
            await circuit.checkConstraints(witness);
        }

        async function runAlt2(jwt, index, expected) {
            const maxSubstringLength = option_length + 10;

            circuit = await test.genMain(path.join(__dirname, "..", "circuits", "strings.circom"), 
            "B64SubstrExistsAlt", [
                num_options,
                maxSubstringLength,
                jwt.length
            ]);

            const sub_in_b64_padded = sub_in_b64.map(e => e.concat(Array(maxSubstringLength - option_length).fill(0)));

            const witness = await circuit.calculateWitness({
                "substringArray": sub_in_b64_padded,
                "substringLength": option_length,
                "offsetArray": offsets,
                "inputString": jwt.split('').map(c => c.charCodeAt()),
                "payloadIndex": header.length,
                "substringIndex": index,
                "selector": expected
            });
    
            await circuit.checkConstraints(witness);
        }

        describe("Start", async () => {
            const jwt = header + utils.trimEndByChar(Buffer.from(JSON.stringify({
                "sub": "4840061",
                "iat": 1614787200,
                "exp": 1614787200
            })).toString('base64url'), '=');
            const index = jwt.indexOf(A[6][0]);
            assert.equal(index, header.length);

            it("Main", async () => {
                await run(jwt, index, 6);
            });
            it ("Alt w/ substringLength = maxSubstringLength", async () => {
                await runAlt1(jwt, index, 6);
            });
            it ("Alt w/ substringLength < maxSubstringLength", async () => {
                await runAlt2(jwt, index, 6);
            });
        });

        describe("End", async () => {
            for (const [i, iat] of [10, 100, 1].entries()) {
                const jwt = header + utils.trimEndByChar(Buffer.from(JSON.stringify({
                    "iat": iat,
                    "sub": "4840061"
                })).toString('base64url'), '=');    

                const index = jwt.indexOf(A[3 + i][0]);
                assert.notDeepEqual(index, -1);

                it ("Main (index:" + i + ")", async () => {
                    await run(jwt, index, 3 + i);
                });
                it ("Alt w/ substringLength = maxSubstringLength (index:"  + i + ")", async () => {
                    await runAlt1(jwt, index, 3 + i);
                });
                it ("Alt w/ substringLength < maxSubstringLength (index:"  + i + ")", async () => {
                    await runAlt2(jwt, index, 3 + i);
                });
                }
        });

        describe("Middle", async () => {
            for (const [i, iat] of [10, 100, 1].entries()) {
                const jwt = utils.trimEndByChar(Buffer.from(JSON.stringify({
                    "iat": iat,
                    "sub": "4840061",
                    "exp": 1614787200
                })).toString('base64url'), '=');

                const index = jwt.indexOf(A[i][0]);
                assert.notDeepEqual(index, -1);

                it ("Main (index:"  + i + ")", async () => {
                    await run(jwt, index, i);
                });
                it ("Alt w/ substringLength = maxSubstringLength (index:"  + i + ")", async () => {
                    await runAlt1(jwt, index, i);
                });
                it ("Alt w/ substringLength < maxSubstringLength (index:"  + i + ")", async () => {
                    await runAlt2(jwt, index, i);
                });
            }
        });
    });
});