const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const jwtutils = require("../js/jwtutils");
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
    
        it("Fails when OOB: index >= inputLength", async () => {
            cir_fixed = await test.genMain(file, "SliceFixed", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [3,1,5,9,2,6];
            
            try {
                await cir_fixed.calculateWitness({ "in": input, "index": 6 });
                assert.fail("Should have failed");
            } catch (e) {
                assert.include(e.message, "Error in template RangeCheck");
            }
        });

        it("Slice outside: index + outputLength > inputLength", async () => {
            cir_fixed = await test.genMain(file, "SliceFixed", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [3,1,5,9,2,6];
            
            try {
                await cir_fixed.calculateWitness({ "in": input, "index": 4 });
                assert.fail("Should have failed");
            } catch (e) {
                assert.include(e.message, "Error in template RangeCheck");
            }
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

        it("Fails when index >= inputLength", async () => {
            cir_fixed = await test.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            try {
                await cir_fixed.calculateWitness({ "in": input, "index": 6, "length": 4 });
                assert.fail("Should have failed");
            } catch (e) {
                assert.include(e.message, "Error in template RangeCheck");
            }
        });

        it("Fails when length > outputLength", async () => {
            cir_fixed = await test.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            try {
                await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 5 });
                assert.fail("Should have failed");
            } catch (e) {
                assert.include(e.message, "Error in template RangeCheck");
            }
        });

        it("Fails when index + length > inputLength", async () => {
            cir_fixed = await test.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            try {
                await cir_fixed.calculateWitness({ "in": input, "index": 4, "length": 4 });
                assert.fail("Should have failed");
            } catch (e) {
                assert.include(e.message, "Error in template RangeCheck");
            }
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

describe("ASCIISubstrExistsInB64" , () => {
    async function gen(jwt, maxJwtLen, A, maxA, indexB, lenB, payloadIndex) {
        assert.isTrue(jwt.length <= maxJwtLen, "JWT too long");
        const circuit = await test.genMain(
            path.join(__dirname, "..", "circuits", "strings.circom"),
            "ASCIISubstrExistsInB64",
            [maxJwtLen, maxA]
        );

        const witness = await circuit.calculateWitness({
            "b64Str": jwt.split("").map(c => c.charCodeAt(0)).concat(Array(maxJwtLen - jwt.length).fill(0)), // pad with 0s
            "lenB": lenB,
            "BIndex": indexB,
            "A": A.split("").map(c => c.charCodeAt(0)).concat(Array(maxA - A.length).fill(0)), // pad with 0s
            "lenA": A.length,
            "payloadIndex": payloadIndex
        });

        await circuit.checkConstraints(witness);
    }

    describe("Simple JWTs", () => {
        const maxJwtLen = 100;
        const A = '"sub":"4840061"}';
        const maxA = A.length + 14;
        const maxB = 1 + ((maxA / 3) * 4);

        // Prefixes chosen such that index of A in the JWT is 0, 1, 2
        const prefixes = ['{   ', '{', '{ '];
        const decoded_jwts = prefixes.map(prefix => prefix + A);
        const jwts = decoded_jwts.map(jwt => Buffer.from(jwt).toString("base64url"));

        const X = jwts.map(jwt => jwtutils.indicesOfB64(jwt, 'sub'));
        const indicesB = X.map(tuple => tuple[0]);
        const lensB = X.map(tuple => tuple[1]);

        before(() => {
            assert.equal(maxA % 3, 0);
            assert.isTrue(maxB <= maxJwtLen);
            for (let i = 0; i < decoded_jwts.length; i++) {
                assert.deepEqual(decoded_jwts[i].indexOf(A) % 4 , i);
                assert.deepEqual(jwtutils.getClaimString(decoded_jwts[i], 'sub'), A);
                assert.deepEqual(jwtutils.decodeB64URL(
                    jwts[i].slice(indicesB[i], indicesB[i] + lensB[i]),
                    indicesB[i]
                ), A);
            }
            // console.log(jwts);
            // console.log(X);
            // console.log("lenBs", lensB);
            // console.log("BIndices", indicesB);
        });

        for (let offset = 0; offset < 3; offset++) {
            it(`Succeeds when A is at offset ${offset}`, async () => {
                await gen(jwts[offset], maxJwtLen, A, maxA, indicesB[offset], lensB[offset], 0);
            });

            it("Fails when substring index is either large or small", async () => {
                for (let i in [1, -1]) {
                    try {
                        await gen(jwts[offset], maxJwtLen, A, maxA, indicesB[offset] + i, lensB[offset], 0);
                        assert.fail("Should have failed");
                    } catch (e) {
                        assert.include(e.message, "Error in template ASCIISubstrExistsInB64");
                    }
                }
            });

            it("Fails when lenB is small", async () => {
                try {
                    await gen(jwts[offset], maxJwtLen, A, maxA, indicesB[offset], lensB[offset] - 1, 0);
                    assert.fail("Should have failed");
                } catch (e) {
                    assert.include(e.message, "Error in template ASCIISubstrExistsInB64");
                }
            });

            it("Succeeds when lenB is large", async() => {
                await gen(jwts[offset], maxJwtLen, A, maxA, indicesB[offset], lensB[offset] + 1, 0);
            });
        }

        it("Fails when substring index < payload index", async () => {
            try {
                await gen(jwts[0], maxJwtLen, A, maxA, indicesB[0], lensB[0], indicesB[0] + 1);
                assert.fail("Should have failed");
            } catch (e) {
                assert.include(e.message, "Error in template RemainderMod4");
                assert.include(e.message, "Error in template Num2Bits");
            }
        });
    });
});