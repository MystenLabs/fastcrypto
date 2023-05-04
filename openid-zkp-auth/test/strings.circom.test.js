const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const jwtutils = require("../js/jwtutils");
const utils = require("../js/utils");

const testutils = require("./testutils");

describe("Slices", () => {
    const file = path.join(__dirname, "../circuits/helpers", "strings.circom");

    describe("Fixed length", () => {
        it("(6, 2)", async () => {
            cir_fixed = await testutils.genMain(file, "SliceFixed", [6, 2]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1 });
            
            assert.sameOrderedMembers(testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n]);
        });
    
        it("(6, 6)", async () => {
            cir_fixed = await testutils.genMain(file, "SliceFixed", [6, 6]);
            await cir_fixed.loadSymbols();
            input = [3,1,5,9,2,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 0 });
            
            assert.sameOrderedMembers(testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [3n, 1n, 5n, 9n, 2n, 6n]);
        });
    
        it("Fails when OOB: index >= inputLength", async () => {
            cir_fixed = await testutils.genMain(file, "SliceFixed", [6, 4]);
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
            cir_fixed = await testutils.genMain(file, "SliceFixed", [6, 4]);
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
            cir_fixed = await testutils.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 2 });
            
            assert.sameOrderedMembers(testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n, 0n, 0n]);
        });
        
        it("Corner case: length = 0", async () => {
            cir_fixed = await testutils.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];

            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 0 });

            assert.sameOrderedMembers(testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [0n, 0n, 0n, 0n]);
        });

        it("Corner case: length = outputLength", async () => {
            cir_fixed = await testutils.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];
            
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 4 });
            
            assert.sameOrderedMembers(testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [2n, 3n, 4n, 5n]);
        });

        it("Fails when index >= inputLength", async () => {
            cir_fixed = await testutils.genMain(file, "Slice", [6, 4]);
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
            cir_fixed = await testutils.genMain(file, "Slice", [6, 4]);
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
            cir_fixed = await testutils.genMain(file, "Slice", [6, 4]);
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
            cir_fixed = await testutils.genMain(file, "Slice", [8, 6]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6,7,8];
            const witness = await cir_fixed.calculateWitness({ "in": input, "index": 4, "length": 4 });
            assert.sameOrderedMembers(testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out"), [5n, 6n, 7n, 8n, 0n, 0n]);
        });
    });
})

describe("ASCIISubstrExistsInB64" , () => {
    async function genCircuit(maxJwtLen, maxA) {
        return await testutils.genMain(
            path.join(__dirname, "../circuits/helpers", "strings.circom"),
            "ASCIISubstrExistsInB64",
            [maxJwtLen, maxA]
        );
    }

    async function genProof(circuit, jwt, maxJwtLen, A, maxA, indexB, lenB, payloadIndex, lenA=A.length) {
        assert.isTrue(jwt.length <= maxJwtLen, "JWT too long");
        assert.isTrue(A.length <= maxA, "A too long");

        const witness = await circuit.calculateWitness({
            "b64Str":  utils.padWithZeroes(jwt.split("").map(c => c.charCodeAt(0)), maxJwtLen), // pad with 0s
            "lenB": lenB,
            "BIndex": indexB,
            "A": utils.padWithZeroes(A.split("").map(c => c.charCodeAt(0)), maxA), // pad with 0s
            "lenA": lenA,
            "payloadIndex": payloadIndex
        });

        await circuit.checkConstraints(witness);
    }

    describe("lenA < maxA", () => {
        const maxJwtLen = 200;
        const A = '"sub":"4840061"}';
        const maxA = A.length + 14;
        const maxB = 1 + ((maxA / 3) * 4);
        var circuit;

        before(() => {
            assert.equal(maxA % 3, 0);
            assert.isTrue(maxB <= maxJwtLen);
        })

        beforeEach(async () => {
            circuit = await genCircuit(maxJwtLen, maxA);
        });

        describe("Simple JWTs", () => {
            // Prefixes chosen such that index of A in the JWT is 0, 1, 2
            const prefixes = ['{   ', '{', '{ '];
            const decoded_jwts = prefixes.map(prefix => prefix + A);
            const jwts = decoded_jwts.map(jwt => Buffer.from(jwt).toString("base64url"));

            const X = jwts.map(jwt => jwtutils.indicesOfB64(jwt, 'sub'));
            const indicesB = X.map(tuple => tuple[0]);
            const lensB = X.map(tuple => tuple[1]);

            before(async () => {
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
            });

            for (let offset = 0; offset < 3; offset++) {
                it(`Succeeds when A is at offset ${offset}`, async () => {
                    await genProof(circuit, jwts[offset], maxJwtLen, A, maxA, indicesB[offset], lensB[offset], 0);
                });
    
                it("Fails when substring index is either large or small", async () => {
                    for (let i in [1, -1]) {
                        try {
                            await genProof(circuit, jwts[offset], maxJwtLen, A, maxA, indicesB[offset] + i, lensB[offset], 0);
                            assert.fail("Should have failed");
                        } catch (e) {
                            assert.include(e.message, "Error in template ASCIISubstrExistsInB64");
                        }
                    }
                });
    
                it("Fails when lenB is small", async () => {
                    try {
                        await genProof(circuit, jwts[offset], maxJwtLen, A, maxA, indicesB[offset], lensB[offset] - 1, 0);
                        assert.fail("Should have failed");
                    } catch (e) {
                        assert.include(e.message, "Error in template ASCIISubstrExistsInB64");
                    }
                });
    
                it("Succeeds when lenB is large", async() => {
                    await genProof(circuit, jwts[offset], maxJwtLen, A, maxA, indicesB[offset], lensB[offset] + 1, 0);
                });
            }
    
            it("Fails when substring index < payload index", async () => {
                try {
                    await genProof(circuit, jwts[0], maxJwtLen, A, maxA, indicesB[0], lensB[0], indicesB[0] + 1);
                    assert.fail("Should have failed");
                } catch (e) {
                    assert.include(e.message, "Error in template RemainderMod4");
                    assert.include(e.message, "Error in template Num2Bits");
                }
            });    
        });

        describe("Bigger JWTs", async () => {
            const payload = JSON.stringify({
                "iat": 1616421600,
                "exp": 1616425200,
                "name": "John Doe",
                "sub": "4840061"
            });
            const encoded_payload = Buffer.from(payload).toString("base64url");

            it("No header", async () => {
                const jwt = encoded_payload;
                [index, len] = jwtutils.indicesOfB64(jwt, 'sub');
                await genProof(circuit, jwt, maxJwtLen, A, maxA, index, len, 0);    
            });

            it("With header", async () => {
                const header = JSON.stringify({
                    "alg": "RS256",
                    "typ": "JWT"
                });
                const jwt = Buffer.from(header).toString("base64url") + "." + encoded_payload;
                [index, len] = jwtutils.indicesOfB64(encoded_payload, 'sub');
                const payload_index = jwt.indexOf(encoded_payload);
                await genProof(circuit, jwt, maxJwtLen, A, maxA, index + payload_index, len, payload_index);
            });

            it("lenB = maxB", async () => {
                const jwt = encoded_payload;
                [index, len] = jwtutils.indicesOfB64(jwt, 'sub');
                await genProof(circuit, jwt, maxJwtLen, A, maxA, index, maxB, 0);
            });

            it("Fails when lenB > maxB or lenB < 0", async () => {
                const jwt = encoded_payload;
                [index, len] = jwtutils.indicesOfB64(jwt, 'sub');
                for (lenB of [-1, maxB + 1]) {
                    try {
                        await genProof(circuit, jwt, maxJwtLen, A, maxA, index, lenB, 0);
                        assert.fail("Should have failed");
                    } catch (e) {
                        assert.include(e.message, "Error in template RangeCheck");
                        assert.include(e.message, "Error in template Slice");
                    }
                }
            })

            it("Fails when lenA > maxA or lenA < 0", async () => {
                const jwt = encoded_payload;
                [index, len] = jwtutils.indicesOfB64(jwt, 'sub');
                for (lenA of [maxA + 1, -1]) {
                    try {
                        await genProof(circuit, jwt, maxJwtLen, A, maxA, index, len, 0, lenA);
                        assert.fail("Should have failed");
                    } catch (e) {
                        assert.include(e.message, "Error in template LTBitVector");
                    }
                }
            });

        });
    });

    it("lenA = maxA", async () => {
        const maxJwtLen = 200;
        const A = '"sub":"484061",'; // 15 chars
        assert.deepEqual(A.length % 3, 0);

        const lenA = A.length;
        const maxA = lenA;
        const maxB = 1 + ((maxA / 3) * 4);
        const header = JSON.stringify({
            "alg": "RS256",
            "typ": "JWT"
        });
        const payload = JSON.stringify({
            "sub": "484061",
            "iat": 1616421600,
            "exp": 1616425200,
            "name": "John Doe"
        });
        assert.deepEqual(jwtutils.getClaimString(payload, 'sub'), A);
        const encoded_payload = Buffer.from(payload).toString("base64url");
        const jwt = Buffer.from(header).toString("base64url") + "." + encoded_payload;

        const payload_index = jwt.indexOf(encoded_payload);

        [index, len] = jwtutils.indicesOfB64(encoded_payload, 'sub');
        assert.isAtMost(len, maxB);

        const circuit = await genCircuit(maxJwtLen, maxA);
        await genProof(circuit, jwt, maxJwtLen, A, maxA, index + payload_index, len, payload_index);
    });
});