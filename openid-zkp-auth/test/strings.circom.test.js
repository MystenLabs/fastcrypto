const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const expect = chai.expect;

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

        it("Fails when length = 0", async () => {
            cir_fixed = await testutils.genMain(file, "Slice", [6, 4]);
            await cir_fixed.loadSymbols();
            input = [1,2,3,4,5,6];

            try {
                await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 0 });
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

    describe("Variable length with SliceGrouped", () => {
        var template_name = "SliceGrouped";

        describe("numsPerGroup = 2", () => {
            var inWidth = 3;
            var numsPerGroup = 2;
            var inLen = 6;
            var outLen = 4;
            var params = [inWidth, numsPerGroup, inLen, outLen];
    
            before(() => {
                expect(inLen % numsPerGroup).to.equal(0);
            });
    
            it("(6, 4), 2", async () => {
                cir_fixed = await testutils.genMain(file, template_name, params);
                await cir_fixed.loadSymbols();
                input = [1,2,3,4,5,6];
                const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 2 });
                assert.sameOrderedMembers(
                    testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out").slice(0, 2),
                    [2n, 3n]
                );
            });
    
            it("Corner case: length = outputLength", async () => {
                cir_fixed = await testutils.genMain(file, template_name, params);
                await cir_fixed.loadSymbols();
                input = [1,2,3,4,5,6];
                const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 4 });
                assert.sameOrderedMembers(
                    testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out"),
                    [2n, 3n, 4n, 5n]
                );
            });
    
            it("Slice outside: inputLength = (index + length) > outputLength", async () => {
                cir_fixed = await testutils.genMain(file, template_name, [4, numsPerGroup, 8, 6]);
                await cir_fixed.loadSymbols();
                input = [1,2,3,4,5,6,7,8];
                const witness = await cir_fixed.calculateWitness({ "in": input, "index": 4, "length": 4 });
                assert.sameOrderedMembers(
                    testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out").slice(0, 4),
                    [5n, 6n, 7n, 8n]
                );
            });
    
            it("Fails when length = 0", async () => {
                cir_fixed = await testutils.genMain(file, template_name, params);
                await cir_fixed.loadSymbols();
                input = [1,2,3,4,5,6];
    
                try {
                    await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 0 });
                    assert.fail("Should have failed");
                } catch (e) {
                    assert.include(e.message, "Error in template RangeCheck");
                }
            });
    
            it("Fails when index >= inputLength", async () => {
                cir_fixed = await testutils.genMain(file, template_name, params);
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
                cir_fixed = await testutils.genMain(file, template_name, params);
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
                cir_fixed = await testutils.genMain(file, template_name, params);
                await cir_fixed.loadSymbols();
                input = [1,2,3,4,5,6];
                try {
                    await cir_fixed.calculateWitness({ "in": input, "index": 4, "length": 4 });
                    assert.fail("Should have failed");
                } catch (e) {
                    assert.include(e.message, "Error in template RangeCheck");
                }
            });    
        });

        describe("numsPerGroup = 4", () => {
            var inWidth = 4;
            var numsPerGroup = 4;

            describe("OutLen tests", () => {
                for (var outLen = 1; outLen <= 20; outLen += 1) {
                    (function(outLen) {
                        it(`outLen: ${outLen}`, async () => {
                            var inLen = 12;
                            expect(inLen % numsPerGroup).to.equal(0);
                            var params = [inWidth, numsPerGroup, inLen, outLen];
                            cir_fixed = await testutils.genMain(file, template_name, params);
                            await cir_fixed.loadSymbols();
                            input = [1,2,3,4,5,6,7,8,9,10,11,12];
                            try {
                                const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": 4 });
                                const output = testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out");
                                assert.sameOrderedMembers(
                                    output.slice(0, 4),
                                    [2n, 3n, 4n, 5n]
                                );
                                if (outLen < 4) {
                                    assert.fail("Should have failed");
                                }
                            } catch (e) {
                                assert.include(e.message, "Error in template RangeCheck");
                            }
                        });
                    })(outLen);
                }    
            });

            describe("Index tests", () => {
                var inLen = 12;
                var outLen = 8;
                
                for (var index = 0; index < 12; index += 1) {
                    (function(index) {
                        it(`index: ${index}`, async () => {
                            expect(inLen % numsPerGroup).to.equal(0);
                            var params = [inWidth, numsPerGroup, inLen, outLen];
                            cir_fixed = await testutils.genMain(file, template_name, params);
                            await cir_fixed.loadSymbols();
                            input = [1,2,3,4,5,6,7,8,9,10,11,12];
                            try {
                                const witness = await cir_fixed.calculateWitness({ "in": input, "index": index, "length": 4 });
                                const output = testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out");    
                                assert.sameOrderedMembers(
                                    output.slice(0, 4).map(Number),
                                    input.slice(index, index + 4)
                                );
                                if (index + 4 > inLen) {
                                    assert.fail("Should have failed");
                                }
                            } catch (e) {
                                assert.include(e.message, "Error in template RangeCheck");
                            }
                        });
                    })(index);
                }    
            });

            describe("Length tests", () => {
                var inLen = 12;
                var outLen = 8;
                for (var length = 1; length <= 12; length += 1) {
                    (function(length) {
                        it(`length: ${length}`, async () => {
                            expect(inLen % numsPerGroup).to.equal(0);
                            var params = [inWidth, numsPerGroup, inLen, outLen];
                            cir_fixed = await testutils.genMain(file, template_name, params);
                            await cir_fixed.loadSymbols();
                            input = [1,2,3,4,5,6,7,8,9,10,11,12];
                            try {
                                const witness = await cir_fixed.calculateWitness({ "in": input, "index": 1, "length": length });
                                const output = testutils.getWitnessArray(witness, cir_fixed.symbols, "main.out");    
                                assert.sameOrderedMembers(
                                    output.slice(0, length).map(Number),
                                    input.slice(1, 1 + length)
                                );
                                if (1 + length > inLen || length > outLen) {
                                    assert.fail("Should have failed");
                                }
                            } catch (e) {
                                assert.include(e.message, "Error in template RangeCheck");
                            }
                        });
                    })(length);
                }
            });

        });
    });

})

describe("ASCIISubstrExistsInB64" , () => {
    const numsPerGroup = 8;

    async function genCircuit(maxJwtLen, maxA, numsPerGroup) {
        return await testutils.genMain(
            path.join(__dirname, "../circuits/helpers", "strings.circom"),
            "ASCIISubstrExistsInB64",
            [maxJwtLen, maxA, numsPerGroup]
        );
    }

    async function genProof(circuit, jwt, maxJwtLen, A, maxA, indexB, lenB, payloadIndex, lenA=A.length) {
        assert.isTrue(jwt.length <= maxJwtLen, "JWT too long");
        assert.isTrue(A.length <= maxA, "A too long");

        const inputs = {
            "b64Str":  utils.padWithZeroes(jwt.split("").map(c => c.charCodeAt(0)), maxJwtLen), // pad with 0s
            "lenB": lenB,
            "BIndex": indexB,
            "A": utils.padWithZeroes(A.split("").map(c => c.charCodeAt(0)), maxA), // pad with 0s
            "lenA": lenA,
            "payloadIndex": payloadIndex
        };

        const witness = await circuit.calculateWitness(inputs);
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
            assert.equal(maxJwtLen % numsPerGroup, 0);
        })

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
                    assert.deepEqual(jwtutils.getExtendedClaim(decoded_jwts[i], 'sub'), A);
                    assert.deepEqual(jwtutils.decodeBase64URL(
                        jwts[i].slice(indicesB[i], indicesB[i] + lensB[i]),
                        indicesB[i]
                    ), A);
                }
            });

            for (let offset = 0; offset < 3; offset++) {
                it(`Succeeds when A is at offset ${offset}`, async () => {
                    circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
                    await genProof(circuit, jwts[offset], maxJwtLen, A, maxA, indicesB[offset], lensB[offset], 0);
                });
    
                it(`Fails when substring index is either large or small. A offset ${offset}`, async () => {
                    for (let i in [1, -1]) {
                        try {
                            circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
                            await genProof(circuit, jwts[offset], maxJwtLen, A, maxA, indicesB[offset] + i, lensB[offset], 0);
                            assert.fail("Should have failed");
                        } catch (e) {
                            assert.include(e.message, "Error in template ASCIISubstrExistsInB64");
                        }
                    }
                });

                // NOTE: Removed "Fails when lenB is small" tests after the change to SliceGrouped as it might succeed in some cases now.
    
                it(`Succeeds when lenB is large. A offset ${offset}`, async() => {
                    circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
                    await genProof(circuit, jwts[offset], maxJwtLen, A, maxA, indicesB[offset], lensB[offset] + 1, 0);
                });
            }
    
            it("Fails when substring index < payload index", async () => {
                try {
                    circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
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
                circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
                const jwt = encoded_payload;
                [index, len] = jwtutils.indicesOfB64(jwt, 'sub');
                await genProof(circuit, jwt, maxJwtLen, A, maxA, index, len, 0);    
            });

            it("With header", async () => {
                circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
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
                circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
                const jwt = encoded_payload;
                [index, len] = jwtutils.indicesOfB64(jwt, 'sub');
                await genProof(circuit, jwt, maxJwtLen, A, maxA, index, maxB, 0);
            });

            it("Fails when lenB > maxB or lenB < 0", async () => {
                const jwt = encoded_payload;
                [index, len] = jwtutils.indicesOfB64(jwt, 'sub');
                for (lenB of [-1, maxB + 1]) {
                    circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
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
                    circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
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
        assert.deepEqual(jwtutils.getExtendedClaim(payload, 'sub'), A);
        const encoded_payload = Buffer.from(payload).toString("base64url");
        const jwt = Buffer.from(header).toString("base64url") + "." + encoded_payload;

        const payload_index = jwt.indexOf(encoded_payload);

        [index, len] = jwtutils.indicesOfB64(encoded_payload, 'sub');
        assert.isAtMost(len, maxB);

        const circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
        await genProof(circuit, jwt, maxJwtLen, A, maxA, index + payload_index, len, payload_index);
    });

    it("Nonce", async() => {
        const maxJwtLen = 200;
        const bignum = 8679359968269066238270369971672891012793979385072768529748854974904529914083n;
        const numbits = bignum.toString(2).length;
        expect(numbits).to.be.at.most(254);

        const bignum_in_base64 = Buffer.from(bignum.toString(16), "hex").toString("base64url");
        chai.expect(bignum_in_base64.length).to.equal(Math.ceil(numbits / 6));

        const A = '"nonce":"' + bignum_in_base64 + '",'; // <= 11 + Math.ceil(254/6) = 54 chars 

        const lenA = A.length;
        const maxA = lenA;
        expect(maxA).to.be.at.most(54);
        const maxB = 1 + ((maxA / 3) * 4);

        const header = JSON.stringify({
            "alg": "RS256",
            "typ": "JWT"
        });
        const payload = JSON.stringify({
            "sub": "484061",
            "iat": 1616421600,
            "exp": 1616425200,
            "nonce": bignum_in_base64,
            "name": "John Doe"
        });
        assert.deepEqual(jwtutils.getExtendedClaim(payload, 'nonce'), A);

        const encoded_payload = Buffer.from(payload).toString("base64url");
        const jwt = Buffer.from(header).toString("base64url") + "." + encoded_payload;
        const payload_index = jwt.indexOf(encoded_payload);
        const [index, len] = jwtutils.indicesOfB64(encoded_payload, 'nonce');
        assert.isAtMost(len, maxB);

        const circuit = await genCircuit(maxJwtLen, maxA, numsPerGroup);
        await genProof(circuit, jwt, maxJwtLen, A, maxA, index + payload_index, len, payload_index);
    });
});
