// Tests for important functions in utils.js and jwtutils.js

const chai = require("chai");
const assert = chai.assert;
const expect = chai.expect;
const crypto = require("crypto");

const circuit = require("../js/circuitutils");
const utils = require("../js/utils");
const jwtutils = require("../js/jwtutils");

describe("Circuit Utilities", () => {
    it("Buffer to/from bit array works as expected", async () => {
        const input = crypto.randomBytes(20*32).toString("hex");
        
        const bits = utils.buffer2BitArray(Buffer.from(input));
        const buffer = utils.bitArray2Buffer(bits);
        
        assert.equal(input, buffer.toString());
    });
    
    it("rfc4634#4.1 padding conforms: L % 512 = 0", async () => {
        const input = crypto.randomBytes(512/8/2).toString("hex");
        
        const bits = utils.buffer2BitArray(Buffer.from(input));
        const padded = circuit.padMessage(bits);
        
        assert.equal(bits.length, 512);
        assert.equal(padded.length, 1024); // Padding a 448+-bit message requires an additional block
        assert.equal(1, padded.slice(-512, -511)); // Padding begins with 1
        assert.equal(bits.length, parseInt(padded.slice(-64).join(''), 2)); // base2(L)
    });
    
    it("rfc4634#4.1 padding conforms: L % 512 = 65", async () => {
        const input = crypto.randomBytes(512/8/2).toString("hex");
        
        const bits = utils.buffer2BitArray(Buffer.from(input)).slice(0, 447);
        const padded = circuit.padMessage(bits);
        
        assert.equal(bits.length, 447);
        assert.equal(padded.length, 512);
        assert.equal(1, padded.slice(-65, -64)); // Padding begins with 1
        assert.equal(bits.length, parseInt(padded.slice(-64).join(''), 2));
    });
    
    it("rfc4634#4.1 padding conforms: L % 512 = 100", async () => {
        const input = crypto.randomBytes(512/8/2).toString("hex");
        
        const bits = utils.buffer2BitArray(Buffer.from(input)).slice(0, 412);
        const padded = circuit.padMessage(bits);
        
        assert.equal(bits.length, 412);
        assert.equal(padded.length, 512);
        assert.equal(1, padded.slice(-100, -99)); // Padding begins with 1
        assert.equal(bits.length, parseInt(padded.slice(-64).join(''), 2));
    });
});

describe("JWT utils tests", () => {
    const getClaimString = jwtutils.getClaimString;
    const b64Len = jwtutils.b64Len;
    const indicesOfB64 = jwtutils.indicesOfB64;
    const decodeB64URL = jwtutils.decodeB64URL;

    describe("getClaimString", () => {
        it("Normal strings", () => {
            // Without quotes, not end
            assert.deepEqual(
                getClaimString('{"iss":12345,"sub":45678,"aud":"https://example.com"}', "iss"),
                '"iss":12345,'
            );

            // With quotes, not end
            assert.deepEqual(
                getClaimString('{"iss":"12345","sub":45678,"aud":"https://example.com"}', "iss"),
                '"iss":"12345",'
            );

            // Without quotes, end
            assert.deepEqual(
                getClaimString('{"iss":12345,"sub":45678}', "sub"),
                '"sub":45678}'
            );
    
            // With quotes, end
            assert.deepEqual(
                getClaimString('{"iss":12345,"sub":45678,"aud":"https://example.com"}', "aud"),
                '"aud":"https://example.com"}'
            );
        })

        it("With escapes", () => {
            assert.deepEqual(
                getClaimString('{"iss":"https:\\/\\/www.facebook.com","sub":45678,"aud":12345}', "iss"),
                '"iss":"https:\\/\\/www.facebook.com",'
            );
    
            assert.deepEqual(
                getClaimString('{"iss":"https:\\/\\/www.facebook.com","sub":45678,"picture":"https:\\/\\/platform-lookaside.fbsbx.com\\/platform\\/profilepic\\/?asid=708562611009525&height=100&width=100&ext=1684596798&hash=AeRIgRL_XooqrdDidNY"}', "picture"),
                '"picture":"https:\\/\\/platform-lookaside.fbsbx.com\\/platform\\/profilepic\\/?asid=708562611009525&height=100&width=100&ext=1684596798&hash=AeRIgRL_XooqrdDidNY"}'
            );
        });
    });

    it("b64Len", () => {
        assert.deepEqual(b64Len(0, 0), 0, "Test case 1");
        assert.deepEqual(b64Len(3, 0), 4, "Test case 2");
        assert.deepEqual(b64Len(3, 1), 5, "Test case 3");
        assert.deepEqual(b64Len(3, 2), 5, "Test case 4");
        assert.deepEqual(b64Len(6, 0), 8, "Test case 5");
        assert.deepEqual(b64Len(6, 1), 9, "Test case 6");
        assert.deepEqual(b64Len(6, 2), 9, "Test case 7");
        assert.deepEqual(b64Len(9, 0), 12, "Test case 8");
        assert.deepEqual(b64Len(9, 1), 13, "Test case 9");
        assert.deepEqual(b64Len(9, 2), 13, "Test case 10");
    });

    describe("decodeB64URL", () => {
        it("Corner case: Two length strings", () => {
            const input = Buffer.from("H").toString('base64url');
            assert.deepEqual(input.length, 2);
            assert.deepEqual(decodeB64URL(input, 0), 'H');

            const input2 = Buffer.from("He").toString('base64url').slice(1);
            assert.deepEqual(input2.length, 2);
            assert.deepEqual(decodeB64URL(input2, 1), 'e');

            const input3 = Buffer.from("Hel").toString('base64url').slice(2);
            assert.deepEqual(input3.length, 2);
            assert.deepEqual(decodeB64URL(input3, 2), 'l');
        });

        it('should decode a tightly packed base64URL string with i % 4 == 0', () => {
            const input = Buffer.from("Hello, world!").toString('base64url');
            const i = 0;
            const expected = "Hello, world!";

            const result = decodeB64URL(input, i);
            assert.deepEqual(result, expected);
        });

        it('should decode a tightly packed base64URL string with i % 4 == 1', () => {
            const input = Buffer.from("Hello, world").toString('base64url').slice(1);
            const i = 1;
            const expected = 'ello, world';
        
            const result = decodeB64URL(input, i);
            assert.deepEqual(result, expected);
        });

        it('should decode a tightly packed base64URL string with i % 4 == 2', () => {
            const input = Buffer.from("Hello, world").toString('base64url').slice(2);
            const i = 2;
            const expected = 'llo, world';
        
            const result = decodeB64URL(input, i);
            assert.deepEqual(result, expected);
        });

        it('should throw an error when i % 4 == 3', () => {
            const input = Buffer.from("Hello, world").toString('base64url');
        
            try {
                decodeB64URL(input, 3);
                assert.fail();
            } catch (e) {
                assert.include(e.message, "not tightly packed because i%4 = 3");
            }
        });

        it('should throw an error when (i + s.length - 1) % 4 == 0', () => {
            const input = Buffer.from("Hello, world").toString('base64url').slice(1);
            const i = 2;
            assert.deepEqual((i + input.length - 1) % 4, 0);
            try {
                decodeB64URL(input, i);
                assert.fail();
            } catch (e) {
                assert.include(e.message, "not tightly packed because (i + s.length - 1)%4 = 0");
            }
        });

        it("Base64url testing", () => {
            // this input has a different base64 and base64url encoding
            const extendedInput = ',' + 'abc/?' + '}';
            const b64 = utils.trimEndByChar(Buffer.from(extendedInput).toString('base64'), '=');
            const b64url = Buffer.from(extendedInput).toString('base64url');
            assert.isTrue(b64 !== b64url);

            assert.deepEqual(decodeB64URL(b64url, 0), extendedInput);
        })
    })

    describe("indicesOfB64, b64Len, b64Index", () => {
        it("Crafted JWTs", () => {
            const sub_claim = '"sub":45678';
            [
                '{"sub":45678,"iss":12345}', // At the start
                '{"iss":12345,"sub":45678}', // At the end
                '{"iss":12345,"sub":45678,"aud":"https://example.com"}' // In the middle
            ].forEach(input => {
                assert.isTrue(input.includes(sub_claim));
                const sub_claim_with_last_char = getClaimString(input, "sub");
                assert.deepEqual(sub_claim_with_last_char.slice(0, -1), sub_claim);
                assert.isTrue(sub_claim_with_last_char.slice(-1) === ',' || sub_claim_with_last_char.slice(-1) === '}');
    
                jwt = Buffer.from(input).toString('base64url');
                const [start, len] = indicesOfB64(jwt, "sub");
    
                const substr = jwt.slice(start, start + len);
                const decoded = decodeB64URL(substr, start % 4);
                assert.deepEqual(decoded, sub_claim_with_last_char);
            });    
        })

        it("Google JWT", () => {
            const jwt = require('./testvectors').google.jwt;
            const payload = jwt.split('.')[1];
            const decoded_payload = Buffer.from(payload, 'base64url').toString();
            const sub_claim_with_last_char = getClaimString(decoded_payload, "sub");
            assert.deepEqual(sub_claim_with_last_char, '"sub":"110463452167303598383",');

            const [start, len] = indicesOfB64(payload, "sub");
            const substr = payload.slice(start, start + len);
            const decoded = decodeB64URL(substr, start % 4);
            assert.deepEqual(decoded, sub_claim_with_last_char);    
        })

        it("Twitch JWT", () => {
            const jwt = require('./testvectors').twitch.jwt;
            const payload = jwt.split('.')[1];
            const decoded_payload = Buffer.from(payload, 'base64url').toString();

            const sub_claim_with_last_char = getClaimString(decoded_payload, "sub");
            assert.deepEqual(sub_claim_with_last_char, '"sub":"904448692",');
            const [start, len] = indicesOfB64(payload, "sub");
            const substr = payload.slice(start, start + len);
            const decoded = decodeB64URL(substr, start % 4);
            assert.deepEqual(decoded, sub_claim_with_last_char);

            const username = getClaimString(decoded_payload, "preferred_username");
            assert.deepEqual(username, '"preferred_username":"joyqvq"}');
            const [start2, len2] = indicesOfB64(payload, "preferred_username");
            const substr2 = payload.slice(start2, start2 + len2);
            const decoded2 = decodeB64URL(substr2, start2 % 4);
            assert.deepEqual(decoded2, username);
        })
    })
});