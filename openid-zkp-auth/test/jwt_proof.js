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

describe("JWT Proof", () => {
    const inCount = 448; // 64 * 7. For context, google_jwt size is 413, facebook_jwt: 673.
    const inWidth = 8;
    const outWidth = 253;
    const hashWidth = 128;

    const facebook_jwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjE0ZWJjMDRlNmFjM2QzZTk2MDMxZDJjY2QzODZmY2E5NWRkZjMyZGQifQ.eyJpc3MiOiJodHRwczpcL1wvd3d3LmZhY2Vib29rLmNvbSIsImF1ZCI6IjEyNDE1NTkzNjY3NTUyMTQiLCJzdWIiOiI3MDg1NjI2MTEwMDk1MjUiLCJpYXQiOjE2Nzk5MzIwMTQsImV4cCI6MTY3OTkzNTYxNCwianRpIjoiVEt2ei5kYmVjN2NhMzE5NDJhNWQyZTU2YmQwZGJmYjgyNGIxNzE4NWUwZjMwYjIwZjI1NzNkZTVkNDhmYzlmNTgzZTQzIiwibm9uY2UiOiJ0ZXN0IiwiZ2l2ZW5fbmFtZSI6IkpveSIsImZhbWlseV9uYW1lIjoiV2FuZyIsIm5hbWUiOiJKb3kgV2FuZyIsInBpY3R1cmUiOiJodHRwczpcL1wvcGxhdGZvcm0tbG9va2FzaWRlLmZic2J4LmNvbVwvcGxhdGZvcm1cL3Byb2ZpbGVwaWNcLz9hc2lkPTcwODU2MjYxMTAwOTUyNSZoZWlnaHQ9MTAwJndpZHRoPTEwMCZleHQ9MTY4MjUyNDAxNSZoYXNoPUFlUzBDcW5YTzJjYU94OFg4UWcifQ.ZCJrb_Fsu_cvMy-mCrRrRxSptL-3WhBW7DxasYYaDWGeFcADQKkPW4PW9MZNYrqq00hDqOgUkCJ_brq9Qf1mV2LOfHFmGHUSVwciCFH8f_7KH-Uu1TuPQbduBHgPqXiFkFxxEmz3o25mDO7VjgipRlsez4-XjUYJkSMCYRGkpmRFJPIDtz97dhCLbW16Kb59m8_7Lf4Uz2unDubHnwXeuIPxSmX2wr1WQxiFemFhgvnULZx4PvFnb72eHk9pFlywHrm-bA7qJWnajkrXEDNKAALV2uolgJDlPrlpZLiSW65fT2V3IBZSAsFeq4pCsuxr6eON9KIa8-4TFBy8xL4EZg'
    const jwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk4NmVlOWEzYjc1MjBiNDk0ZGY1NGZlMzJlM2U1YzRjYTY4NWM4OWQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTc5MTI3MzU2NTg1NDEzMzY2NDYiLCJhdF9oYXNoIjoicm9aYm11cUVXdmNHSThDR2N1SnJmUSIsImlhdCI6MTY3OTY3NDE0NSwiZXhwIjoxNjc5Njc3NzQ1fQ.G8cciXefORmYvdwrfVAO6DjDy7DUWe6NxyanGg4w7EQBu8Ab7PJAeXhU7HL5w_LtTgiLA3Ew07RRzuNuaFITvs_m9lIolxHOl0BZSyGIGlI9BRiBFQQK2OZ2b8xetWz3B1mezcwlrrQMgbLQI0puuaA6917h_3MjIgZu_bQkjQH3Lwl3kkZWp0W-PRuK20KAQneNFB9ehTvSeRkImIr5QlZU6LMb7M3rI_-gP6ePRryAN9UCGBASzNEYLaQz-eMIdYFw-WmqkesTX1IDLQT0n44BhG9-9mWIA6kNRSBo9FV89VGKvYION9PTDds1vsf5h3smBQZjourR2H5pLJ_MUA';
    const input = jwt.split('.').slice(0,2).join('.');
    const signature = jwt.split('.')[2];
    const jwk = {
        "e": "AQAB",
        "kty": "RSA",
        "n": "onb-s1Mvbpti06Sp-ZsHH5eeJxdvMhRgfmx5zK7cVlcAajI_0rKu8ylU2CkfgPlMe9-8W5ayozm1h2yx2ToS7P7qoR1sMINXbKxobu8xy9zOBuFAr3WvEoor6lo0Qp747_4bN1sVU6GBEBEXLjb8vHN-o_yoBv8NSB_yP7XbEaS3U5MJ4V2s5o7LziIIRP9PtzF0m3kWm7DuyEzGvCaW8s9bOiMd3eZyXXyfKjlBB727eBXgwqcV-PttECRw6JCLO-11__lmqfKIj5CBw18Pb4ZrNwBa-XrGXfHSSAJXFkR4LR7Bj24sWzlOcKXN2Ew4h3WDJfxtN_StNSYoagyaFQ"
      };
    const subClaim = ',"sub":';
    
    it("sub claim finding", () => {
        const decoded_jwt = Buffer.from(jwt.split('.')[1], 'base64').toString();
        const subClaimIndex = decoded_jwt.indexOf(subClaim);

        const subClaiminB64Options = utils.getAllBase64Variants(subClaim);
        const subClaimIndexInJWT = jwt.indexOf(subClaiminB64Options[subClaimIndex % 3]);
        assert.isTrue(subClaimIndexInJWT !== -1);

        // debug info
        // console.log("subClaimIndexInJWT:", subClaimIndexInJWT);
        // console.log(subClaimIndex % 3, subClaiminB64Options[subClaimIndex % 3]);

        // const subValue = subClaim + '"117912735658541336646",';
        // const subKVinB64Options = utils.getAllBase64Variants(subValue);
        // console.log(subKVinB64Options);
    });

    it("Extract from Base64 JSON", async () => {
        const buildPoseidon = require("circomlibjs").buildPoseidon;
        poseidon = await buildPoseidon();
    
        const hash = crypto.createHash("sha256").update(input).digest("hex");
        
        var inputs = circuit.genJwtProofInputs(input, inCount, ["iss", "aud"], inWidth);
        const nonceExpected = utils.calculateNonce(inputs, poseidon);
        const maskedContent = utils.applyMask(inputs["content"], inputs["mask"]);
        const maskedHashExpected = utils.calculateMaskedHash(maskedContent, poseidon, outWidth);

        const cir = await test.genMain(path.join(__dirname, "..", "circuits", "jwt_proof.circom"), "JwtProof", [inCount]);
        await cir.loadSymbols();
        const witness = await cir.calculateWitness(inputs, true);
        
        const hash2 = utils.getWitnessBuffer(witness, cir.symbols, "main.hash", varSize=hashWidth).toString("hex");
        assert.equal(hash2, hash);

        const maskedHash = utils.getWitnessValue(witness, cir.symbols, "main.out");
        assert.equal(maskedHash, maskedHashExpected);

        const claims = maskedContent.split(/=+/).filter(e => e !== '').map(e => Buffer.from(e, 'base64').toString());
        console.log("claims", claims);
        
        // assert.equal(claims.length, 2, "Incorrect number of claims");
        // assert.include(claims[0], '"iss":"https://accounts.google.com"', "Does not contain iss claim");
        // assert.include(claims[1], '"azp":"407408718192.apps.googleusercontent.com"', "Does not contain azp claim");
        // assert.include(claims[2], '"iat":1679674145', "Does not contain nonce claim");

        const nonceActual = utils.getWitnessValue(witness, cir.symbols, "main.nonce");
        assert.equal(nonceActual, nonceExpected);
        
        const pubkey = await jose.importJWK(jwk);
        assert.isTrue(crypto.createVerify('RSA-SHA256').update(input).verify(pubkey, Buffer.from(signature, 'base64')), "Signature does not correspond to hash");
    });
});
