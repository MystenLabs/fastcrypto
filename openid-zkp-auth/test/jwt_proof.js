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

const google_playground = {
    jwt: 'eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk4NmVlOWEzYjc1MjBiNDk0ZGY1NGZlMzJlM2U1YzRjYTY4NWM4OWQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTc5MTI3MzU2NTg1NDEzMzY2NDYiLCJhdF9oYXNoIjoicm9aYm11cUVXdmNHSThDR2N1SnJmUSIsImlhdCI6MTY3OTY3NDE0NSwiZXhwIjoxNjc5Njc3NzQ1fQ.G8cciXefORmYvdwrfVAO6DjDy7DUWe6NxyanGg4w7EQBu8Ab7PJAeXhU7HL5w_LtTgiLA3Ew07RRzuNuaFITvs_m9lIolxHOl0BZSyGIGlI9BRiBFQQK2OZ2b8xetWz3B1mezcwlrrQMgbLQI0puuaA6917h_3MjIgZu_bQkjQH3Lwl3kkZWp0W-PRuK20KAQneNFB9ehTvSeRkImIr5QlZU6LMb7M3rI_-gP6ePRryAN9UCGBASzNEYLaQz-eMIdYFw-WmqkesTX1IDLQT0n44BhG9-9mWIA6kNRSBo9FV89VGKvYION9PTDds1vsf5h3smBQZjourR2H5pLJ_MUA',
    jwk: {
        "e": "AQAB",
        "kty": "RSA",
        "n": "onb-s1Mvbpti06Sp-ZsHH5eeJxdvMhRgfmx5zK7cVlcAajI_0rKu8ylU2CkfgPlMe9-8W5ayozm1h2yx2ToS7P7qoR1sMINXbKxobu8xy9zOBuFAr3WvEoor6lo0Qp747_4bN1sVU6GBEBEXLjb8vHN-o_yoBv8NSB_yP7XbEaS3U5MJ4V2s5o7LziIIRP9PtzF0m3kWm7DuyEzGvCaW8s9bOiMd3eZyXXyfKjlBB727eBXgwqcV-PttECRw6JCLO-11__lmqfKIj5CBw18Pb4ZrNwBa-XrGXfHSSAJXFkR4LR7Bj24sWzlOcKXN2Ew4h3WDJfxtN_StNSYoagyaFQ"
    }
}

const google_app = {
    jwt: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFjZGEzNjBmYjM2Y2QxNWZmODNhZjgzZTE3M2Y0N2ZmYzM2ZDExMWMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1NzU1MTkyMDQyMzctbXNvcDllcDQ1dTJ1bzk4aGFwcW1uZ3Y4ZDg0cWRjOGsuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTA0NjM0NTIxNjczMDM1OTgzODMiLCJub25jZSI6IjIyNzI1NTA4MTA4NDE5ODUwMTgxMzkxMjY5MzEwNDExOTI5MjcxOTA1NjgwODQwODIzOTk0NzM5NDMyMzkwODAzMDUyODE5NTczMzAiLCJpYXQiOjE2ODA4MTE4MDIsImV4cCI6MTY4MDgxNTQwMiwianRpIjoiN2U5ZTczY2YyOGI5YTRjZTc0NDE2MTE1YzI5MjYwOWNhYzg2NzBkMCJ9.dOlPIrRRPTVHvDADaCuA8t8njwU_tVKiSIQXpsOSqMmg3Mtm_35ixEDNuwCHr5TA_rE8_ETBqSwYxTbIcLhYg8FsnPk02BRA9kMiLXbMAY5dCqUDoIjp6zFBH2fEe-Zqubj7JJb2I0CMm4d8cJaA_a-GoaFT9jIbta5BPstc8LTKMbLie-7Sm1EA3wDZXc2QutxNWzCN8Bkr1HqVIHiJlpTJARFie9VqZ883CM_C_gcpGP7GXS7rQqom-byXvnR1dFsXKR-mzQh-_j3Ksuvrh59Tw61tx-brdXab2cp-N_vpx7bvcNeCRDSfHU4yC0h9upV69VmJ-mgBj_Tm1G18pQ",
    jwk: {
        "e": "AQAB",
        "kty": "RSA",
        "n": "r54td3hTv87IwUNhdc-bYLIny4tBVcasvdSd7lbJILg58C4DJ0RJPczXd_rlfzzYGvgpt3Okf_anJd5aah196P3bqwVDdelcDYAhuajBzn40QjOBPefvdD5zSo18i7OtG7nhAhRSEGe6Pjzpck3wAogqYcDgkF1BzTsRB-DkxprsYhp5pmL5RnX-6EYP5t2m9jJ-_oP9v1yvZkT5UPb2IwOk5GDllRPbvp-aJW_RM18ITU3qIbkwSTs1gJGFWO7jwnxT0QBaFD8a8aev1tmR50ehK-Sz2ORtvuWBxbzTqXXL39qgNJaYwZyW-2040vvuZnaGribcxT83t3cJlQdMxw"
    }
}

describe("JWT Proof", () => {
    const inCount = 64 * 7; // 64 * 7
    const inWidth = 8;
    const outWidth = 253;
    const hashWidth = 128;

    const jwt = google_playground["jwt"];
    const input = jwt.split('.').slice(0,2).join('.');
    const signature = jwt.split('.')[2];
    const jwk = google_playground["jwk"];
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
        var inputs = await circuit.genJwtProofInputs(input, inCount, ["iss", "aud"], inWidth, outWidth);

        const cir = await test.genMain(
            path.join(__dirname, "..", "circuits", "jwt_proof.circom"),
            "JwtProof",
            [inCount]
        );

        const w = await cir.calculateWitness(inputs, true);
        await cir.checkConstraints(w);

        const maskedContent = utils.applyMask(inputs["content"], inputs["mask"]);
        assert.deepEqual(maskedContent.split('.').length, 2);
        const header = Buffer.from(maskedContent.split('.')[0], 'base64').toString();
        const claims = maskedContent.split('.')[1].split(/=+/).filter(e => e !== '').map(e => Buffer.from(e, 'base64').toString());
        console.log("header", header, "\nclaims", claims);
        
        // assert.equal(claims.length, 2, "Incorrect number of claims");
        // assert.include(claims[0], '"iss":"https://accounts.google.com"', "Does not contain iss claim");
        // assert.include(claims[1], '"azp":"407408718192.apps.googleusercontent.com"', "Does not contain azp claim");
        // assert.include(claims[2], '"iat":1679674145', "Does not contain nonce claim");
        
        const pubkey = await jose.importJWK(jwk);
        assert.isTrue(crypto.createVerify('RSA-SHA256').update(input).verify(pubkey, Buffer.from(signature, 'base64')), "Signature does not correspond to hash");
    });
});
