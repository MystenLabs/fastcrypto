const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const crypto = require("crypto");
const jose = require("jose");

const circuit = require("../js/circuit");
const utils = require("../js/utils");
const test = require("../js/test");
const GOOGLE = require("../js/testvectors").google_extension;

describe("JWT Proof", () => {
    const inCount = 64 * 11; // This is the maximum length of a JWT
    const inWidth = 8;
    const outWidth = 253;

    const jwt = GOOGLE["jwt"];
    const jwk = GOOGLE["jwk"];

    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;

    const subClaim = utils.getExtendedClaim(payload, "sub");
    const subInB64 = utils.getAllBase64Variants(subClaim);
    
    it("sub claim finding", () => {
        const decoded_jwt = Buffer.from(payload, 'base64').toString();
        const subClaimIndex = decoded_jwt.indexOf(subClaim);

        const subClaiminB64Options = utils.getAllBase64Variants(subClaim);
        const subClaimIndexInJWT = jwt.indexOf(subClaiminB64Options[subClaimIndex % 3][0]);
        assert.isTrue(subClaimIndexInJWT !== -1);
    });

    it("Extract from Base64 JSON", async () => {
        var inputs = await circuit.genJwtProofInputs(input, inCount, ["iss", "aud", "nonce"], inWidth, outWidth);
        const masked_content = utils.applyMask(inputs["content"], inputs["mask"]);
        utils.checkMaskedContent(masked_content, inputs["last_block"], inCount);
        // utils.writeJSONToFile(inputs, "inputs.json");

        const cir = await test.genMain(
            path.join(__dirname, "..", "circuits", "jwt_proof.circom"),
            "JwtProof", [
                inCount, 
                subInB64.map(e => e[0].split('').map(c => c.charCodeAt())), 
                subInB64[0][0].length,
                subInB64.map(e => e[1])
            ]
        );

        const w = await cir.calculateWitness(inputs, true);
        await cir.checkConstraints(w);

        // Check the revealed JWT
        // assert.deepEqual(maskedContent.split('.').length, 2);
        // const header = Buffer.from(maskedContent.split('.')[0], 'base64').toString();
        // const claims = maskedContent.split('.')[1].split(/=+/).filter(e => e !== '').map(e => Buffer.from(e, 'base64').toString());
        // console.log("header", header, "\nclaims", claims);
        
        // assert.equal(claims.length, 2, "Incorrect number of claims");
        // assert.include(claims[0], '"iss":"https://accounts.google.com"', "Does not contain iss claim");
        // assert.include(claims[1], '"azp":"407408718192.apps.googleusercontent.com"', "Does not contain azp claim");
        // assert.include(claims[2], '"iat":1679674145', "Does not contain nonce claim");

        // Check signature
        const pubkey = await jose.importJWK(jwk);
        assert.isTrue(crypto.createVerify('RSA-SHA256')
                            .update(input)
                            .verify(pubkey, Buffer.from(signature, 'base64')),
                            "Signature does not correspond to hash");
    });
});
