const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const crypto = require("crypto");
const jose = require("jose");

const circuit = require("../js/circuit");
const utils = require("../js/utils");
const b64utils = require("../js/b64utils");
const test = require("../js/test");
const GOOGLE = require("../js/testvectors").google_extension;
const checkMaskedContent = require("../js/verify").checkMaskedContent;

const inWidth = "../js/constants".inWidth;
const outWidth = "../js/constants".outWidth;

describe("JWT Proof", () => {
    const inCount = 64 * 11; // This is the maximum length of a JWT

    const jwt = GOOGLE["jwt"];
    const jwk = GOOGLE["jwk"];

    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;

    const subClaim = utils.getExtendedClaimString(payload, "sub");
    const subInB64 = b64utils.getAllBase64Variants(subClaim);
    
    it("sub claim finding", () => {
        const decoded_jwt = Buffer.from(payload, 'base64').toString();
        const subClaimIndex = decoded_jwt.indexOf(subClaim);

        const subClaiminB64Options = b64utils.getAllBase64Variants(subClaim);
        const subClaimIndexInJWT = jwt.indexOf(subClaiminB64Options[subClaimIndex % 3][0]);
        assert.isTrue(subClaimIndexInJWT !== -1);
    });

    it("Extract from Base64 JSON", async () => {
        var inputs = await circuit.genJwtProofInputs(input, inCount, ["iss", "aud", "nonce"], inWidth, outWidth);
        utils.writeJSONToFile(inputs, "inputs.json");

        const masked_content = utils.applyMask(inputs["content"], inputs["mask"]);
        checkMaskedContent(masked_content, inputs["num_sha2_blocks"], inCount);

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

        // Check signature
        const pubkey = await jose.importJWK(jwk);
        assert.isTrue(crypto.createVerify('RSA-SHA256')
                            .update(input)
                            .verify(pubkey, Buffer.from(signature, 'base64')),
                            "Signature does not correspond to hash");
    });
});
