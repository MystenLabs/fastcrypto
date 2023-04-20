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

describe("JWT Proof", function() {
    const inCount = 64 * 11; // This is the maximum length of a JWT

    const jwt = GOOGLE["jwt"];
    const jwk = GOOGLE["jwk"];

    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;
    const decoded_payload = Buffer.from(payload, 'base64').toString();

    const sub_claim = utils.getClaimString(decoded_payload, "sub");
    const sub_in_b64 = utils.removeDuplicates(b64utils.getAllExtendedBase64Variants(sub_claim));
    
    it("Google", async function() {
        var inputs = await circuit.genJwtProofInputs(input, inCount, ["iss", "aud", "nonce"], inWidth, outWidth);
        utils.writeJSONToFile(inputs, "inputs.json");

        const masked_content = utils.applyMask(inputs["content"], inputs["mask"]);
        checkMaskedContent(
            masked_content,
            inputs["num_sha2_blocks"],
            inputs["payload_start_index"],
            inputs["payload_len"],
            inCount
        );

        const cir = await test.genMain(
            path.join(__dirname, "..", "circuits", "jwt_proof.circom"),
            "JwtProof", [
                inCount, 
                sub_in_b64.map(e => e[0].split('').map(c => c.charCodeAt())),
                sub_in_b64.length, 
                sub_in_b64[0][0].length,
                sub_in_b64.map(e => e[1])
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
