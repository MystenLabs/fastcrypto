const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const crypto = require("crypto");
const jose = require("jose");

const circuit = require("../js/circuit");
const utils = require("../js/utils");
const b64utils = require("../js/b64utils");
const test = require("../js/test");
const GOOGLE = require("../js/testvectors").google;
const FB = require("../js/testvectors").facebook;
const checkMaskedContent = require("../js/verify").checkMaskedContent;

const inWidth = "../js/constants".inWidth;
const outWidth = "../js/constants".outWidth;

genJwtProof = (async (jwt, jwk, inCount, claimsToReveal) => {
    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;
    var inputs = await circuit.genJwtProofInputs(input, inCount, claimsToReveal, inWidth, outWidth);
    // utils.writeJSONToFile(inputs, "inputs.json");

    const masked_content = utils.applyMask(inputs["content"], inputs["mask"]);
    checkMaskedContent(
        masked_content,
        inputs["num_sha2_blocks"],
        inputs["payload_start_index"],
        inputs["payload_len"],
        inCount
    );

    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const sub_claim = utils.getClaimString(decoded_payload, "sub");
    const sub_in_b64 = utils.removeDuplicates(b64utils.getAllExtendedBase64Variants(sub_claim));

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
                        .verify(pubkey, Buffer.from(signature, 'base64url')),
                        "Signature does not correspond to hash");
})

describe("JWT Proof", function() {
    it("Google", async function() {
        await genJwtProof(GOOGLE["jwt"], GOOGLE["jwk"], 64 * 12, ["iss", "aud", "nonce"]);
    });

    // TODO: To be updated after pairwise IDs are supported
    it("Facebook", async function() {
        await genJwtProof(FB["jwt"], FB["jwk"], 64 * 14, ["iss", "aud", "nonce"]);
    });
});
