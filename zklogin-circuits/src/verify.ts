import * as jwt from "jsonwebtoken";
import jwkToPem, { JWK } from "jwk-to-pem";
import * as jwtutils from './jwtutils';
import { toBigIntBE } from "bigint-buffer";
import { PartialAuxInputs } from "./common";

// JWT Token, JWK Public Key
const verifyJwt = (token: string, jwkPublicKey: JWK) => {
    try {
        // Convert the JWK to PEM format
        const publicKey = jwkToPem(jwkPublicKey);

        const verifyOptions: jwt.VerifyOptions = {
            algorithms: ["RS256"],
            ignoreExpiration: true
        };

        const decoded = jwt.verify(token, publicKey, verifyOptions);
        console.log("JWT is valid:", decoded);
    } catch (error) {
        console.error("Invalid JWT:", (error as Error).message);
    }
};

// A partial implementation of the on-chain proof verification logic. Only checks the masked_content.
const verifyAuxInputs = (auxiliary_inputs: PartialAuxInputs, MAX_JWT_LENGTH: number) => {
    checkMaskedContent(
        auxiliary_inputs["masked_content"],
        auxiliary_inputs["num_sha2_blocks"],
        auxiliary_inputs["payload_start_index"],
        auxiliary_inputs["payload_len"],
        MAX_JWT_LENGTH
    );
}

function checkMaskedContent (
    masked_content: number[], 
    num_sha2_blocks: number,
    expected_payload_start_index: number,
    expected_payload_len: number,
    expected_length: number
) {
    if (masked_content.length != expected_length) throw new Error("Invalid length");
    if (num_sha2_blocks * 64 > masked_content.length) throw new Error("Invalid last block");

    // Process any extra padding
    const extra_padding = masked_content.slice(num_sha2_blocks * 64);
    console.log("Length of extra padding:", extra_padding.length);
    if (extra_padding.length !== 0) {
        if (extra_padding.some(e => e != 0)) throw new Error("Invalid extra padding");
        masked_content = masked_content.slice(0, num_sha2_blocks * 64);
    }

    // Process header
    const header_length = masked_content.indexOf('.'.charCodeAt(0));
    if (header_length == -1 || header_length != expected_payload_start_index - 1) throw new Error("Invalid header length");

    const encodedHeader = masked_content.slice(0, header_length).map(e => String.fromCharCode(e)).join('');
    const header = Buffer.from(encodedHeader, 'base64url').toString('utf8');
    // console.log("header", header);
    // ...JSON Parse header...

    // Process SHA-2 padding
    const payload_and_sha2pad = masked_content.slice(header_length + 1);
    const header_and_payload_len_in_bits_bigint =  toBigIntBE(Buffer.from(payload_and_sha2pad.slice(-8)));
    if (header_and_payload_len_in_bits_bigint > Number.MAX_SAFE_INTEGER) { // 2^53 - 1
        throw new Error("Too large header_and_payload_len_in_bits");
    }
    // casting to a number should work for our use case as the numbers aren't big
    const header_and_payload_len_in_bits = Number(header_and_payload_len_in_bits_bigint);
    if (header_and_payload_len_in_bits % 8 != 0) throw new Error("Invalid header_and_payload_len_in_bits");
    const header_and_payload_len = header_and_payload_len_in_bits / 8;

    const payload_len = header_and_payload_len - expected_payload_start_index;
    if (payload_len != expected_payload_len) throw new Error(`Invalid payload length: ${payload_len} != ${expected_payload_len}`);

    const payload = payload_and_sha2pad.slice(0, payload_len);
    const sha2pad = payload_and_sha2pad.slice(payload_len);

    if (sha2pad[0] != 128) throw new Error("Invalid sha2pad start byte");
    if (sha2pad.slice(1, -8).some(e => e != 0)) throw new Error("Invalid sha2pad");
    // TODO: Check that the length of sha2pad.slice(1, -8) satisfies 4.1(b) from https://datatracker.ietf.org/doc/html/rfc4634#section-4.1

    // Process payload
    const maskedPayload = payload.map(e => String.fromCharCode(e)).join('');
    console.log("Masked payload:", maskedPayload);
    const claims = extractClaims(maskedPayload);
    console.log("Revealed claims:", claims);

    for (const claim of claims) {
        if (claim[0] !== '"') {
            // First character of each extracted_claim must be '"' (extractClaims omits partial bits at the start)
            console.log("Invalid claim", claim);
            throw new Error("Invalid claim");
        }

        if (!(claim.slice(-1) === '}' || claim.slice(-1) === ',')) {
            // Last character of each extracted_claim must be '}' or ','
            console.log("Invalid claim", claim);
            throw new Error("Invalid claim");
        }
    }
}

// Extracts the claims from the masked payload.
// 1. Extract continguous sets of non-masked characters
// 2. For each group of Base64 chars, find its starting index and prefix-pad with enough '0's before Base64 decoding.
function extractClaims(maskedPayload: string) {
    return maskedPayload.split(/=+/).filter(e => e !== '').map(
        e => {
            const pos = maskedPayload.indexOf(e);
            return jwtutils.decodeBase64URL(e, pos % 4);
        }
    );
}

export {
    verifyJwt, 
    verifyAuxInputs,
    extractClaims
};