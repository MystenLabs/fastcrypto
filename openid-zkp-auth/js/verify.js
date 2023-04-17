// jwtVerifierRS256JWK.js
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

// JWT Token, JWK Public Key
const verifyJwt = (token, jwkPublicKey) => {
  try {
    // Convert the JWK to PEM format
    const publicKey = jwkToPem(jwkPublicKey);

    const verifyOptions = {
        algorithms: ["RS256"],
        ignoreExpiration: true
    };
  
    const decoded = jwt.verify(token, publicKey, verifyOptions);
    console.log("JWT is valid:", decoded);
  } catch (error) {
    console.error("Invalid JWT:", error.message);
  }
};

const checkMaskedContent = (masked_content, last_block, expected_length) => {
    if (masked_content.length != expected_length) throw new Error("Invalid length");
    if (last_block * 64 > masked_content.length) throw new Error("Invalid last block");

    // Process any extra padding
    extra_padding = masked_content.slice(last_block * 64);
    console.log("Length of extra padding:", extra_padding.length);
    if (extra_padding != '') {
        if (extra_padding.some(e => e != 0)) throw new Error("Invalid extra padding");
        masked_content = masked_content.slice(0, last_block * 64);
    }

    // Process header
    const header_length = masked_content.indexOf('.'.charCodeAt());
    if (header_length == -1) throw new Error("Invalid header length");

    const encodedHeader = masked_content.slice(0, header_length).map(e => String.fromCharCode(e)).join('');
    const header = Buffer.from(encodedHeader, 'base64').toString('utf8');
    console.log("header", header);
    // ...JSON Parse header...

    // Process SHA-2 padding
    const payload_and_sha2pad = masked_content.slice(header_length + 1);
    const header_and_payload_len_in_bits = Number('0x' + payload_and_sha2pad.slice(-8).map(e => e.toString(16)).join(''));
    if (header_and_payload_len_in_bits % 8 != 0) throw new Error("Invalid header_and_payload_len_in_bits");
    const header_and_payload_len = header_and_payload_len_in_bits / 8;

    const payload_len = header_and_payload_len - header_length - 1;
    const payload = payload_and_sha2pad.slice(0, payload_len);
    const sha2pad = payload_and_sha2pad.slice(payload_len);

    if (sha2pad[0] != 128) throw new Error("Invalid sha2pad start byte");
    if (sha2pad.slice(1, -8).some(e => e != 0)) throw new Error("Invalid sha2pad");
    // TODO: Check that the length of sha2pad.slice(1, -8) satisfies 4.1(b) from https://datatracker.ietf.org/doc/html/rfc4634#section-4.1

    // Process payload
    const maskedPayload = payload.map(e => String.fromCharCode(e)).join('');
    console.log("encoded payload", maskedPayload);
    const claims = extractClaims(maskedPayload);
    console.log("claims", claims);
}

const b64utils = require("./b64utils");
// Extracts the claims from the masked payload.
// 1. Extract continguous sets of non-masked characters
// 2. For each group of Base64 chars, find its starting index and prefix-pad with enough '0's before Base64 decoding.
const extractClaims = (maskedPayload) => {
    return maskedPayload.split(/=+/).filter(e => e !== '').map(
        e => {
            const pos = maskedPayload.indexOf(e);
            return b64utils.decodeMaskedB64(e, pos % 4);
        }
    );
}

module.exports = {
  verifyJwt, 
  checkMaskedContent, 
  extractClaims
};
