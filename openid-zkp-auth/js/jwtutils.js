/**
 * Returns a claim as it appears in the decoded JWT.
 * We take a conservative approach, e.g., assume that the claim value does not have spaces. 
 * In such cases, the code will fail.
 * The last character after the claim value is also returned (either a comma or a closing brace).
 * 
 * @param {*} decoded_payload e.g., {"sub":"1234567890","name":"John Doe","iat":1516239022} 
 * @param {*} claim e.g., sub
 * @returns e.g., "sub":"1234567890",
 */
function getClaimString(decoded_payload, claim) {
    const json_input = JSON.parse(decoded_payload);
    if (!json_input.hasOwnProperty(claim)) {
        throw new Error("Field " + claim + " not found in " + decoded_payload);
    }

    const field_value = JSON.stringify(json_input[claim]);
    const kv_pair = `"${claim}":${field_value}`;
    const claimStart = decoded_payload.indexOf(`"${claim}"`);
    const kv_pair_expanded = kv_pair + decoded_payload[claimStart + kv_pair.length];

    if (decoded_payload.includes(kv_pair_expanded)) {
        var lastchar = kv_pair_expanded[kv_pair_expanded.length - 1];
        if (!(lastchar == '}' || lastchar == ',')) {
            throw new Error("Something is wrong with the decoded payload");
        }
        return kv_pair_expanded;
    }

    // Facebook is escaping the '/' characters in the JWT payload
    const escaped_field_value = field_value.replace(/([/])/g, '\\$1');
    const escaped_kv_pair = `"${claim}":${escaped_field_value}`;
    const escaped_kv_pair_expanded = escaped_kv_pair + 
        decoded_payload[claimStart + escaped_kv_pair.length];
    
    if (decoded_payload.includes(escaped_kv_pair_expanded)) {
        var lastchar = escaped_kv_pair_expanded[escaped_kv_pair_expanded.length - 1];
        if (!(lastchar == '}' || lastchar == ',')) {
            throw new Error("Something is wrong with the decoded payload");
        }

        return escaped_kv_pair_expanded;
    }

    throw new Error("Fields " + kv_pair_expanded + " or " + escaped_kv_pair_expanded + " not found in " + decoded_payload);
}

/**
 * @param {String} payload  A Base64 encoded string, e.g., a JWT
 * @param {String} field    A claim string, e.g., "sub" (without quotes)
 * @returns [start, length] The start index and length of the (base64) encoded 
 *                          claim string in the input. 
 * 
 * The returned indices are tight, i.e., both payload[start] and payload[start + length - 1] 
 *  contain at least some bits of the claim string.
 */
function indicesOfB64(payload, field) {
    const decoded = Buffer.from(payload, 'base64url').toString();
    
    const kv_pair = getClaimString(decoded, field);
    const start_index_ascii = decoded.indexOf(kv_pair);
    const length_b64 = b64Len(kv_pair.length, start_index_ascii);
    const start_b64 = b64Index(start_index_ascii);

    // test
    const expectedB64Variant = payload.slice(start_b64, start_b64 + length_b64);
    if (payload.indexOf(expectedB64Variant) == -1) {
        throw new Error("Field " + kv_pair + " not found in the Base64");
    }

    return [start_b64, length_b64];
}

// If a character appears at an index i in a string S, 
//  return the index at which it would appear in the base64 representation of S
function b64Index(i) {
    var q = 4 * Math.floor(i / 3);

    if (i % 3 == 0) {
        /**
         * - - - - <=> . . .
         * - - - - <=> . . .
         * X x     <=> i  
         */
        return q;
    } else if (i % 3 == 1) {
        /**
         * - - - - <=> . . .
         * - - - - <=> . . .
         * _ X x   <=> . i  
         */
        return q + 1;
    } else if (i % 3 == 2) {
        /**
         * - - - - <=> . . .
         * - - - - <=> . . .
         * _ _ X x <=> . . i  
         */
        return q + 2;
    } else {
        throw new Error("Something is wrong with the index", i);
    }
}

// Given an ascii string of length n starting at index i, 
//  return the length of its base64 representation
function b64Len(n, i) {
    var q = 4 * Math.floor(n / 3);
    if (i % 3 == 0) {
        if (n % 3 == 0) {
            /**
             * a - - => 4
             * - - b => 4
             */
            return q;
        } else if (n % 3 == 1) {
            /**
             * a - - => 4
             * - - - => 4
             * b     => 2
             */
            return q + 2;
        } else {
            /**
             * a - - => 4
             * - - - => 4
             * - b   => 3
             */
            return q + 3;
        }
    } else if (i % 3 == 1) {
        if (n % 3 == 0) {
            /**
             *   a - => 3
             * - - - => 4
             * b     => 2
             */
            return q + 1;
        } else if (n % 3 == 1) {
            /**
             *   a - => 3
             * - - - => 4
             * - b   => 3
             */
            return q + 2;
        } else {
            /**
             *   a - => 3
             * - - - => 4
             * - - b => 4
             */
            return q + 3;
        }
    } else if (i % 3 == 2) {
        if (n % 3 == 0) {
            /**
             *     a => 2
             * - - - => 4
             * - b   => 3
             */
            return q + 1;
        } else if (n % 3 == 1) {
            /**
             *     a => 2
             * - - - => 4
             * - - b => 4
             */
            return q + 2;
        } else {
            /**
             *     a => 2
             * - - - => 4
             * - - - => 4
             * b     => 2
             */
            return q + 4;
        }
    } else {
        throw new Error("Something is wrong with the index", i);
    }
}

function base64UrlCharTo6Bits(base64UrlChar) {
    if (base64UrlChar.length !== 1) {
        throw new Error('Invalid base64Url character: ' + base64UrlChar);
    }

    // Define the base64URL character set
    const base64UrlCharacterSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  
    // Find the index of the input character in the base64URL character set
    const index = base64UrlCharacterSet.indexOf(base64UrlChar);

    if (index === -1) {
        throw new Error('Invalid base64Url character: ' + base64UrlChar);
    }
  
    // Convert the index to a 6-bit binary string
    const binaryString = index.toString(2).padStart(6, '0');
  
    // Convert the binary string to an array of bits
    const bits = Array.from(binaryString).map(Number);
  
    return bits;
}

function base64UrlStringToBitVector(base64UrlString) {
    let bitVector = [];
    for (let i = 0; i < base64UrlString.length; i++) {
        const base64UrlChar = base64UrlString.charAt(i);
        const bits = base64UrlCharTo6Bits(base64UrlChar);
        bitVector = bitVector.concat(bits);
    }
    return bitVector;
}
  
/**
 * Decode a Base64URL substring `s` that appears at index `i` of a valid Base64URL string.
 *
 * @param {string} s - a Base64URL substring
 * @param {number} i - the index at which `s` appears in the Base64URL string
 * @returns {string} the decoded string
 *  
 * Like before, we assume tight packing, i.e., both s[i] and s[i + s.length - 1] carry 
 *  non-zero bits of the encoded string.
 */
function decodeBase64URL(s, i) {
    if (s.length < 2) {
        throw new Error(`Input (s = ${s}) is not tightly packed because s.length < 2`);
    }
    var bits = base64UrlStringToBitVector(s);

    const first_char_offset = i % 4;
    if (first_char_offset == 0) {
        // skip
    } else if (first_char_offset == 1) {
        bits = bits.slice(2);
    } else if (first_char_offset == 2) {
        bits = bits.slice(4);
    } else { // (offset == 3)
        throw new Error(`Input (s = ${s}) is not tightly packed because i%4 = 3 (i = ${i}))`);
    }

    const last_char_offset = (i + s.length - 1) % 4;
    if (last_char_offset == 3) {
        // skip
    } else if (last_char_offset == 2) {
        bits = bits.slice(0, bits.length - 2);
    } else if (last_char_offset == 1) {
        bits = bits.slice(0, bits.length - 4);
    } else { // (offset == 0)
        throw new Error(`Input (s = ${s}) is not tightly packed because (i + s.length - 1)%4 = 0 (i = ${i}))`);
    }

    if (bits.length % 8 != 0) {
        throw new Error(`We should never reach here...`);
    }

    var bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
        const bitChunk = bits.slice(i, i + 8);
    
        // Convert the 8-bit chunk to a byte and add it to the bytes array
        const byte = parseInt(bitChunk.join(''), 2);
        bytes.push(byte);
    }
    
    return Buffer.from(bytes).toString();
}

module.exports = {
    getClaimString: getClaimString,
    indicesOfB64: indicesOfB64,
    b64Len: b64Len,
    decodeBase64URL: decodeBase64URL,
    base64UrlCharTo6Bits: base64UrlCharTo6Bits
}