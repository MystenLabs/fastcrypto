const utils = require('./utils.js');

/**
 * Takes an ASCII string as input and outputs the three possible Base64 variants in which it can appear in a JWT.
 * The output is guaranteed to capture all characters except the first and last precisely.
 * 
 * @param {*} string The ASCII string
 * @returns arr[3][2] 
 *      If i is the index at which "string" appears in the decoded JWT, then b64string = arr[i%3][0] will be a substring of the JWT.
 *      And let j be the index at which b64string appears in the JWT, then arr[i%3][1] = j%4.
 */
function getAllBase64Variants(string) {
    var offset0, offset1, offset2, expected_len;
    var expected_offset0, expected_offset1, expected_offset2;
    if (string.length % 3 == 0) {
        offset0 = Buffer.from(string).toString('base64').slice(1, -1);
        expected_offset0 = 1;
        offset1 = Buffer.from('0' + string).toString('base64').slice(2, -4);
        expected_offset1 = 2;
        offset2 = Buffer.from('00' + string).toString('base64').slice(4, -2);
        expected_offset2 = 0;
        expected_len = ((string.length / 3) * 4) - 2;
    } else if (string.length % 3 == 1) {
        offset0 = Buffer.from(string).toString('base64').slice(0, -4);
        expected_offset0 = 0;
        offset1 = Buffer.from('0' + string).toString('base64').slice(2, -2);
        expected_offset1 = 2;
        offset2 = Buffer.from('00' + string).toString('base64').slice(4);
        expected_offset2 = 0;
        expected_len = (((string.length - 1) / 3) * 4);
    } else { //  (string.length % 3 == 2)
        offset0 = Buffer.from(string).toString('base64').slice(0, -2);
        expected_offset0 = 0;
        offset1 = Buffer.from('0' + string).toString('base64').slice(2);
        expected_offset1 = 2;
        offset2 = Buffer.from('00' + string).toString('base64').slice(3, -3);
        expected_offset2 = 3;
        expected_len = (((string.length - 2) / 3) * 4) + 2;
    }
    if (offset0.length != expected_len || offset1.length != expected_len || offset2.length != expected_len) throw new Error("Something went wrong");
    return [[offset0, expected_offset0],
            [offset1, expected_offset1],
            [offset2, expected_offset2]];
}

// Given a claim string, returns all possible Base64 variants in which it can appear in a JWT.
// In particular, we don't assume the position of the claim in the JWT.
function getAllExtendedBase64Variants(claim_string, payload = "") {
    const extended_string_1 = ',' + claim_string + ',';
    const extended_string_2 = ',' + claim_string + '}';
    const extended_string_3 = '{' + claim_string + ',';
    if (payload != "" && ![extended_string_1, extended_string_2, extended_string_3].some(e => payload.indexOf(e) == -1)) {
        throw new Error(extended_string, "is not in", decoded);
    }
    const variants_1 = getAllBase64Variants(extended_string_1);
    const variants_2 = getAllBase64Variants(extended_string_2);
    // extended_string_3 can only appear at the start of the payload, i.e., idx % 3 = 0
    const variants_3 = [getAllBase64Variants(extended_string_3)[0]];

    const final_variants = variants_1.concat(variants_2).concat(variants_3);
    return final_variants;
}

/**
 * @param {String} input A Base64 encoded string, e.g., a JWT
 * @param {String} field A claim string, e.g., "sub" (without quotes)
 * @returns [start, end] The start and end indexes of the (base64) encoded claim string in the input.
 */
function indicesOfB64(input, field) {
    const decoded = Buffer.from(input, 'base64').toString();
    const kv_pair = utils.getClaimString(decoded, field);
    const fieldStart = decoded.indexOf(`"${field}"`);

    // take one char more on both sides
    const kv_pair_expanded = decoded.slice(fieldStart - 1, fieldStart + kv_pair.length + 1);
    const b64Variants = getAllBase64Variants(kv_pair_expanded);
    const x = (fieldStart - 1) % 3;
    const expectedB64Variant = b64Variants[x][0];
    if (input.indexOf(expectedB64Variant) == -1) {
        console.log("Index:", x);
        console.log(expectedB64Variant);
        throw new Error("Field " + kv_pair + " not found in the Base64");
    }

    const start = input.indexOf(expectedB64Variant);
    return [start, start + expectedB64Variant.length - 1];
}

// Decode a Base64 string with some initial portions masked.
function decodeMaskedB64(input, offset) {
    if (offset > 3 || offset < 0) throw new Error("Invalid offset");

    var extraPrefix = '0'.repeat(offset);
    const decoded = Buffer.from(extraPrefix + input, 'base64').toString('utf8');
    return decoded.slice(offset);
    // Remove all characters corresponding to the added prefix before sending.
    // Due to the nature of Base64 encoding, the above action will also remove the first character of the decoded string in some cases.
    // If the mask was set using getAllBase64Variants, then this action will never omit an important character.
}

module.exports = {
    indicesOfB64: indicesOfB64,
    decodeMaskedB64: decodeMaskedB64,
    getAllBase64Variants: getAllBase64Variants,
    getAllExtendedBase64Variants: getAllExtendedBase64Variants
}
