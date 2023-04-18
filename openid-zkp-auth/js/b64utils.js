const utils = require('./utils.js');

// TODO: Write tests
function getBase64JSONSlice(input, field) {
    const decoded = Buffer.from(input, 'base64').toString();
    const kv_pair = utils.getClaimString(decoded, field);
    const fieldStart = decoded.indexOf(`"${field}"`);

    // take one char more on both sides
    const kv_pair_expanded = decoded.slice(fieldStart - 1, fieldStart + kv_pair.length + 1); 
    // console.log(kv_pair_expanded);
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

function findB64IndexOf(payload, claim) {
    const full_string = utils.getExtendedClaimString(payload, claim);

    const all_variants = getAllBase64Variants(full_string).map(e => e[0]);

    for (var i = 0; i < all_variants.length; i++) {
        const index = payload.indexOf(all_variants[i]);
        if (index != -1) {
            return index;
        }
    }

    console.log(full_string);
    console.log(all_variants);
    throw new Error("Claim not found");
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

/**
 * Takes an ASCII string as input and outputs the three possible Base64 variants in which it can appear in a JWT.
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

module.exports = {
    getBase64JSONSlice: getBase64JSONSlice,
    findB64IndexOf: findB64IndexOf,
    decodeMaskedB64: decodeMaskedB64,
    getAllBase64Variants: getAllBase64Variants
}
