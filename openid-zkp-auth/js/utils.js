const PADDING_CHAR = '=';

function arrayChunk(array, chunk_size) {
    return Array(Math.ceil(array.length / chunk_size)).fill().map((_, index) => index * chunk_size).map(begin => array.slice(begin, begin + chunk_size));
}

function trimEndByChar(string, character) {
  const arr = Array.from(string);
  const last = arr.reverse().findIndex(char => char !== character);
  return string.substring(0, string.length - last);
}

function getJSONFieldLength(input, field) {
    const json_input = JSON.parse(input);
    const matching_fields = input.match(new RegExp(`"${field}"\\:\\s*`));
    if (matching_fields == undefined) throw new Error("Field " + field + " not found in JSON");
    const fieldNameLength = matching_fields[0].length;
    const fieldValueLength = JSON.stringify(json_input[field]).length;
    
    return fieldNameLength + fieldValueLength;
}

function getBase64JSONSlice(input, field) {
    const decoded = Buffer.from(input, 'base64').toString();
    const fieldStart = decoded.indexOf(`"${field}"`);
    const lead = trimEndByChar(Buffer.from(decoded.slice(0, fieldStart)).toString('base64'), '=');
    const fieldLength = getJSONFieldLength(decoded, field);
    const target = trimEndByChar(Buffer.from(decoded.slice(fieldStart, fieldStart + fieldLength)).toString('base64'), '=');
    
    const start = Math.floor(lead.length / 4) * 4;
    const end = Math.ceil(((lead.length + target.length) - 1) / 4) * 4;

    // var start = lead.length;
    // var startOffset = 0;
    // if (lead.length % 4 !== 0) {
    //     if (lead.length % 4 == 1) throw new Error("Invalid base64 string");
    //     start--; // one more base64 char needs to be revealed
    //     if (lead.length % 4 == 2) { // '==' to be added for proper padding 
    //         startOffset = 1;
    //     } else { // (lead.length % 4 == 3) '=' needs to be added for proper padding
    //         startOffset = 2; // two base64 chars need to be added at the start
    //     }
    // }
    
    return [start, end >= input.length ? input.length - 1 : end - 1];
    // return [start, end >= input.length ? input.length - 1 : end - 1, startOffset];
}

function findB64IndexOf(payload, claim) {
    const full_string = getExtendedClaim(payload, claim);

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

function buffer2BitArray(b) {
    return [].concat(...Array.from(b.entries()).map(([index, byte]) => byte.toString(2).padStart(8, '0').split('').map(bit => bit == '1' ? 1 : 0) ))
}

function bitArray2Buffer(a) {
    return Buffer.from(arrayChunk(a, 8).map(byte => parseInt(byte.join(''), 2)))
}

function bigIntArray2Bits(arr, intSize=16) {
    return [].concat(...arr.map(n => n.toString(2).padStart(intSize, '0').split(''))).map(bit => bit == '1' ? 1 : 0);
}

function bigIntArray2Buffer(arr, intSize=16) {
    return bitArray2Buffer(bigIntArray2Bits(arr, intSize));
}

function getWitnessValue(witness, symbols, varName) {
    return witness[symbols[varName]['varIdx']];
}

function getWitnessMap(witness, symbols, arrName) {
    return Object.entries(symbols).filter(([index, symbol]) => index.startsWith(arrName)).map(([index, symbol]) => Object.assign({}, symbol, { "name": index, "value": witness[symbol['varIdx']] }) );
}

function getWitnessArray(witness, symbols, arrName) {
    return Object.entries(symbols).filter(([index, symbol]) => index.startsWith(`${arrName}[`)).map(([index, symbol]) => witness[symbol['varIdx']] );
}

function getWitnessBuffer(witness, symbols, arrName, varSize=1) {
    const witnessArray = getWitnessArray(witness, symbols, arrName);
    if(varSize == 1) {
        return bitArray2Buffer(witnessArray);
    } else {
        return bigIntArray2Buffer(witnessArray, varSize);
    }
}

// Assuming that the claim isn't the first or last, we look for an extended string of the form `,"claim":"value",`
function getExtendedClaim(payload, claim) {
    const decoded = Buffer.from(payload, 'base64').toString();
    const json_input = JSON.parse(decoded);
    const extended_string = `,"${claim}":"` + json_input[claim] + '",';
    if (decoded.indexOf(extended_string) == -1) {
        console.log(decoded, extended_string);
        throw new Error(extended_string, "is not in", decoded);
    }
    return extended_string;
}

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

function writeJSONToFile(inputs, file_name = "inputs.json") {
    const fs = require('fs');
    fs.writeFileSync(file_name, JSON.stringify(inputs, null, 2));
}

function calculateNonce(inputs, poseidon) {
    return poseidon.F.toObject(poseidon([
        inputs["eph_public_key"][0], 
        inputs["eph_public_key"][1], 
        inputs["max_epoch"],
        inputs["randomness"]
    ]));
}

function calculateMaskedHash(content, mask, poseidon, outWidth) {
    const masked_content = applyMask(content, mask);
    const bits = bigIntArray2Bits(masked_content, 8);

    const extra_bits = (bits.length % outWidth == 0) ? 0 : outWidth - (bits.length % outWidth);
    const bits_padded = bits.concat(Array(extra_bits).fill(0));
    if (bits_padded.length % outWidth != 0) throw new Error("Invalid logic");

    const packed = arrayChunk(bits_padded, outWidth).map(chunk => BigInt("0b" + chunk.join('')));
    return poseidonHash(packed, poseidon);
}

function poseidonHash(inputs, poseidon) {
    if (inputs.length < 1) {
        return poseidon.F.toObject(poseidon([inputs]))
    } else if (inputs.length <= 15) {
        return poseidon.F.toObject(poseidon(inputs))
    } else if (inputs.length <= 30) {
        const hash1 = poseidon(inputs.slice(0, 15));
        const hash2 = poseidon(inputs.slice(15));
        return poseidon.F.toObject(poseidon([hash1, hash2]));
    } else {
        throw new Error("Yet to implement multiple rounds of poseidon");
    }
}

/**
 * @param {Array} input 
 * @param {Array} mask 
 * @returns A string of characters where the masked characters are replaced with '='
 */
function applyMask(input, mask) {
    if (input.length != mask.length) {
        throw new Error("Input and mask must be of the same length");
    }
    return input.map((charCode, index) => (mask[index] == 1) 
                ? Number(charCode)
                : PADDING_CHAR.charCodeAt()
            );
}

function fromBase64WithOffset(input, offset) {
    var extraPrefix = '='.repeat(offset);
    return Buffer.from(extraPrefix + input, 'base64').toString('utf8');
}

function checkMaskedContent(masked_content, last_block, expected_length) {
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

    // Process payload
    const encodedPayload = payload.map(e => String.fromCharCode(e)).join('');
    console.log("encoded payload", encodedPayload);
    const claims = encodedPayload.split(/=+/).filter(e => e !== '').map(e => Buffer.from(e, 'base64').toString());
    console.log("claims", claims);
    // ...JSON Parse claims...

    // TODO: Careful decoding to be implemented once proper masking is done
}

module.exports = {
    arrayChunk: arrayChunk,
    trimEndByChar: trimEndByChar,
    getJSONFieldLength: getJSONFieldLength,
    getBase64JSONSlice: getBase64JSONSlice,
    buffer2BitArray: buffer2BitArray,
    bitArray2Buffer: bitArray2Buffer,
    bigIntArray2Bits: bigIntArray2Bits,
    bigIntArray2Buffer: bigIntArray2Buffer,
    getWitnessValue: getWitnessValue,
    getWitnessMap: getWitnessMap,
    getWitnessArray: getWitnessArray,
    getWitnessBuffer: getWitnessBuffer,
    getAllBase64Variants: getAllBase64Variants,
    writeJSONToFile: writeJSONToFile,
    calculateNonce: calculateNonce,
    fromBase64WithOffset: fromBase64WithOffset,
    calculateMaskedHash: calculateMaskedHash,
    findB64IndexOf: findB64IndexOf,
    getExtendedClaim: getExtendedClaim,
    applyMask: applyMask,
    checkMaskedContent: checkMaskedContent,
    poseidonHash: poseidonHash,
}
