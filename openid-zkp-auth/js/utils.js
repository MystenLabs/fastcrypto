function arrayChunk(array, chunk_size) {
    return Array(Math.ceil(array.length / chunk_size)).fill().map((_, index) => index * chunk_size).
                map(begin => array.slice(begin, begin + chunk_size));
}

function trimEndByChar(string, character) {
  const arr = Array.from(string);
  const last = arr.reverse().findIndex(char => char !== character);
  return string.substring(0, string.length - last);
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

function writeJSONToFile(inputs, file_name = "inputs.json") {
    const fs = require('fs');
    fs.writeFileSync(file_name, JSON.stringify(inputs, null, 2));
}

function removeDuplicates(twod_array) {
    return twod_array.filter((item, index) => {
        return index === twod_array.findIndex((subItem) => {
            return subItem.every((value, i) => value === item[i]);
        });
    });
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
 * @param {Array} input: vector of bytes
 * @param {Array} mask: vector of 0s and 1s 
 * @returns A vector of characters where the masked characters are replaced with '='
 */
function applyMask(input, mask) {
    if (input.length != mask.length) {
        throw new Error("Input and mask must be of the same length");
    }
    return input.map((charCode, index) => (mask[index] == 1) 
                ? Number(charCode)
                : require('./constants').maskValue
            );
}

// Returns a claim as it appears in the decoded JWT
function getClaimString(decoded_payload, claim) {
    const json_input = JSON.parse(decoded_payload);
    const field_value = JSON.stringify(json_input[claim]);
    const kv_pair = `"${claim}":${field_value}`;

    if (decoded_payload.indexOf(kv_pair) == -1) 
        throw new Error("Field " + kv_pair + " not found in JWT");

    return kv_pair;
}

module.exports = {
    arrayChunk: arrayChunk,
    trimEndByChar: trimEndByChar,
    buffer2BitArray: buffer2BitArray,
    bitArray2Buffer: bitArray2Buffer,
    bigIntArray2Bits: bigIntArray2Bits,
    bigIntArray2Buffer: bigIntArray2Buffer,
    getWitnessValue: getWitnessValue,
    getWitnessMap: getWitnessMap,
    getWitnessArray: getWitnessArray,
    getWitnessBuffer: getWitnessBuffer,
    writeJSONToFile: writeJSONToFile,
    getClaimString: getClaimString,
    applyMask: applyMask,
    removeDuplicates: removeDuplicates,
    // hashing
    calculateMaskedHash: calculateMaskedHash,
    poseidonHash: poseidonHash
}
