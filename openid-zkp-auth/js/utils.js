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
    return b.reduce((bitArray, byte) => {
        const binaryString = byte.toString(2).padStart(8, '0');
        const bitValues = binaryString.split('').map(bit => bit === '1' ? 1 : 0);
        return bitArray.concat(bitValues);
    }, []);
}

function bitArray2Buffer(a) {
    return Buffer.from(arrayChunk(a, 8).map(byte => parseInt(byte.join(''), 2)))
}

function bigIntArray2Bits(arr, intSize = 16) {
    return arr.reduce((bitArray, n) => {
        const binaryString = n.toString(2).padStart(intSize, '0');
        const bitValues = binaryString.split('').map(bit => bit === '1' ? 1 : 0);
        return bitArray.concat(bitValues);
    }, []);
}

function bigIntArray2Buffer(arr, intSize=16) {
    return bitArray2Buffer(bigIntArray2Bits(arr, intSize));
}

function pack(inArr, inWidth, outWidth) {
    const bits = bigIntArray2Bits(inArr, inWidth);

    const extra_bits = bits.length % outWidth == 0 ? 0 : outWidth - (bits.length % outWidth);
    const bits_padded = bits.concat(Array(extra_bits).fill(0));
    if (bits_padded.length % outWidth != 0) throw new Error("Invalid logic");

    const packed = arrayChunk(bits_padded, outWidth).map(chunk => BigInt("0b" + chunk.join('')));
    return packed;
}

function padWithZeroes(inArr, outCount) {
    const extra_bits = outCount - inArr.length;
    const bits_padded = inArr.concat(Array(extra_bits).fill(0));
    return bits_padded;
}

function poseidonHash(inputs, poseidon) {
    if (inputs.length == 1) {
        return poseidon.F.toObject(poseidon([inputs]))
    } else if (inputs.length <= 15) {
        return poseidon.F.toObject(poseidon(inputs))
    } else if (inputs.length <= 30) {
        const hash1 = poseidon(inputs.slice(0, 15));
        const hash2 = poseidon(inputs.slice(15));
        return poseidon.F.toObject(poseidon([hash1, hash2]));
    } else {
        throw new Error(`Yet to implement: Unable to hash a vector of length ${inputs.length}`);
    }
}

function applyMask(input, mask) {
    if (input.length != mask.length) {
        throw new Error("Input and mask must be of the same length");
    }
    return input.map((charCode, index) => (mask[index] == 1) 
                ? Number(charCode)
                : require('./constants').maskValue
            );
}

async function commitSubID(claim_string, pin, maxSubLength, outWidth=253) {
    const buildPoseidon = require("circomlibjs").buildPoseidon;
    poseidon = await buildPoseidon();

    const padded_claim_string = padWithZeroes(claim_string.split('').map(c => c.charCodeAt()), maxSubLength);
    const packed_subject_id = pack(padded_claim_string, 8, outWidth);
    return poseidonHash([
        poseidonHash(packed_subject_id, poseidon),
        pin
    ], poseidon);
}

function writeJSONToFile(inputs, file_name = "inputs.json") {
    const fs = require('fs');
    fs.writeFileSync(file_name, JSON.stringify(inputs, null, 2));
}

module.exports = {
    arrayChunk: arrayChunk,
    trimEndByChar: trimEndByChar,
    buffer2BitArray: buffer2BitArray,
    bitArray2Buffer: bitArray2Buffer,
    bigIntArray2Bits: bigIntArray2Bits,
    bigIntArray2Buffer: bigIntArray2Buffer,
    applyMask: applyMask,
    padWithZeroes: padWithZeroes,
    pack: pack,
    commitSubID: commitSubID,
    poseidonHash: poseidonHash,
    writeJSONToFile: writeJSONToFile
}
