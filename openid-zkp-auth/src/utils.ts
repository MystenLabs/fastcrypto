import { constants, bit } from './common';
import * as fs from 'fs';

function getNumFieldElements(asciiSize: number, packWidth=constants.packWidth): number {
    if (packWidth % 8 !== 0) throw new Error("packWidth must be a multiple of 8");

    const packWidthInBytes = packWidth / 8;
    return Math.ceil(asciiSize / packWidthInBytes);
}

function arrayChunk<T>(array: T[], chunk_size: number): T[][] {
    return Array(Math.ceil(array.length / chunk_size)).fill(undefined).map((_, index) => index * chunk_size).
                map(begin => array.slice(begin, begin + chunk_size));
}

function trimEndByChar(string: string, character: string) {
    if (character.length !== 1) throw new Error("character must be a single character");

    const arr = Array.from(string);
    const last = arr.reverse().findIndex(char => char !== character);
    return string.substring(0, string.length - last);
}

function buffer2BitArray(b: Buffer): bit[] {
    return b.reduce((bitArray: bit[], byte) => {
        const binaryString = byte.toString(2).padStart(8, '0');
        const bitValues = binaryString.split('').map(bit => bit === '1' ? 1 : 0);
        return bitArray.concat(bitValues);
    }, []);
}

function bitArray2Buffer(a: bit[]): Buffer {
    return Buffer.from(arrayChunk(a, 8).map(byte => parseInt(byte.join(''), 2)))
}

function bigIntArray2Bits(arr: bigint[], intSize = 16): bit[] {
    return arr.reduce((bitArray: bit[], n) => {
        const binaryString = n.toString(2).padStart(intSize, '0');
        const bitValues = binaryString.split('').map(bit => bit === '1' ? 1 : 0);
        return bitArray.concat(bitValues);
    }, []);
}

function bigIntArray2Buffer(arr: bigint[], intSize=16): Buffer {
    return bitArray2Buffer(bigIntArray2Bits(arr, intSize));
}

// Pack into an array of chunks each outWidth bits
function pack(inArr: bigint[], inWidth: number, outWidth: number): bigint[] {
    const bits = bigIntArray2Bits(inArr, inWidth);

    const extra_bits = bits.length % outWidth == 0 ? 0 : outWidth - (bits.length % outWidth);
    const bits_padded = bits.concat(Array(extra_bits).fill(0));
    if (bits_padded.length % outWidth != 0) throw new Error("Invalid logic");

    const packed = arrayChunk(bits_padded, outWidth).map(chunk => BigInt("0b" + chunk.join('')));
    return packed;
}

// Pack into exactly outCount chunks of outWidth bits each
function pack2(inArr: bigint[], inWidth: number, outWidth: number, outCount: number): bigint[] {
    const packed = pack(inArr, inWidth, outWidth);
    if (packed.length > outCount) throw new Error("packed is big enough");

    return packed.concat(Array(outCount - packed.length).fill(0));
}

function padWithZeroes<T>(inArr: T[], outCount: number) {
    if (inArr.length > outCount) throw new Error("inArr is big enough");

    const extra_zeroes = outCount - inArr.length;
    const arr_padded = inArr.concat(Array(extra_zeroes).fill(0));
    return arr_padded;
}

// Poseidon is marked as any because circomlibjs does not have typescript definitions
function poseidonHash(inputs: bigint[], poseidon: any) {
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

/**
 * 
 * @param input A Base64-decoded JWT chunked into bytes
 * @param mask A vector of 0s and 1s of the same length as input
 * @returns 
 */
function applyMask(input: number[], mask: bit[]) {
    if (input.length != mask.length) {
        throw new Error("Input and mask must be of the same length");
    }
    return input.map((charCode, index) => (mask[index] == 1) 
                ? charCode
                : constants.maskValue
            );
}

async function deriveAddrSeed(
    claim_value: string, pin: bigint,
    maxKeyClaimValueLen = constants.maxKeyClaimValueLen,
    packWidth=constants.packWidth
): Promise<bigint> {
    const claim_val_F = await mapToField(claim_value, maxKeyClaimValueLen, packWidth);
    const buildPoseidon = require("circomlibjs").buildPoseidon;
    const poseidon = await buildPoseidon();

    return poseidonHash([
        claim_val_F, pin
    ], poseidon);
}

// Map str into a field element after padding it to maxSize chars
async function mapToField(str: string, maxSize: number, packWidth=constants.packWidth) {
    if (str.length > maxSize) {
        throw new Error(`String ${str} is longer than ${maxSize} chars`);
    }

    const numElements = getNumFieldElements(maxSize, packWidth);
    const packed = pack2(str.split('').map(c => BigInt(c.charCodeAt(0))), 8, packWidth, numElements);

    const buildPoseidon = require("circomlibjs").buildPoseidon;
    const poseidon = await buildPoseidon();
    return poseidonHash(packed, poseidon);
}

function writeJSONToFile(inputs: object, file_name = "inputs.json") {
    fs.writeFileSync(file_name, JSON.stringify(inputs, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2));
}

export {
    arrayChunk,
    trimEndByChar,
    buffer2BitArray,
    bitArray2Buffer,
    bigIntArray2Bits,
    bigIntArray2Buffer,
    applyMask,
    padWithZeroes,
    pack,
    deriveAddrSeed,
    poseidonHash,
    writeJSONToFile,
    mapToField
}
