pragma circom 2.1.3;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";
include "../node_modules/circomlib/circuits/gates.circom";
include "misc.circom";
include "base64.circom";

/**
SliceFixed: Returns a fixed-length slice of an array.
More precisely, in[index:index+outLen] (both inclusive).

Cost: inLen + outLen * inLen

Range checks:
    - index in [0, inLen)
    - index + outLen in [0, inLen]
    - outLen in (0, inLen]
**/
template SliceFixed(inLen, outLen) {
    assert(outLen > 0);
    assert(outLen <= inLen);

    signal input in[inLen];
    signal input index;
    signal output out[outLen];

    RangeCheck(numBits(inLen), inLen - 1)(index); // index in [0, inLen - 1]
    RangeCheck(numBits(inLen), inLen)(index + outLen); // index + outLen in [0, inLen]

    // eqs[index] = 1, 0 otherwise
    signal eqs[inLen] <== OneBitVector(inLen)(index);
    for(var i = 0; i < outLen; i++) {
        // arr[i + index] = 1 (if i + index < inLen), 0 otherwise
        var arr[inLen];
        for (var j = 0; j < inLen; j++) {
            if (j < i) {
                arr[j] = 0;
            } else {
                arr[j] = eqs[j - i];
            }
        }
        out[i] <== EscalarProduct(inLen)(arr, in);
    }
}

/**
Slice: Returns a variable-length slice of an array.
More precisely, in[index:index+length] + [0] * (outLen - length).

Cost: Roughly (inLen + outLen + outLen * inLen)

Range checks:
    - index in [0, inLen)
    - length in [0, outLen]
    - index + length in [0, inLen]
    - outLen in (0, inLen]
**/
template Slice(inLen, outLen) {
    assert(outLen > 0);
    assert(outLen <= inLen);

    signal input in[inLen];
    signal input index;
    signal input length;

    RangeCheck(numBits(inLen), inLen - 1)(index); // index in [0, inLen - 1]
    RangeCheck(numBits(outLen), outLen)(length); // length in [0, outLen]
    RangeCheck(numBits(inLen), inLen)(index + length); // index + length in [0, inLen]

    signal output out[outLen];

    // eqs[i] = 1 if i = index, 0 otherwise
    signal eqs[inLen] <== OneBitVector(inLen)(index);
    // lt[i] = 1 if i < length, 0 otherwise
    signal lts[outLen] <== LTBitVector(outLen)(length);

    signal tmp[outLen];
    for(var i = 0; i < outLen; i++) {
        var arr[inLen];
        for (var j = 0; j < inLen; j++) {
            if (j < i) {
                arr[j] = 0;
            } else {
                arr[j] = eqs[j - i];
            }
        }
        tmp[i] <== EscalarProduct(inLen)(arr, in);
        out[i] <== tmp[i] * lts[i];
    }
}

// in[index: index + length*groupLen] + [0] * (outLen - length)*groupLen
// template SliceGrouped(inLen, outLen, groupLen) {
//     signal input in[inLen];
//     signal input index;
//     signal input length;

//     signal output out[outLen * groupLen];

//     // eqs[i] = 1 if i = index, 0 otherwise
//     signal eqs[inLen] <== OneBitVector(inLen)(index);
//     // lt[i] = 1 if i < length, 0 otherwise
//     signal lts[outLen] <== LTBitVector(outLen)(length);

//     signal tmp[outLen];
//     for(var i = 0; i < outLen; i++) {
//         var arr[inLen];
//         for (var j = 0; j < inLen; j++) {
//             if (j < i) {
//                 arr[j] = 0;
//             } else {
//                 arr[j] = eqs[j - i];
//             }
//         }
//         tmp[i] <== EscalarProduct(inLen)(arr, in);

//         for (var j = 0; j < groupLen; j++) {
//             out[i * groupLen + j] <== tmp[i] * lts[i];
//         }
//     }
// }

/**
Checks if an ASCII-encoded substring exists in a Base64-encoded string.

Cost: Slice is the costliest since b64StrLen is big in practice.

Construction Parameters:
    b64StrLen:              The length of the Base64-encoded string
    maxA:                   The maximum length of the ASCII-encoded substring
                            (must be a multiple of 3)

Input:
    b64Str[b64StrLen]:      The Base64-encoded string to search in
    lenB:                   The length of the Base64-encoded substring to check
    BIndex:                 The index of the first character of the
                            Base64-encoded substring to check. For the check to 
                            work, it should represent just the part of b64Str that 
                            contains A.
    A[maxA]:                The ASCII-encoded substring to search for padded with 0s
                            e.g., A = ,"sub":"12345",0000 and lenA = 15
    lenA:                   The length of the ASCII-encoded substring
    payloadIndex:           The index of the first character of the payload

Output:
    The function checks if the ASCII-encoded substring exists in the
    Base64-encoded string with an offset of 0, 1, or 2.

Range checks:
    0 <= lenB <= maxB (checked in Slice)
    0 <= BIndex < b64StrLen (checked in Slice)
    0 <= BIndex + lenB <= b64StrLen (checked in Slice)
    maxB <= b64StrLen (checked in Slice)
    0 <= lenA <= maxA (checked in LTBitVector)
    payloadIndex <= BIndex (checked in RemainderMod4)
*/
template ASCIISubstrExistsInB64(b64StrLen, maxA) {
    assert(maxA % 3 == 0); // for simplicity
    var maxB = 1 + ((maxA / 3) * 4); // max(b64Len(maxA, i)) for any i

    signal input b64Str[b64StrLen];
    signal input lenB;
    signal input BIndex;
    signal B[maxB] <== Slice(b64StrLen, maxB)(
        b64Str, BIndex, lenB
    );

    var B_bit_len = maxB * 6;
    signal B_in_bits[B_bit_len] <== MultiB64URLToBits(maxB)(B);

    signal input A[maxA];
    signal input lenA;

    var A_bit_len = 8 * maxA;
    signal A_in_bits[A_bit_len];
    for (var i = 0; i < maxA; i++) {
        var X[8] = Num2BitsBE(8)(A[i]);
        for (var j = 0; j < 8; j++) {
            A_in_bits[i * 8 + j] <== X[j];
        }
    }

    signal input payloadIndex;
    var BIndexInPayload = BIndex - payloadIndex;
    signal expectedOffset <== RemainderMod4(numBits(b64StrLen))(BIndexInPayload);
    signal eq_0 <== IsEqual()([expectedOffset, 0]);
    signal eq_1 <== IsEqual()([expectedOffset, 1]);
    signal eq_2 <== IsEqual()([expectedOffset, 2]);
    eq_0 + eq_1 + eq_2 === 1; // ensure offset is 0, 1, or 2

    var T_actual_len = lenA * 8;
    signal tmp[maxA] <== LTBitVector(maxA)(lenA);

    signal enabled_0[maxA];
    // A_bit_len <= B_bit_len is guaranteed by the condition on maxB
    assert(A_bit_len <= B_bit_len);
    for (var i = 0; i < A_bit_len; i++) {
        if (i % 8 == 0) {
            enabled_0[i \ 8] <== tmp[i \ 8] * eq_0;
        }
        MyForceEqualIfEnabled()(enabled_0[i \ 8], [A_in_bits[i], B_in_bits[i]]);
    }

    signal enabled_1[maxA];
    // A_bit_len + 2 <= B_bit_len is guaranteed by the condition on maxB
    assert(A_bit_len + 2 <= B_bit_len);
    for (var i = 0; i < A_bit_len; i++) {
        if (i % 8 == 0) {
            enabled_1[i \ 8] <== tmp[i \ 8] * eq_1;
        }
        MyForceEqualIfEnabled()(enabled_1[i \ 8], [A_in_bits[i], B_in_bits[i + 2]]);
    }

    signal enabled_2[maxA];
    // A_bit_len + 4 <= B_bit_len is guaranteed by the condition on maxB
    assert(A_bit_len + 4 <= B_bit_len);
    for (var i = 0; i < A_bit_len; i++) {
        if (i % 8 == 0) {
            enabled_2[i \ 8] <== tmp[i \ 8] * eq_2;
        }
        MyForceEqualIfEnabled()(enabled_2[i \ 8], [A_in_bits[i], B_in_bits[i + 4]]);
    }
}