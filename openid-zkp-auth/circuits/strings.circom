pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";
include "misc.circom";

// Returns in[index:index+outstrLen]
// Cost: instrLen + outstrLen * instrLen
template SliceFixed(instrLen, outstrLen) {
    signal input in[instrLen];
    signal input index;
    signal output out[outstrLen];
    
    // eqs[i] = 1 if i = index, 0 otherwise
    signal eqs[instrLen] <== OneBitVector(instrLen)(index);
    for(var i = 0; i < outstrLen; i++) {
        var arr[instrLen];
        for (var j = 0; j < instrLen; j++) {
            if (j < i) {
                arr[j] = 0;
            } else {
                arr[j] = eqs[j - i];
            }
        }
        out[i] <== EscalarProduct(instrLen)(arr, in);
    }
}

/**
Checks if a Base64-encoded substring exists in a Base64-encoded string.

Construction Parameters:
    substrArr[numSubstrs][substrLen]:     An array of Base64 representations of the substring to search for
    numSubstrs:                        The number of substrings
    substrLen:                         The length of the substring
    substrExpOffsets[3]:               The expected offsets of the substrings in the Base64 representation
    strLen:                              The length of the input string

Input:
    string[strLen]:             The string to search in
    startIndex:                  The index of the first character of the payload
    substrIndex:                 The index of the first character of the substring to check
*/
template CheckIfB64StringExists(substrArr, numSubstrs, substrLen, substrExpOffsets, strLen) {
    signal input string[strLen];
    signal input startIndex;
    signal input substrIndex;

    signal extracted[substrLen] <== SliceFixed(strLen, substrLen)(string, substrIndex);

    signal remainder <== RemainderMod4(log2(strLen))(substrIndex - startIndex);
    // TODO: Do we need to check if subStrIndex > startIndex?

    signal eq[numSubstrs];
    signal isCheckEnabled[numSubstrs];
    var sum = 0;
    for (var i = 0; i < numSubstrs; i++) {
        isCheckEnabled[i] <== IsEqual()([
            remainder,
            substrExpOffsets[i]
        ]);

        eq[i] <== IsEqualIfEnabled(substrLen)([
            extracted,
            substrArr[i]
        ], isCheckEnabled[i]);

        sum += eq[i];
    }

    sum === 1;
}

// l => (4 - (l % 4)) % 4
// template offsetCalculator() {
//     signal input in;
//     signal output out;

//     component r1 = remainderMod4();
//     r1.in <== in;

//     component r2 = remainderMod4();
//     r2.in <== 4 - r1.out;

//     out <== r2.out;
// }

/**
Computes offsets relative to the start of the payload.

Construction Params:
    strLen: Number of signals to compute offsets for

Inputs:
    index: Payload start index

Outputs:
    out[i] = (4 - (index % 4)) % 4 if i = 0
           = (out[i-1] + 1) % 4 otherwise

Note that this ensures that out[index] will be 0.
**/
// template computePayloadOffsets(strLen) {
//     signal input index;
//     signal output b64offsets[strLen];

//     component offsetCalc = offsetCalculator();
//     offsetCalc.in <== index;
//     b64offsets[0] <== offsetCalc.out;

//     component rems[4];
//     for (var i = 1; i < 4; i++) {
//         rems[i] = remainderMod4();
//         rems[i].in <== b64offsets[i - 1] + 1;
//         b64offsets[i] <== rems[i].out;
//     }

//     for (var i = 4; i < strLen; i++) {
//         b64offsets[i] <== b64offsets[i % 4];
//     }
// }

/**
Find all substrings in a string. Cost: O(substrLen * strLen)

Construction Parameters:
    substrArr[3][substrLen]:        The three Base64 representations of the substring to search for
    substrLen:                   The length of the substring
    substrExpOffsets[3]:         The expected offsets of the substrings in the Base64 representation
    strLen:                     The length of the input string

Input:
    string[strLen]:             The string to search in
    b64offsets[strLen]:         The offsets of the Base64 representation of the string

Output:
    out[3]:                      out[i] is 1 if substrArr[i] is found in the string
    index:                       The index of the first character of the first substring found
**/
// template findAllB64String(substrArr, substrLen, substrExpOffsets, strLen) {
//     signal input string[strLen];
//     signal input b64offsets[strLen];
//     signal output out[3];
//     signal output index;

//     component subEQCheck[strLen][3];
//     component b64OffsetCheck[strLen][3];

//     var accumulate[3] = [0, 0, 0];
//     var offset = 0;
//     for (var i = 0; i < strLen - substrLen; i++) {
//         // TODO: Extend it to enable these checks only in [payloadIndex, payloadIndex + payloadLength]
//         for (var k = 0; k < 3; k++) { // looking for subClaim[k] if substrExpOffsets[k] == b64offsets[i]
//             b64OffsetCheck[i][k] = IsEqual();
//             b64OffsetCheck[i][k].in[0] <== b64offsets[i];
//             b64OffsetCheck[i][k].in[1] <== substrExpOffsets[k];

//             subEQCheck[i][k] = isEqualIfEnabled(substrLen);
//             subEQCheck[i][k].enabled <== b64OffsetCheck[i][k].out;

//             for (var j = 0; j < substrLen; j++) {
//                 var idx = i + j;
//                 subEQCheck[i][k].in[0][j] <== string[idx];
//                 subEQCheck[i][k].in[1][j] <== substrArr[k][j];
//             }
//         }

//         offset += i * (subEQCheck[i][0].out + subEQCheck[i][1].out + subEQCheck[i][2].out);

//         accumulate[0] += subEQCheck[i][0].out;
//         accumulate[1] += subEQCheck[i][1].out;
//         accumulate[2] += subEQCheck[i][2].out;
//         // log(i, b64offsets[i], accumulate[0], accumulate[1], accumulate[2]);
//     }

//     accumulate[0] + accumulate[1] + accumulate[2] === 1; // Adding at most 3*strLen bits, so no concern of wrapping around

//     out[0] <== accumulate[0];
//     out[1] <== accumulate[1];
//     out[2] <== accumulate[2];

//     index <== offset;
// }

