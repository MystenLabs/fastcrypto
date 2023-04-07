pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "misc.circom";

// Returns in[index:index+outSize]
// Cost: O(inSize * outSize)
template SliceFixed(inSize, outSize) {
    signal input in[inSize];
    signal input index;
    
    signal output out[outSize];
    
    component selector[outSize];
    component eqs[inSize][outSize];
    for(var i = 0; i < outSize; i++) {
        selector[i] = CalculateTotal(inSize);
        
        for(var j = 0; j < inSize; j++) {
            eqs[j][i] = IsEqual();
            eqs[j][i].in[0] <== j;
            eqs[j][i].in[1] <== index + i;
            
            selector[i].nums[j] <== eqs[j][i].out * in[j];
        }

        out[i] <== selector[i].sum;
    }
}

/**
Checks if a Base64-encoded substring exists in a Base64-encoded string.

Construction Parameters:
    substr[3][substrLen]:        The three Base64 representations of the substring to search for
    substrLen:                   The length of the substring
    substrExpOffsets[3]:         The expected offsets of the substrings in the Base64 representation
    inCount:                     The length of the input string

Input:
    string[inCount]:             The string to search in
    startIndex:                  The index of the first character of the payload
    substrIndex:                 The index of the first character of the substring to check
*/
template CheckIfB64StringExists(substr, substrLen, substrExpOffsets, inCount) {
    signal input string[inCount];
    signal input startIndex;
    signal input substrIndex;

    component extractor = SliceFixed(inCount, substrLen);
    for (var i = 0; i < inCount; i++) {
        extractor.in[i] <== string[i];
    }
    extractor.index <== substrIndex;

    component O = RemainderMod4();
    O.in <== substrIndex - startIndex; // TODO: Do we need to check if subStrIndex > startIndex?

    component eq[3];
    component I[3];
    for (var i = 0; i < 3; i++) {
        I[i] = IsEqual();
        I[i].in[0] <== O.out;
        I[i].in[1] <== substrExpOffsets[i];

        eq[i] = IsEqualIfEnabled(substrLen);
        for (var j = 0; j < substrLen; j++) {
            eq[i].in[0][j] <== extractor.out[j];
            eq[i].in[1][j] <== substr[i][j];
        }
        eq[i].enabled <== I[i].out;
    }

    eq[0].out + eq[1].out + eq[2].out === 1;
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
    inCount: Number of signals to compute offsets for

Inputs:
    index: Payload start index

Outputs:
    out[i] = (4 - (index % 4)) % 4 if i = 0
           = (out[i-1] + 1) % 4 otherwise

Note that this ensures that out[index] will be 0.
**/
// template computePayloadOffsets(inCount) {
//     signal input index;
//     signal output b64offsets[inCount];

//     component offsetCalc = offsetCalculator();
//     offsetCalc.in <== index;
//     b64offsets[0] <== offsetCalc.out;

//     component rems[4];
//     for (var i = 1; i < 4; i++) {
//         rems[i] = remainderMod4();
//         rems[i].in <== b64offsets[i - 1] + 1;
//         b64offsets[i] <== rems[i].out;
//     }

//     for (var i = 4; i < inCount; i++) {
//         b64offsets[i] <== b64offsets[i % 4];
//     }
// }

/**
Find all substrings in a string. Cost: O(substrLen * inCount)

Construction Parameters:
    substr[3][substrLen]:        The three Base64 representations of the substring to search for
    substrLen:                   The length of the substring
    substrExpOffsets[3]:         The expected offsets of the substrings in the Base64 representation
    inCount:                     The length of the input string

Input:
    string[inCount]:             The string to search in
    b64offsets[inCount]:         The offsets of the Base64 representation of the string

Output:
    out[3]:                      out[i] is 1 if substr[i] is found in the string
    index:                       The index of the first character of the first substring found
**/
// template findAllB64String(substr, substrLen, substrExpOffsets, inCount) {
//     signal input string[inCount];
//     signal input b64offsets[inCount];
//     signal output out[3];
//     signal output index;

//     component subEQCheck[inCount][3];
//     component b64OffsetCheck[inCount][3];

//     var accumulate[3] = [0, 0, 0];
//     var offset = 0;
//     for (var i = 0; i < inCount - substrLen; i++) {
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
//                 subEQCheck[i][k].in[1][j] <== substr[k][j];
//             }
//         }

//         offset += i * (subEQCheck[i][0].out + subEQCheck[i][1].out + subEQCheck[i][2].out);

//         accumulate[0] += subEQCheck[i][0].out;
//         accumulate[1] += subEQCheck[i][1].out;
//         accumulate[2] += subEQCheck[i][2].out;
//         // log(i, b64offsets[i], accumulate[0], accumulate[1], accumulate[2]);
//     }

//     accumulate[0] + accumulate[1] + accumulate[2] === 1; // Adding at most 3*inCount bits, so no concern of wrapping around

//     out[0] <== accumulate[0];
//     out[1] <== accumulate[1];
//     out[2] <== accumulate[2];

//     index <== offset;
// }

