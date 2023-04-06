pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "misc.circom";

// Returns in[offset:offset+outSize]
// Cost: O(inSize * outSize)
template sliceFixed(inSize, outSize) {
    signal input in[inSize];
    signal input offset;
    
    signal output out[outSize];
    
    component selector[outSize];
    component eqs[inSize][outSize];
    for(var i = 0; i < outSize; i++) {
        selector[i] = CalculateTotal(inSize);
        
        for(var j = 0; j < inSize; j++) {
            eqs[j][i] = IsEqual();
            eqs[j][i].in[0] <== j;
            eqs[j][i].in[1] <== offset + i;
            
            selector[i].nums[j] <== eqs[j][i].out * in[j];
        }

        out[i] <== selector[i].sum;
    }
}

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
template findAllB64String(substr, substrLen, substrExpOffsets, inCount) {
    signal input string[inCount];
    signal input b64offsets[inCount];
    signal output out[3];
    signal output index;

    component subEQCheck[inCount][3];
    component b64OffsetCheck[inCount][3];

    var accumulate[3] = [0, 0, 0];
    var offset = 0;
    for (var i = 0; i < inCount - substrLen; i++) {
        // TODO: Extend it to enable these checks only in [payloadIndex, payloadIndex + payloadLength]
        for (var k = 0; k < 3; k++) { // looking for subClaim[k] if substrExpOffsets[k] == b64offsets[i]
            b64OffsetCheck[i][k] = IsEqual();
            b64OffsetCheck[i][k].in[0] <== b64offsets[i];
            b64OffsetCheck[i][k].in[1] <== substrExpOffsets[k];

            subEQCheck[i][k] = isEqualIfEnabled(substrLen);
            subEQCheck[i][k].enabled <== b64OffsetCheck[i][k].out;

            for (var j = 0; j < substrLen; j++) {
                var idx = i + j;
                subEQCheck[i][k].in[0][j] <== string[idx];
                subEQCheck[i][k].in[1][j] <== substr[k][j];
            }
        }

        offset += i * (subEQCheck[i][0].out + subEQCheck[i][1].out + subEQCheck[i][2].out);

        accumulate[0] += subEQCheck[i][0].out;
        accumulate[1] += subEQCheck[i][1].out;
        accumulate[2] += subEQCheck[i][2].out;
        // log(i, b64offsets[i], accumulate[0], accumulate[1], accumulate[2]);
    }

    accumulate[0] + accumulate[1] + accumulate[2] === 1; // Adding at most 3*inCount bits, so no concern of wrapping around

    out[0] <== accumulate[0];
    out[1] <== accumulate[1];
    out[2] <== accumulate[2];

    index <== offset;
}