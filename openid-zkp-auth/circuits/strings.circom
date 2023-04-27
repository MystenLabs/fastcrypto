pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";
include "misc.circom";
include "base64.circom";

// Returns in[index:index+outLen]
// Cost: inLen + outLen * inLen
template SliceFixed(inLen, outLen) {
    signal input in[inLen];
    signal input index;
    signal output out[outLen];
    
    // eqs[i] = 1 if i = index, 0 otherwise
    signal eqs[inLen] <== OneBitVector(inLen)(index);
    for(var i = 0; i < outLen; i++) {
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

// Returns in[index:index+length] + [0] * (outLen - length)
// Cost: Roughly (inLen + outLen + outLen * inLen)
// Assumes index in [0, inLen) and length in [0, outLen]. Fails otherwise.
template Slice(inLen, outLen) {
    signal input in[inLen];
    signal input index;
    signal input length;

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

/**
Checks if a Base64-encoded substring exists in a Base64-encoded string.

Construction Parameters:
    substringArray[numSubstrings][substringLength]: An array of Base64 representations
                                                    of the substrings to search for
    numSubstrings:                                 Number of substrings
    substringLength:                               Length of the substring
    offsetArray[numSubstrings]:                    Array of expected offsets of the
                                                    substrings in the Base64 representation
    inputStringLength:                             Length of the input string

Input:
    inputString[inputStringLength]:                String to search in
    payloadIndex:                                  Index of the 1st character of the 
                                                    payload in the JWT
    substringIndex:                                Index of the 1st character of the
                                                    substring to check in the JWT
*/
template B64SubstrExists(substringArray, numSubstrings, substringLength, offsetArray, inputStringLength) {
    signal input inputString[inputStringLength];
    signal input payloadIndex;
    signal input substringIndex;

    signal extractedSubstring[substringLength] <== 
        SliceFixed(inputStringLength, substringLength)
            (inputString, substringIndex);

    var substringIndexInPayload = substringIndex - payloadIndex;
    signal remainder <== RemainderMod4(log2(inputStringLength))(substringIndexInPayload);

    signal isEqualArray[numSubstrings];
    signal isCheckEnabledArray[numSubstrings];
    var sum = 0;
    for (var i = 0; i < numSubstrings; i++) {
        isCheckEnabledArray[i] <== IsEqual()([
            remainder,
            offsetArray[i]
        ]);

        isEqualArray[i] <== IsEqualIfEnabled(substringLength)([
            extractedSubstring,
            substringArray[i]
        ], isCheckEnabledArray[i]);

        sum += isEqualArray[i];
    }

    sum === 1;
}

/**
Checks if a Base64-encoded substring exists in a Base64-encoded string.
This variant takes the different substring options as a private input.

Construction Parameters:
    numSubstrings:          The number of substrings
    maxSubstringLength:     The maximum length of the substring
    inputStringLength:      The length of the input string

Input:
    substringArray[numSubstrings][maxSubstringLength]: An array of Base64 representations
                                                       of the substring to search for.
                                                       substringArray[numSubstrings][substringLength]
                                                       contains the real substring. The rest must be 0s.
    offsets[numSubstrings]:                           The expected offsets of the substrings
                                                       in the Base64 representation
    inputString[inputStringLength]:                   The string to search in
    payloadIndex:                                     The index of the first character of the 
                                                        payload in the JWT
    substringIndex:                                   The index of the first character of the
                                                       substring to check in the JWT
*/
template B64SubstrExistsAlt(numSubstrings, maxSubstringLength, inputStringLength) {
    signal input substringArray[numSubstrings][maxSubstringLength];
    signal input substringLength;
    signal input offsets[numSubstrings];

    signal input inputString[inputStringLength];
    signal input payloadIndex;
    signal input substringIndex;

    signal extracted[maxSubstringLength] <== Slice(inputStringLength, maxSubstringLength)(
                                                inputString, substringIndex, substringLength);

    signal remainder <== RemainderMod4(log2(inputStringLength))(substringIndex -
                                                                 payloadIndex);

    signal isEqualArray[numSubstrings];
    signal isCheckEnabledArray[numSubstrings];
    var sum = 0;
    for (var i = 0; i < numSubstrings; i++) {
        isCheckEnabledArray[i] <== IsEqual()([
            remainder,
            offsets[i]
        ]);

        isEqualArray[i] <== IsEqualIfEnabled(maxSubstringLength)([
            extracted,
            substringArray[i]
        ], isCheckEnabledArray[i]);

        sum += isEqualArray[i];
    }

    sum === 1;
}
