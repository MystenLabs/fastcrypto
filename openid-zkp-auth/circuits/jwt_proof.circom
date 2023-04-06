pragma circom 2.0.0;

include "sha256.circom";
include "misc.circom";

/**
JWT Proof
    Takes message content segmented into inWidth chunks and calculates a SHA256 hash, for which an RSA signature is known,
    as well as masking the content to obscure private fields.

    Construction Parameters:
    - inCount:          Number of content inputs of inWidth size

    Private Inputs:
    - content[inCount]:         Segments of X as inWidth bit chunks where X is JWT header + JWT payload + SHA-2 padding + zeroes
    - lastBlock:                At which 512-bit block to select output hash
    - mask[inCount]:            A binary mask over X, i.e., mask[i] = 0 or 1
    - randomness:               A 248-bit random number to keep the sensitive parts of JWT hidden

    Public Inputs:
    - payloadIndex:             The index of the payload in the content
    - ephPubKey[2]:             The ephemeral public key split into two 128-bit values
    - maxEpoch:                 The maximum epoch for which the ephPubKey is valid
    - nonce:                    H(ephPubKey, maxEpoch, randomness)
    - hash[2]:                  SHA256 hash output split into two 128-bit values
    - out:                      H(content & masked). The masked content is first packed into 253-bit chunks before hashing.
*/
template JwtProof(inCount) {
    // Input is Base64 characters encoded as ASCII
    var inWidth = 8;
    signal input content[inCount];

    /**
        #1) SHA-256 (30k * nBlocks constraints)
    **/
    signal input lastBlock;
    // Note: In theory, we could've packed 253 bits into an output value, but 
    //       that'd still require at least 2 values. Instead, the below impl
    //       packs the 256 bits into 2 values of 128 bits each. 
    var hashCount = 2;
    signal input hash[hashCount];

    component sha256 = Sha2_wrapper(inWidth, inCount);
    for (var i = 0; i < inCount; i++) {
        sha256.in[i] <== content[i];
    }
    sha256.lastBlock <== lastBlock;

    for (var i = 0; i < hashCount; i++) {
        sha256.hash[i] === hash[i];
    }

    /** 
        #2) sub claim checks 
            2a) Ensures "sub" only appears once (~40k constraints)
            2b) checks the userID (~40k constraints)
        
        Check 2a can be omitted if we can assume that "sub" only appears once.
    **/
    signal input payloadIndex;
    component X = computePayloadOffsets(inCount);
    X.index <== payloadIndex;

    var subKeyLength = 8;
    var subValueLength = 32;

    // ',"sub":'
    var subClaim[3][subKeyLength] = [
        // LCJzdWIi => 4c434a7a64574969 => 0x4c, 0x43, 0x4a, 0x7a, 0x64, 0x57, 0x49, 0x69 => (decimal) 76, 67, 74, 122, 100, 87, 73, 105
        [76, 67, 74, 122, 100, 87, 73, 105], // Appears at 0
        // wic3ViIj => 7769633a53756249
        [119, 105, 99, 51, 86, 105, 73, 106], // Appears at 2
        // InN1YiI6 => 496e4e3159694936
        [73, 110, 78, 49, 89, 105, 73, 54] // Appears at 0
    ];
    var subClaimExpOffsets[3] = [0, 2, 0];

    // ',"sub":"117912735658541336646",'
    var subValue[3][subValueLength] = [
        // LCJzdWIi OiIxMTc5MTI3MzU2NTg1NDEzMzY2NDYi
        [79, 105,  73, 120, 77,  84, 99,  53, 77,  84,  73,  51, 77, 122, 85, 50,
         78,  84, 103,  49, 78,  68, 69, 122, 77, 122,  89,  50, 78,  68, 89, 105],
        // wic3ViIj oiMTE3OTEyNzM1NjU4NTQxMzM2NjQ2Ii
        [111, 105, 77,  84, 69,  51, 79,  84, 69, 121, 78, 122, 77,  49, 78, 106,
         85,  52, 78,  84, 81, 120, 77, 122, 77,  50, 78, 106, 81,  50, 73, 105],
        // InN1YiI6 IjExNzkxMjczNTY1ODU0MTMzNjY0NiIs
        [73, 106, 69, 120, 78, 122, 107, 120, 77, 106, 99, 122, 78,  84,  89,  49, 
         79,  68, 85,  48, 77,  84,  77, 122, 78, 106, 89,  48, 78, 105,  73, 115]
    ];

    component subEQCheck[inCount][3];
    component b64OffsetCheck[inCount][3];

    // Check 2a. Cost: O(subKeyLength * inCount)
    var accumulate[3] = [0, 0, 0];
    var subValueOffset = 0;
    for (var i = 0; i < inCount - subKeyLength - subValueLength; i++) {
        // TODO: Extend it to enable these checks only in [payloadB64Offset, payloadB64Offset + payloadLength]
        for (var k = 0; k < 3; k++) { // looking for subClaim[k] if subClaimExpOffsets[k] == b64offsets[i]
            b64OffsetCheck[i][k] = IsEqual();
            b64OffsetCheck[i][k].in[0] <== X.b64offsets[i];
            b64OffsetCheck[i][k].in[1] <== subClaimExpOffsets[k];

            subEQCheck[i][k] = isEqualIfEnabled(subKeyLength);
            subEQCheck[i][k].enabled <== b64OffsetCheck[i][k].out;

            for (var j = 0; j < subKeyLength; j++) {
                var idx = i + j;
                subEQCheck[i][k].in[0][j] <== content[idx];
                subEQCheck[i][k].in[1][j] <== subClaim[k][j];
            }
        }

        subValueOffset += (i + subKeyLength) * (subEQCheck[i][0].out + subEQCheck[i][1].out + subEQCheck[i][2].out);

        accumulate[0] += subEQCheck[i][0].out;
        accumulate[1] += subEQCheck[i][1].out;
        accumulate[2] += subEQCheck[i][2].out;
        // log(i, b64offsets[i], accumulate[0], accumulate[1], accumulate[2]);
    }

    accumulate[0] + accumulate[1] + accumulate[2] === 1; // Adding at most 3*inCount bits, so no concern of wrapping around

    // Check 2b. Implicit check for expected offsets as it appears right after "sub".
    component subExtractor = SliceFixed(inCount, subValueLength);
    for (var i = 0; i < inCount; i++) {
        subExtractor.in[i] <== content[i];
    }
    subExtractor.offset <== subValueOffset;
    for (var i = 0; i < subValueLength; i++) {
        subExtractor.out[i] === subValue[0][i] * accumulate[0] + subValue[1][i] * accumulate[1] + subValue[2][i] * accumulate[2];
    }

    /** 
        #3) Masking 
        Cost: (1k constraints) (2*inCount) 
    **/
    signal input mask[inCount];
    signal masked[inCount];
    signal input out;

    for(var i = 0; i < inCount; i++) {
        // Ensure mask is binary
        mask[i] * (1 - mask[i]) === 0;
        // If mask is 0, then replace with '=' (ASCII 61) to avoid conflicts with base64 characters
        masked[i] <== content[i] * mask[i] + (1 - mask[i]) * 61;
    }

    var outWidth = 253;
    var inBits = inCount * inWidth;
    var outCount = inBits \ outWidth;
    if (inBits % outWidth != 0) {
        outCount++;
    }

    component outPacker = Packer(inWidth, inCount, outWidth, outCount);
    for (var i = 0; i < inCount; i++) {
        outPacker.in[i] <== masked[i];
    }

    component outHasher = Hasher(outCount);
    for (var i = 0; i < outCount; i++) {
        outHasher.in[i] <== outPacker.out[i];
    }
    out === outHasher.out;

    /**
        #4) nonce == Hash(ephPubKey, maxEpoch, r)
    **/
    signal input ephPubKey[2];
    signal input maxEpoch;
    signal input randomness;
    signal input nonce;

    component nhash = Poseidon(4);
    nhash.inputs[0] <== ephPubKey[0];
    nhash.inputs[1] <== ephPubKey[1];
    nhash.inputs[2] <== maxEpoch;
    nhash.inputs[3] <== randomness;
    nonce === nhash.out;
}
