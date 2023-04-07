pragma circom 2.0.0;

include "sha256.circom";
include "misc.circom";
include "strings.circom";

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
template JwtProof(inCount, subValue, subValueLength, subOffsets) {
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
        #2) Checks that the substring `,"sub":UserID,` appears at subClaimIndex 
        Cost: ~40k constraints
    **/
    signal input payloadIndex;
    signal input subClaimIndex;
    component subChecker = CheckIfB64StringExists(
        subValue,
        subValueLength,
        subOffsets,
        inCount
    );

    for (var i = 0; i < inCount; i++) {
        subChecker.string[i] <== content[i];
    }
    subChecker.substrIndex <== subClaimIndex;
    subChecker.startIndex <== payloadIndex;

    /** 
        #3) Masking 
        Cost: 1k constraints (2*inCount) 
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
