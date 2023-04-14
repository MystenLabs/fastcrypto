pragma circom 2.0.0;

include "sha256.circom";
include "misc.circom";
include "strings.circom";
include "zkhasher.circom";

/**
JWT Proof
    Takes message content segmented into inWidth chunks and calculates a SHA256 hash, for which an RSA signature is known,
    as well as masking the content to obscure private fields.

    Construction Parameters:
    - inCount:          Number of content inputs of inWidth size

    Private Inputs:
    - content[inCount]:         Segments of X as inWidth bit chunks where X is JWT header + JWT payload + SHA-2 padding + zeroes
    - mask[inCount]:            A binary mask over X, i.e., mask[i] = 0 or 1
    - randomness:               A 248-bit random number to keep the sensitive parts of JWT hidden
    - sub_claim_index:          The index of the substring `,"sub":UserID,` in the Base64 encoded content

    Public Inputs:
    - jwt_sha2_hash[2]:         SHA256 hash output split into two 128-bit values
    - masked_content_hash:      H(content & masked). The masked content is first packed into 253-bit chunks before hashing.
    - payload_index:            The index of the payload in the content
    - eph_public_key[2]:        The ephemeral public key split into two 128-bit values
    - max_epoch:                The maximum epoch for which the eph_public_key is valid
    - nonce:                    H(eph_public_key, max_epoch, randomness)
    - last_block:               At which 512-bit block to select output hash
*/
template JwtProof(inCount, subValue, subValueLength, subOffsets) {
    // Input is Base64 characters encoded as ASCII
    var inWidth = 8;
    signal input content[inCount];

    /**
        #1) SHA-256 (30k * nBlocks constraints)
    **/
    signal input last_block;
    // Note: In theory, we could've packed 253 bits into an output value, but 
    //       that'd still require at least 2 values. Instead, the below impl
    //       packs the 256 bits into 2 values of 128 bits each. 
    var hashCount = 2;
    signal input jwt_sha2_hash[hashCount];

    component sha256 = Sha2_wrapper(inWidth, inCount);
    for (var i = 0; i < inCount; i++) {
        sha256.in[i] <== content[i];
    }
    sha256.last_block <== last_block;

    for (var i = 0; i < hashCount; i++) {
        sha256.hash[i] === jwt_sha2_hash[i];
    }

    /** 
        #2) Checks that the substring `,"sub":UserID,` appears at sub_claim_index 
        Cost: ~40k constraints
    **/
    signal input payload_index;
    signal input sub_claim_index;
    component subChecker = CheckIfB64StringExists(
        subValue,
        subValueLength,
        subOffsets,
        inCount
    );

    for (var i = 0; i < inCount; i++) {
        subChecker.string[i] <== content[i];
    }
    subChecker.substrIndex <== sub_claim_index;
    subChecker.startIndex <== payload_index;

    /** 
        #3) Masking 
        Cost: 1k constraints (2*inCount) 
    **/
    signal input mask[inCount];
    signal masked[inCount];
    signal input masked_content_hash;

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
    masked_content_hash === outHasher.out;

    /**
        #4) nonce == Hash(eph_public_key, max_epoch, r)
    **/
    signal input eph_public_key[2];
    signal input max_epoch;
    signal input randomness;
    signal input nonce;

    component nhash = Poseidon(4);
    nhash.inputs[0] <== eph_public_key[0];
    nhash.inputs[1] <== eph_public_key[1];
    nhash.inputs[2] <== max_epoch;
    nhash.inputs[3] <== randomness;
    nonce === nhash.out;
}
