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

    Private inputs (revealed outside the circuit):
    - payload_start_index:      The index of the payload in the content
    - payload_len:              The length of the payload
    - eph_public_key[2]:        The ephemeral public key split into two 128-bit values
    - max_epoch:                The maximum epoch for which the eph_public_key is valid
    - num_sha2_blocks:          Number of SHA2 (64-byte) blocks the SHA2-padded JWT consumes

    Public Inputs:
    - all_inputs_hash:          H(jwt_sha2_hash[2] || masked_content_hash || payload_start_index || payload_len
                                  eph_public_key[2] || max_epoch || nonce || num_sha2_blocks)

*/
template JwtProof(inCount, subValue, subValueLength, subOffsets) {
    // Input is Base64 characters encoded as ASCII
    var inWidth = 8;
    signal input content[inCount];

    /**
        #1) SHA-256 (30k * nBlocks constraints)
    **/
    signal input num_sha2_blocks;
    // Note: In theory, we could've packed 253 bits into an output value, but 
    //       that'd still require at least 2 values. Instead, the below impl
    //       packs the 256 bits into 2 values of 128 bits each. 
    var hashCount = 2;
    signal jwt_sha2_hash[hashCount] <== Sha2_wrapper(inWidth, inCount)(
        content, 
        num_sha2_blocks
    );

    /** 
        #2) Checks that the substring `,"sub":UserID,` appears at sub_claim_index 
        Cost: (subValueLength + 1) * inCount constraints
    **/
    signal input payload_start_index;
    signal input sub_claim_index;
    CheckIfB64StringExists(
        subValue,
        subValueLength,
        subOffsets,
        inCount
    )(
        string <== content,
        substrIndex <== sub_claim_index,
        startIndex <== payload_start_index
    );

    /** 
        #3) Masking 
        Cost: 1k constraints (2*inCount) 
    **/
    signal input mask[inCount];
    signal masked[inCount];

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

    signal packed[outCount] <== Packer(inWidth, inCount, outWidth, outCount)(masked);
    signal masked_content_hash <== Hasher(outCount)(packed);

    /**
        #4) nonce == Hash(eph_public_key, max_epoch, r)
    **/
    signal input eph_public_key[2];
    signal input max_epoch;
    signal input randomness;

    signal nonce <== Poseidon(4)([
        eph_public_key[0], 
        eph_public_key[1], 
        max_epoch, 
        randomness
    ]);

    /**
        #5) Misc checks: 
            - Ensure mask[i] == 1 for all i >= payload_start_index + payload_len
    **/
    signal input payload_len;
    signal payload_len_actual <== payload_start_index + payload_len;

    // set pllt[i] = 1 if i >= payload_len_actual, 0 otherwise
    signal plgt[inCount] <== GTBitVector(inCount)(payload_len_actual);
    for (var i = 0; i < inCount; i++) {
        plgt[i] * (1 - mask[i]) === 0; // if pllt[i] == 1, then mask[i] == 1
    }

    /**
        #6) Hash all public inputs
    **/
    signal input all_inputs_hash;
    signal all_inputs_hash_actual <== Poseidon(10)([
        jwt_sha2_hash[0],
        jwt_sha2_hash[1],
        masked_content_hash,
        payload_start_index,
        payload_len,
        eph_public_key[0],
        eph_public_key[1],
        max_epoch,
        nonce,
        num_sha2_blocks
    ]);
    all_inputs_hash === all_inputs_hash_actual;
}
