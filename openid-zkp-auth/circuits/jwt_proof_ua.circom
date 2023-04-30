pragma circom 2.0.0;

include "sha256.circom";
include "misc.circom";
include "strings.circom";
include "zkhasher.circom";

/**
JWT Proof: User-agnostic (UA) circuit

    Construction params:
    - jwtMaxLen:                Maximum length of the JWT in bytes
    - maxSubLength:             Maximum length of the subject_id (in ascii)

    Private Inputs:
    - content[inCount]:         Segments of X as inWidth bit chunks where X is JWT header + JWT payload + SHA-2 padding + zeroes
    - sub_length_ascii:         Length of the subject_id in ASCII, e.g., for ',"sub":12345,' it is 13
    - subject_id[maxSubLength]: The subject (user) ID for the first sub_length_ascii characters and 0s for the rest
    - subject_pin:              User's PIN to keep the subject_id private
    - mask[inCount]:            A binary mask over X, i.e., mask[i] = 0 or 1
    - randomness:               A 248-bit random number to keep the sensitive parts of JWT hidden

    Circuit signals revealed to the verifier along with the ZK proof:
    - jwt_sha2_hash:            The SHA2 hash of the JWT header + JWT payload + SHA-2 padding
    - num_sha2_blocks:          Number of SHA2 (64-byte) blocks the SHA2-padded JWT consumes
    - subject_id_com:           A (binding, hiding) commitment to subject_id, H(subject_id || PIN)
    - payload_start_index:      The index of the payload in the content
    - payload_len:              The length of the payload
    - masked_content:           The content with the sensitive parts masked
    - eph_public_key[2]:        The ephemeral public key split into two 128-bit values
    - max_epoch:                The maximum epoch for which the eph_public_key is valid

    Public Inputs:
    - all_inputs_hash:          H(jwt_sha2_hash[2] || masked_content_hash || payload_start_index || payload_len
                                  eph_public_key[2] || max_epoch || nonce || num_sha2_blocks || subject_id_com)
*/
template JwtProofUA(jwtMaxLen, maxSubLength) {
    // Input is Base64 characters encoded as ASCII
    var inWidth = 8;
    var inCount = jwtMaxLen;
    signal input content[inCount];

    /**
     1. SHA2(content)
    */
    signal input num_sha2_blocks;
    var hashCount = 2;
    signal jwt_sha2_hash[hashCount] <== Sha2_wrapper(inWidth, inCount)(
        content, 
        num_sha2_blocks
    );

    /**
     2. Check if the user-input string exists in the JWT payload
    */
    signal input subject_id[maxSubLength];
    signal input sub_length_ascii;
    signal input sub_length_b64;

    signal input payload_start_index;
    signal input sub_claim_index_b64;
    ASCIISubstrExistsInB64(
        inCount,
        maxSubLength
    )(
        b64Str <== content,
        BIndex <== sub_claim_index_b64,
        lenB <== sub_length_b64,
        A <== subject_id,
        lenA <== sub_length_ascii,
        payloadIndex <== payload_start_index
    );

    /**
     3. Calculate commitment to subject_id
    **/
    signal input subject_pin;
    signal subject_id_com <== Poseidon(2)([subject_id[0], subject_pin]); // To fix

    /** 
      4. Masking 
    **/
    signal input mask[inCount];
    signal masked_content[inCount];

    for(var i = 0; i < inCount; i++) {
        // Ensure mask is binary
        mask[i] * (1 - mask[i]) === 0;
        // If mask is 0, then replace with '=' (ASCII 61) to avoid conflicts with base64 characters
        masked_content[i] <== content[i] * mask[i] + (1 - mask[i]) * 61;
    }

    var outWidth = 253;
    var inBits = inCount * inWidth;
    var outCount = inBits \ outWidth;
    if (inBits % outWidth != 0) {
        outCount++;
    }

    signal packed[outCount] <== Packer(inWidth, inCount, outWidth, outCount)(masked_content);
    signal masked_content_hash <== Hasher(outCount)(packed);

    /**
     5. Calculate nonce
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
       6. Misc checks: 
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
       7. Hash all signals revealed to the verifier outside
    **/
    signal input all_inputs_hash;
    signal all_inputs_hash_actual <== Poseidon(11)([
        jwt_sha2_hash[0],
        jwt_sha2_hash[1],
        masked_content_hash,
        payload_start_index,
        payload_len,
        eph_public_key[0],
        eph_public_key[1],
        max_epoch,
        nonce,
        num_sha2_blocks,
        subject_id_com
    ]);
    all_inputs_hash === all_inputs_hash_actual;

}