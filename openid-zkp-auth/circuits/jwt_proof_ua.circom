pragma circom 2.1.3;

include "helpers/sha256.circom";
include "helpers/misc.circom";
include "helpers/strings.circom";
include "helpers/hasher.circom";

/**
JWT Proof: User-agnostic (UA) circuit

    Construction params:
    - maxContentLength:         Maximum length of the JWT + SHA2 padding in bytes
    - maxSubLength:             Maximum length of the subject_id (in ascii)

    Private Inputs:
    - content[inCount]:         Segments of X as inWidth bit chunks where X is the 
                                    decoded JWT header + decoded JWT payload + SHA-2 padding + zeroes
    - sub_length_ascii:         Length of the subject_id in ASCII, e.g., for ',"sub":12345,' it is 13
    - subject_id[maxSubLength]: The subject (user) ID for the first sub_length_ascii characters and 0s for the rest
    - subject_pin:              A 128-bit PIN to keep the subject_id private
    - mask[inCount]:            A binary mask over X, i.e., mask[i] = 0 or 1
    - jwt_randomness:           A 128-bit random number to keep the sensitive parts of JWT hidden

    Circuit signals revealed to the verifier along with the ZK proof:
    - jwt_sha2_hash:            The SHA2 hash of the JWT header + JWT payload + SHA-2 padding
    - num_sha2_blocks:          Number of SHA2 (64-byte) blocks the SHA2-padded JWT consumes
    - subject_id_com:           H(subject_id || PIN). A binding and hiding commitment to subject_id
    - payload_start_index:      The index of the payload in the content
    - payload_len:              The length of the payload
    - masked_content:           The content with the sensitive parts masked
    - eph_public_key[2]:        The ephemeral public key split into two 128-bit values
    - max_epoch:                The maximum epoch for which the eph_public_key is valid

    Public Inputs:
    - all_inputs_hash:          H(jwt_sha2_hash[2] || masked_content_hash || payload_start_index || payload_len
                                  eph_public_key[2] || max_epoch || nonce || num_sha2_blocks || subject_id_com)
*/
template JwtProofUA(maxContentLength, maxSubLength) {
    // Input is Base64 characters encoded as ASCII
    var inWidth = 8;
    var inCount = maxContentLength;
    signal input content[inCount];

    /**
     1. SHA2(content)
    */
    signal input num_sha2_blocks;
    var hashCount = 2;
    var hashWidth = 256 / hashCount;
    signal jwt_sha2_hash[hashCount] <== Sha2_wrapper(inWidth, inCount, hashWidth, hashCount)(
        content, 
        num_sha2_blocks
    );

    /**
     2. Checks on subject_id
        a) Is it in the JWT payload?
        b) Is subject_id[i] == 0 for all i >= sub_length_ascii?
        c) Is subject_id[sub_length_ascii - 1] == ',' or '}'?
    */
    var subInWidth = 8;
    signal input subject_id[maxSubLength];
    signal input sub_length_ascii; // Check if we ensure it is >= 1 and <= maxSubLength
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

    // subject_id[i] == 0 for all i >= sub_length_ascii
    signal sigt[maxSubLength] <== GTBitVector(maxSubLength)(sub_length_ascii);
    for (var i = 0; i < maxSubLength; i++) {
        sigt[i] * subject_id[i] === 0;
    }

    signal lastchar <== SingleMultiplexer(maxSubLength)(subject_id, sub_length_ascii - 1);
    (lastchar - 44) * (lastchar - 125) === 0; // lastchar = ',' or '}'

    /**
     3. Calculate commitment to subject_id. We exclude the last character of the subject_id
        because it is either ',' or '}'.
    **/
    // exclude last character
    signal subject_id_without_last_char[maxSubLength] <== Slice(maxSubLength, maxSubLength)(
        subject_id, 
        0,
        sub_length_ascii - 1
    );

    // pack
    var outWidth = 253; // field prime is 254 bits
    var subOutCount = getPackedOutputSize(maxSubLength * subInWidth, outWidth);
    signal packed_subject_id[subOutCount] <== Packer(subInWidth, maxSubLength, outWidth, subOutCount)(subject_id_without_last_char);
    signal subject_id_hash <== Hasher(subOutCount)(packed_subject_id);

    signal input subject_pin;
    subject_pin ==> Num2Bits(128); // ensure it is 16 bytes

    signal subject_id_com <== Hasher(2)([subject_id_hash, subject_pin]);

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

    var outCount = getPackedOutputSize(inCount * inWidth, outWidth);
    signal packed[outCount] <== Packer(inWidth, inCount, outWidth, outCount)(masked_content);
    signal masked_content_hash <== Hasher(outCount)(packed);

    /**
     5. Calculate nonce
    **/
    signal input eph_public_key[2];
    signal input max_epoch;
    signal input jwt_randomness;
    jwt_randomness ==> Num2Bits(128); // ensure it is 16 bytes

    signal nonce <== Hasher(4)([
        eph_public_key[0], 
        eph_public_key[1], 
        max_epoch, 
        jwt_randomness
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
    signal all_inputs_hash_actual <== Hasher(11)([
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