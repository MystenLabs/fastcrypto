pragma circom 2.1.3;

include "helpers/sha256.circom";
include "helpers/misc.circom";
include "helpers/strings.circom";
include "helpers/hasher.circom";

template NonceChecker(extNonceLength, nonceBitLen) {
    signal input expected_nonce;
    signal expected_bits[nonceBitLen] <== Num2BitsBE(nonceBitLen)(expected_nonce);

    signal input actual_extended_nonce[extNonceLength];

    // Checks on prefix
    actual_extended_nonce[0] === 34; // '"'
    actual_extended_nonce[1] === 110; // 'n'
    actual_extended_nonce[2] === 111; // 'o'
    actual_extended_nonce[3] === 110; // 'n'
    actual_extended_nonce[4] === 99; // 'c'
    actual_extended_nonce[5] === 101; // 'e'
    actual_extended_nonce[6] === 34; // '"'
    actual_extended_nonce[7] === 58; // ':'
    actual_extended_nonce[8] === 34; // '"'

    // Checks on last char
    var lastchar = actual_extended_nonce[extNonceLength - 1];
    (lastchar - 44) * (lastchar - 125) === 0; // lastchar = ',' or '}'

    // Checks on last but one char
    var lastbutone = actual_extended_nonce[extNonceLength - 2];
    lastbutone === 34;

    var value[extNonceLength - 11];
    for (var i = 0; i < extNonceLength - 11; i++) {
        value[i] = actual_extended_nonce[i + 9];
    }

    signal actual_bits[6 * (extNonceLength - 11)] <== MultiBase64URLToBits(extNonceLength - 11)(value);

    assert(6 * (extNonceLength - 11) >= nonceBitLen);
    for (var i = 0; i < nonceBitLen; i++) {
        expected_bits[i] === actual_bits[i];
    }
}

/**
JWT Proof: User-agnostic (UA) circuit

Constraints (rough): (maxContentLength/64)*30k + maxContentLength * (maxSubLength + maxNonceLength)
The first term is incurred by Sha2_wrapper and the second term is incurred by Slice.

    Construction params:
    - maxContentLength:         Maximum length of the JWT + SHA2 padding in bytes. Must be a multiple of 64.
    - maxSubLength:             Maximum length of the extended_sub (in ascii)

    Private Inputs:
    - content[inCount]:         X in bytes where X is the 
                                decoded JWT header + decoded JWT payload + SHA-2 padding + zeroes

    - extended_sub[maxSubLength]: The subject (user) ID for the first sub_length_ascii characters and 0s for the rest
    - sub_length_ascii:         Length of the extended_sub in ASCII, e.g., for ',"sub":12345,' it is 13
    - sub_claim_index_b64:      The index of extended_sub encoded into Base64 in the JWT payload
    - sub_length_b64:           The length of extended_sub in Base64
    - subject_pin:              A 128-bit PIN to keep the extended_sub private

    - extended_nonce[maxNonceLength]: The nonce for the first nonce_length_ascii characters and 0s for the rest
    - nonce_claim_index_b64:    The index of extended_nonce encoded into Base64 in the JWT payload
    - nonce_length_b64:         The length of extended_nonce in Base64

    - mask[inCount]:            A binary mask over X, i.e., mask[i] = 0 or 1
    - jwt_randomness:           A 128-bit random number to keep the sensitive parts of JWT hidden.

    Circuit signals revealed to the verifier along with the ZK proof:
    - jwt_sha2_hash:            The SHA2 hash of the JWT header + JWT payload + SHA-2 padding
    - num_sha2_blocks:          Number of SHA2 (64-byte) blocks the SHA2-padded JWT consumes
    - subject_id_com:           H(extended_sub || PIN). A binding and hiding commitment to extended_sub
    - payload_start_index:      The index of the payload in the content
    - payload_len:              The length of the payload
    - masked_content:           The content with "iss" and "aud" claims revealed. Rest of it is masked
    - eph_public_key[2]:        The ephemeral public key split into two 128-bit values
    - max_epoch:                The maximum epoch for which the eph_public_key is valid

    Public Inputs:
    - all_inputs_hash:          H(jwt_sha2_hash[2] || masked_content_hash || payload_start_index || payload_len
                                  eph_public_key[2] || max_epoch || num_sha2_blocks || subject_id_com)

Notes:
- nonce = H(nonce_preamble || eph_public_key || max_epoch || jwt_randomness)
*/
template JwtProofUA(maxContentLength, maxSubLength) {
    var inWidth = 8; // input is in bytes
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
     2. Checks on extended_sub
        a) Is it in the JWT payload?
        b) Is extended_sub[i] == 0 for all i >= sub_length_ascii?
        c) Is extended_sub[sub_length_ascii - 1] == ',' or '}'?

    Note that the OpenID standard permits extended_sub to be any valid JSON member. 
    But the below logic is more restrictive: it assumes that the exact same string is 
        returned by the server every time the user logs in.
    */
    var subInWidth = 8;
    signal input extended_sub[maxSubLength];
    signal input sub_length_ascii; // Check if we ensure it is >= 1 and <= maxSubLength

    signal input sub_claim_index_b64;
    signal input sub_length_b64;

    signal input payload_start_index;
    ASCIISubstrExistsInB64(
        inCount,
        maxSubLength
    )(
        b64Str <== content,
        BIndex <== sub_claim_index_b64,
        lenB <== sub_length_b64,
        A <== extended_sub,
        lenA <== sub_length_ascii,
        payloadIndex <== payload_start_index
    );

    // extended_sub[i] == 0 for all i >= sub_length_ascii
    signal sigt[maxSubLength] <== GTBitVector(maxSubLength)(sub_length_ascii);
    for (var i = 0; i < maxSubLength; i++) {
        sigt[i] * extended_sub[i] === 0;
    }

    signal lastchar <== SingleMultiplexer(maxSubLength)(extended_sub, sub_length_ascii - 1);
    (lastchar - 44) * (lastchar - 125) === 0; // lastchar = ',' or '}'

    /**
     3. Calculate commitment to extended_sub. We exclude the last character of the extended_sub
        because it is either ',' or '}'.
    **/
    // exclude last character
    signal extended_sub_without_last_char[maxSubLength] <== Slice(maxSubLength, maxSubLength)(
        extended_sub, 
        0,
        sub_length_ascii - 1
    );

    // pack
    var outWidth = 253; // field prime is 254 bits
    var subOutCount = getPackedOutputSize(maxSubLength * subInWidth, outWidth);
    signal packed_subject_id[subOutCount] <== Packer(subInWidth, maxSubLength, outWidth, subOutCount)(extended_sub_without_last_char);
    signal subject_id_hash <== Hasher(subOutCount)(packed_subject_id);

    signal input subject_pin;
    component size_checker_1 = Num2Bits(128);
    size_checker_1.in <== subject_pin; // ensure it is 16 bytes

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
     5. Checks on extended_nonce
        a) Is it in the JWT payload? 
        b) Calculate nonce from public key, epoch, and randomness
        c) Check that nonce appears in extended_nonce
    **/
    var extNonceLength = 43 + 11; // 43 for Base64 encoding of 256 bits + 11 for prefix and suffix

    // 5a) Is it in the JWT payload?
    signal input extended_nonce[extNonceLength];

    signal input nonce_claim_index_b64;
    signal input nonce_length_b64;

    ASCIISubstrExistsInB64(
        inCount,
        extNonceLength
    )(
        b64Str <== content,
        BIndex <== nonce_claim_index_b64,
        lenB <== nonce_length_b64,
        A <== extended_nonce,
        lenA <== extNonceLength,
        payloadIndex <== payload_start_index
    );

    // 5b) Calculate nonce
    signal input eph_public_key[2];
    signal input max_epoch;
    signal input jwt_randomness;
    component size_checker_2 = Num2Bits(128);
    size_checker_2.in <== jwt_randomness; // ensure it is 16 bytes

    var nonce_preamble = 1;
    signal nonce <== Hasher(5)([
        nonce_preamble,
        eph_public_key[0],
        eph_public_key[1],
        max_epoch,
        jwt_randomness
    ]);

    // 5c) Check that nonce appears in extended_nonce
    NonceChecker(extNonceLength, 256)(
        expected_nonce <== nonce,
        actual_extended_nonce <== extended_nonce
    );

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
    signal all_inputs_hash_actual <== Hasher(10)([
        jwt_sha2_hash[0],
        jwt_sha2_hash[1],
        masked_content_hash,
        payload_start_index,
        payload_len,
        eph_public_key[0],
        eph_public_key[1],
        max_epoch,
        num_sha2_blocks,
        subject_id_com
    ]);
    all_inputs_hash === all_inputs_hash_actual;
}