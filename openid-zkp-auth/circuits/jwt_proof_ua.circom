pragma circom 2.1.3;

include "helpers/sha256.circom";
include "helpers/misc.circom";
include "helpers/strings.circom";
include "helpers/hasher.circom";
include "helpers/jwtchecks.circom";

/**
JWT Proof: User-agnostic (UA) circuit

Constraints (rough): (maxContentLength/64)*30k + maxContentLength * (maxExtKeyClaimLength + maxNonceLength)
The first term is incurred by Sha2_wrapper and the second term is incurred by Slice.

    Construction params:
    - maxContentLength:         Maximum length of the JWT + SHA2 padding in bytes. Must be a multiple of 64.
    - maxExtKeyClaimLength:     Maximum length of the extended_key_claim (in ascii)

    Private Inputs:
    - content[inCount]:         X in bytes where X is the 
                                decoded JWT header + decoded JWT payload + SHA-2 padding + zeroes

    - extended_key_claim[maxExtKeyClaimLength]: 
                                The claim name and value for the first claim_length_ascii characters and 0s for the rest
    - claim_length_ascii:       Length of the extended_key_claim in ASCII, e.g., for ',"sub":12345,' it is 13
    - claim_index_b64:          The index of extended_key_claim encoded into Base64 in the JWT payload
    - claim_length_b64:         The length of extended_key_claim in Base64
    - subject_pin:              A 128-bit PIN to keep the extended_key_claim private

    - extended_nonce[maxNonceLength]: 
                                The nonce for the first nonce_length_ascii characters and 0s for the rest
    - nonce_claim_index_b64:    The index of extended_nonce encoded into Base64 in the JWT payload
    - nonce_length_b64:         The length of extended_nonce in Base64

    - mask[inCount]:            A binary mask over X, i.e., mask[i] = 0 or 1
    - jwt_randomness:           A 128-bit random number to keep the sensitive parts of JWT hidden.

    Circuit signals revealed to the verifier along with the ZK proof:
    - jwt_sha2_hash:            The SHA2 hash of the JWT header + JWT payload + SHA-2 padding
    - num_sha2_blocks:          Number of SHA2 (64-byte) blocks the SHA2-padded JWT consumes
    - key_claim_name_F:         MapToField(key_claim_name)  
    - address_seed:             Poseidon([value, PIN]). It will be used to derive 
                                    subject_addr = Blake2b(flag, iss, key_claim_name_F, address_seed)
    - payload_start_index:      The index of the payload in the content
    - payload_len:              The length of the payload
    - masked_content:           The content with "iss" and "aud" claims revealed. Rest of it is masked
    - eph_public_key[2]:        The ephemeral public key split into two 128-bit values
    - max_epoch:                The maximum epoch for which the eph_public_key is valid

    Public Inputs:
    - all_inputs_hash:          H(jwt_sha2_hash[2] || masked_content_hash || payload_start_index || payload_len
                                  eph_public_key[2] || max_epoch || num_sha2_blocks || key_claim_name_F || address_seed)

Notes:
- nonce = Poseidon([eph_public_key, max_epoch, jwt_randomness])
*/
template JwtProofUA(maxContentLength, maxExtKeyClaimLength, maxKeyClaimNameLen) {
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
     2. Checks on extended_key_claim
        a) Is it in the JWT payload?
        b) Is extended_key_claim[i] == 0 for all i >= claim_length_ascii?
        c) Is the prefix and suffix of extended_key_claim well-formed?

    Note that the OpenID standard permits extended_key_claim to be any valid JSON member. 
    But the below logic is more restrictive: it assumes that the exact same string is 
        returned by the server every time the user logs in.
    */
    var subInWidth = 8;
    signal input extended_key_claim[maxExtKeyClaimLength];
    signal input claim_length_ascii; // Check if we ensure it is >= 1 and <= maxExtKeyClaimLength

    signal input claim_index_b64;
    signal input claim_length_b64;

    signal input payload_start_index;
    ASCIISubstrExistsInB64(
        inCount,
        maxExtKeyClaimLength
    )(
        b64Str <== content,
        BIndex <== claim_index_b64,
        lenB <== claim_length_b64,
        A <== extended_key_claim,
        lenA <== claim_length_ascii,
        payloadIndex <== payload_start_index
    );

    signal input key_claim_name_length;
    var packWidth = 248; // largest 8 multiple <= 254
    var maxClaimValueLen = maxExtKeyClaimLength - maxKeyClaimNameLen - 6;

    signal key_claim_name_F, key_claim_value_F;
    (key_claim_name_F, key_claim_value_F) <== KeyClaimChecker(maxExtKeyClaimLength, maxKeyClaimNameLen, maxClaimValueLen, packWidth)(
        extended_key_claim, claim_length_ascii, key_claim_name_length
    );

    /**
     3. Derive address from extended_key_claim. We exclude its last character because it can be either ',' or '}'.
    **/
    signal input subject_pin;
    signal address_seed <== Hasher(2)([
        key_claim_value_F, subject_pin
    ]);

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

    var outCount = getPackedOutputSize(inCount * inWidth, packWidth);
    signal packed[outCount] <== Packer(inWidth, inCount, packWidth, outCount)(masked_content);
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

    signal nonce <== Hasher(4)([
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
    signal all_inputs_hash_actual <== Hasher(11)([
        jwt_sha2_hash[0],
        jwt_sha2_hash[1],
        masked_content_hash,
        payload_start_index,
        payload_len,
        eph_public_key[0],
        eph_public_key[1],
        max_epoch,
        num_sha2_blocks,
        key_claim_name_F,
        address_seed
    ]);
    all_inputs_hash === all_inputs_hash_actual;
}