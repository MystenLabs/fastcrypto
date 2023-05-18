pragma circom 2.1.3;

include "strings.circom";
include "misc.circom";
include "hasher.circom";

/**
KeyClaimChecker: Checks that the extended claim string representing a key claim is valid.
    a) extended_claim[0] == '"'
    b) Return extended_claim[1:1+name_len] as claim_name (mapped to a field element)
    c) extended_claim[name_len+1] == '"'
    d) extended_claim[name_len+2] == ':'
    e) extended_claim[name_len+3] == '"'
    f) Return extended_claim[name_len+4:extended_claim_len-2] as claim_value (mapped to a field element)
    g) extended_claim[extended_claim_len-2] == '"'
    h) extended_claim[extended_claim_len-1] == ',' or '}'
    i) extended_claim[i] == 0 for all i >= extended_claim_len

E.g., extended_claim = '"sub":"123456",00000', extended_claim_len = 15, name_len = 3
**/
template KeyClaimChecker(maxExtLength, maxClaimNameLen, maxClaimValueLen, packWidth) {
    assert(maxExtLength > 0);
    assert(maxClaimNameLen > 0);
    assert(maxClaimValueLen > 0);
    assert(packWidth > 0);
    assert(maxExtLength == maxClaimNameLen + maxClaimValueLen + 6); // four '"', one ':' and one ',' / '}'

    var inWidth = 8;

    signal input extended_claim[maxExtLength];
    signal input extended_claim_len;
    signal input name_len;

    // Checks on the first char
    extended_claim[0] === 34; // '"'

    // Extract claim name
    signal name[maxClaimNameLen] <== Slice(maxExtLength, maxClaimNameLen)(
        in <== extended_claim,
        index <== 1,
        length <== name_len
    );
    var nameOutCount = getBaseConvertedOutputSize(maxClaimNameLen * inWidth, packWidth);
    signal packed_claim_name[nameOutCount] <== ConvertBase(inWidth, maxClaimNameLen, packWidth, nameOutCount)(name);
    signal output claim_name_F <== Hasher(nameOutCount)(packed_claim_name);

    // Checks on middle
    signal middle[3] <== SliceFixed(maxExtLength, 3)(
        in <== extended_claim,
        index <== name_len + 1
    );
    middle[0] === 34; // '"'
    middle[1] === 58; // ':'
    middle[2] === 34; // '"'

    // Extract claim value
    signal value[maxClaimValueLen];
    value <== Slice(maxExtLength, maxClaimValueLen)(
        in <== extended_claim,
        index <== name_len + 4,
        length <== extended_claim_len - name_len - 6
    );
    var valueOutCount = getBaseConvertedOutputSize(maxClaimValueLen * inWidth, packWidth);
    signal packed_claim_value[valueOutCount] <== ConvertBase(inWidth, maxClaimValueLen, packWidth, valueOutCount)(value);
    signal output claim_value_F <== Hasher(valueOutCount)(packed_claim_value);

    // extended_claim[i] == 0 for all i >= extended_claim_len
    signal sigt[maxExtLength] <== GTBitVector(maxExtLength)(extended_claim_len - 1);
    for (var i = 0; i < maxExtLength; i++) {
        sigt[i] * extended_claim[i] === 0;
    }

    // Checks on last two chars
    signal end[2] <== SliceFixed(maxExtLength, 2)(
        in <== extended_claim,
        index <== extended_claim_len - 2
    );
    end[0] === 34; // '"'
    (end[1] - 44) * (end[1] - 125) === 0; // lastchar = ',' or '}'
}

/**
NonceChecker: Checks that the extended claim string representing nonce is valid.
    a) The first 9 chars are '"nonce":"'
    b) The last two chars are '"}' or '",'
    c) The chars in between are base64url encoded bits of the nonce

Construction Params:
    extNonceLength: length of the extended claim string representing nonce
    nonceBitLen: length of the nonce in bits
**/
template NonceChecker(extNonceLength, nonceBitLen) {
    assert(extNonceLength > 0);
    assert(nonceBitLen > 0);

    signal input expected_nonce;
    signal expected_bits[nonceBitLen] <== Num2BitsBE(nonceBitLen)(expected_nonce);

    signal input actual_extended_nonce[extNonceLength];

    // Checks on prefix (first 9 chars)
    actual_extended_nonce[0] === 34; // '"'
    actual_extended_nonce[1] === 110; // 'n'
    actual_extended_nonce[2] === 111; // 'o'
    actual_extended_nonce[3] === 110; // 'n'
    actual_extended_nonce[4] === 99; // 'c'
    actual_extended_nonce[5] === 101; // 'e'
    actual_extended_nonce[6] === 34; // '"'
    actual_extended_nonce[7] === 58; // ':'
    actual_extended_nonce[8] === 34; // '"'

    // Checks on last but one char
    var lastbutone = actual_extended_nonce[extNonceLength - 2];
    lastbutone === 34; // '"'

    // Checks on last char
    var lastchar = actual_extended_nonce[extNonceLength - 1];
    (lastchar - 44) * (lastchar - 125) === 0; // lastchar = ',' or '}'

    // Remove the 9 character prefix and two character suffix to get the actual nonce
    var nonceLength = extNonceLength - 11;
    var value[nonceLength];
    for (var i = 0; i < nonceLength; i++) {
        value[i] = actual_extended_nonce[i + 9];
    }

    // Convert the base64url encoded nonce to bits
    signal actual_bits[6 * nonceLength] <== MultiBase64URLToBits(nonceLength)(value);

    // Check every bit of expected nonce against the actual nonce
    assert(6 * nonceLength >= nonceBitLen);
    for (var i = 0; i < nonceBitLen; i++) {
        expected_bits[i] === actual_bits[i];
    }
}