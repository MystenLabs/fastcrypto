pragma circom 2.1.3;

include "strings.circom";
include "misc.circom";
include "hasher.circom";

/**
Checks that the key claim is well formed.

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

    // Checks on prefix
    extended_claim[0] === 34; // '"'
    signal name[maxClaimNameLen] <== Slice(maxExtLength, maxClaimNameLen)(
        in <== extended_claim,
        index <== 1,
        length <== name_len
    );
    var nameOutCount = getPackedOutputSize(maxClaimNameLen * inWidth, packWidth);
    signal packed_claim_name[nameOutCount] <== Packer(inWidth, maxClaimNameLen, packWidth, nameOutCount)(name);
    signal output claim_name_F <== Hasher(nameOutCount)(packed_claim_name);

    // Checks on middle
    signal postnamechar <== SingleMultiplexer(maxExtLength)(extended_claim, name_len + 1);
    postnamechar === 34; // '"'

    signal nameseperator <== SingleMultiplexer(maxExtLength)(extended_claim, name_len + 2);
    nameseperator === 58; // ':'

    signal prevaluechar <== SingleMultiplexer(maxExtLength)(extended_claim, name_len + 3);
    prevaluechar === 34; // '"'

    signal value[maxClaimValueLen];
    value <== Slice(maxExtLength, maxClaimValueLen)(
        in <== extended_claim,
        index <== name_len + 4,
        length <== extended_claim_len - name_len - 6
    );
    var valueOutCount = getPackedOutputSize(maxClaimValueLen * inWidth, packWidth);
    signal packed_claim_value[valueOutCount] <== Packer(inWidth, maxClaimValueLen, packWidth, valueOutCount)(value);
    signal output claim_value_F <== Hasher(valueOutCount)(packed_claim_value);

    // extended_claim[i] == 0 for all i >= extended_claim_len
    signal sigt[maxExtLength] <== GTBitVector(maxExtLength)(extended_claim_len);
    for (var i = 0; i < maxExtLength; i++) {
        sigt[i] * extended_claim[i] === 0;
    }

    // Checks on last but one char
    signal postvaluechar <== SingleMultiplexer(maxExtLength)(extended_claim, extended_claim_len - 2);
    postvaluechar === 34; // '"'

    signal lastchar <== SingleMultiplexer(maxExtLength)(extended_claim, extended_claim_len - 1);
    (lastchar - 44) * (lastchar - 125) === 0; // lastchar = ',' or '}'
}

template NonceChecker(extNonceLength, nonceBitLen) {
    assert(extNonceLength > 0);
    assert(nonceBitLen > 0);

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