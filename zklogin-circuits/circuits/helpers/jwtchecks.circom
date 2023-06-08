pragma circom 2.1.3;

include "strings.circom";
include "misc.circom";
include "hasher.circom";

template StringChecker(maxLen) {
    signal input str[maxLen];
    signal input len;

    // first char is a quote
    str[0] === 34; // '"'

    // last char is a quote
    signal last_quote <== SingleMultiplexer(maxLen)(str, len - 1);
    last_quote === 34; // '"'

    // str[i] == 0 for all i >= len
    signal sigt[maxLen] <== GTBitVector(maxLen)(len - 1);
    for (var i = 0; i < maxLen; i++) {
        sigt[i] * str[i] === 0;
    }
}

template isWhitespace() {
    signal input c;

    signal is_space <== IsEqual()([c, 0x20]); // 0x20 = decimal 32
    signal is_tab <== IsEqual()([c, 0x09]); // 0x09 = decimal 9
    signal is_newline <== IsEqual()([c, 0x0A]); // 0x0A = decimal 10 
    signal is_carriage_return <== IsEqual()([c, 0x0D]); // 0x0D = decimal 13

    signal output is_whitespace <== is_space + is_tab + is_newline + is_carriage_return;
}

/**
ExtendedClaimParser

string ws : ws value ws E
     |    |    |   |    |
     n    c    vs  ve   l => n = name_len, c = ':', vs = value_start, ve = value_end, l = length
**/
template ExtendedClaimParser(maxExtendedClaimLen, maxKeyClaimNameLen, maxKeyClaimValueLen) {
    assert(maxExtendedClaimLen > 0);
    assert(maxKeyClaimNameLen > 0);
    assert(maxKeyClaimValueLen > 0);
    assert(maxExtendedClaimLen == maxKeyClaimNameLen + maxKeyClaimValueLen + 2); // +2 for colon and comma/brace

    // TODO: Add range checks for all inputs
    signal input extended_claim[maxExtendedClaimLen];
    signal input length;

    signal input name_len;
    signal input colon_index;
    signal input value_start;
    signal input value_len;

    signal output name[maxKeyClaimNameLen] <== Slice(maxExtendedClaimLen, maxKeyClaimNameLen)(
        extended_claim,
        0,
        name_len
    );
    // Is name a valid JSON string? (All JSON keys are strings)
    StringChecker(maxKeyClaimNameLen)(name, name_len); 

    signal output value[maxKeyClaimValueLen] <== Slice(maxExtendedClaimLen, maxKeyClaimValueLen)(
        extended_claim,
        value_start,
        value_len
    );
    // Is value a valid JSON string?
    StringChecker(maxKeyClaimValueLen)(value, value_len);
    // NOTE: In theory, JSON values need not be strings. But we only use this parser for parsing strings, so this is fine.

    // Whitespaces
    signal is_whitespace[maxExtendedClaimLen];
    for (var i = 0; i < maxExtendedClaimLen; i++) {
        is_whitespace[i] <== isWhitespace()(extended_claim[i]);
    }

    signal is_gt_n[maxExtendedClaimLen] <== GTBitVector(maxExtendedClaimLen)(name_len - 1);
    signal is_lt_c[maxExtendedClaimLen] <== LTBitVector(maxExtendedClaimLen)(colon_index);
    signal selector1[maxExtendedClaimLen] <== vectorAND(maxExtendedClaimLen)(is_gt_n, is_lt_c);
    for (var i = 0; i < maxExtendedClaimLen; i++) {
        selector1[i] * (1 - is_whitespace[i]) === 0;
    }

    signal is_gt_c[maxExtendedClaimLen] <== GTBitVector(maxExtendedClaimLen)(colon_index);
    signal is_lt_vs[maxExtendedClaimLen] <== LTBitVector(maxExtendedClaimLen)(value_start);
    signal selector2[maxExtendedClaimLen] <== vectorAND(maxExtendedClaimLen)(is_gt_c, is_lt_vs);
    for (var i = 0; i < maxExtendedClaimLen; i++) {
        selector2[i] * (1 - is_whitespace[i]) === 0;
    }

    signal is_gt_ve[maxExtendedClaimLen] <== GTBitVector(maxExtendedClaimLen)(value_start + value_len - 1);
    signal is_lt_l[maxExtendedClaimLen] <== LTBitVector(maxExtendedClaimLen)(length - 1);
    signal selector3[maxExtendedClaimLen] <== vectorAND(maxExtendedClaimLen)(is_gt_ve, is_lt_l);
    for (var i = 0; i < maxExtendedClaimLen; i++) {
        selector3[i] * (1 - is_whitespace[i]) === 0;
    }

    // Colon is at index colon_index
    signal colon <== SingleMultiplexer(maxExtendedClaimLen)(extended_claim, colon_index);
    colon === 58; // ':'

    // Last char is either end-brace or comma
    signal last_char <== SingleMultiplexer(maxExtendedClaimLen)(extended_claim, length - 1);
    (last_char - 125) * (last_char - 44) === 0; // '}' or ','
}

/**
NonceChecker: Checks that the extended claim string representing nonce is valid.
    a) The first 9 chars are '"nonce":"'
    b) The last two chars are '"}' or '",'
    c) The chars in between are base64url encoded bits of the nonce

Construction Params:
    nonceValueLength: length of the extended claim string representing nonce
    nonceBitLen: length of the nonce in bits
**/
template NonceChecker(nonceValueLength, nonceBitLen) {
    assert(nonceValueLength > 0);
    assert(nonceBitLen > 0);

    signal input expected_nonce;
    signal expected_bits[nonceBitLen] <== Num2BitsBE(nonceBitLen)(expected_nonce);

    signal input actual_nonce[nonceValueLength];

    // first char is a quote
    actual_nonce[0] === 34; // '"'

    // last char is a quote
    actual_nonce[nonceValueLength - 1] === 34; // '"'

    // Remove the 9 character prefix and two character suffix to get the actual nonce
    var nonceLength = nonceValueLength - 2;
    var value[nonceLength];
    for (var i = 0; i < nonceLength; i++) {
        value[i] = actual_nonce[i + 1];
    }

    // Convert the base64url encoded nonce to bits
    signal actual_bits[6 * nonceLength] <== MultiBase64URLToBits(nonceLength)(value);

    // Check every bit of expected nonce against the actual nonce
    assert(6 * nonceLength >= nonceBitLen);
    for (var i = 0; i < nonceBitLen; i++) {
        expected_bits[i] === actual_bits[i];
    }
}
