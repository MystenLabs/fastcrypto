pragma circom 2.1.3;

include "misc.circom";

function asciiToBase64Url(i) {
    var base64 = 0;
    if (i >= 65 && i <= 90) { // A to Z
        base64 = i - 65;
    } else if (i >= 97 && i <= 122) { // a to z
        base64 = i - 71;
    } else if (i >= 48 && i <= 57) { // 0 to 9
        base64 = i + 4;
    } else if (i == 45) { // -
        base64 = 62;
    } else if (i == 95) { // _
        base64 = 63;
    }
    return base64;
}

/**
Takes as input a base64url character and outputs the corresponding 6-bit value. 
If not a valid base64 character, outputs 0.

Cost: 73 constraints

- in:   The base64url character. Assumed to be a 8-bit number, i.e., in [0, 256)
        NOTE: Behavior is undefined otherwise.
- out:  The 6-bit value
*/
template Base64URLToBits() {
    signal input in;
    signal output out[6];

    signal outascii;
    outascii <-- asciiToBase64Url(in);

    component lt91;
    lt91 = LessThan(8);
    lt91.in[0] <== in;
    lt91.in[1] <== 91;

    component gt64;
    gt64 = GreaterThan(8);
    gt64.in[0] <== in;
    gt64.in[1] <== 64;

    component forceequal1;
    forceequal1 = MyForceEqualIfEnabled();
    forceequal1.enabled <== lt91.out * gt64.out;
    forceequal1.in[0] <== outascii;
    forceequal1.in[1] <== in - 65;

    component lt123;
    lt123 = LessThan(8);
    lt123.in[0] <== in;
    lt123.in[1] <== 123;

    component gt96;
    gt96 = GreaterThan(8);
    gt96.in[0] <== in;
    gt96.in[1] <== 96;

    component forceequal2;
    forceequal2 = MyForceEqualIfEnabled();
    forceequal2.enabled <== lt123.out * gt96.out;
    forceequal2.in[0] <== outascii;
    forceequal2.in[1] <== in - 71;

    component lt58;
    lt58 = LessThan(8);
    lt58.in[0] <== in;
    lt58.in[1] <== 58;

    component gt47;
    gt47 = GreaterThan(8);
    gt47.in[0] <== in;
    gt47.in[1] <== 47;

    component forceequal3;
    forceequal3 = MyForceEqualIfEnabled();
    forceequal3.enabled <== lt58.out * gt47.out;
    forceequal3.in[0] <== outascii;
    forceequal3.in[1] <== in + 4;

    component eq45;
    eq45 = IsEqual();
    eq45.in[0] <== in;
    eq45.in[1] <== 45;

    component forceequal4;
    forceequal4 = MyForceEqualIfEnabled();
    forceequal4.enabled <== eq45.out;
    forceequal4.in[0] <== outascii;
    forceequal4.in[1] <== 62;

    component eq95;
    eq95 = IsEqual();
    eq95.in[0] <== in;
    eq95.in[1] <== 95;

    component forceequal5;
    forceequal5 = MyForceEqualIfEnabled();
    forceequal5.enabled <== eq95.out;
    forceequal5.in[0] <== outascii;
    forceequal5.in[1] <== 63;

    // Note: any = 0 happens only if all the enabled signals are 0. 
    //  This is because all the enabled signals are guaranteed to be either 0 or 1.
    var any = 1 - (forceequal1.enabled + forceequal2.enabled + forceequal3.enabled + forceequal4.enabled + forceequal5.enabled);

    component forceequal6;
    forceequal6 = MyForceEqualIfEnabled();
    forceequal6.enabled <== any;
    forceequal6.in[0] <== outascii;
    forceequal6.in[1] <== 0;

    component convert = Num2BitsBE(6);
    convert.in <== outascii;
    for (var i = 0; i < 6; i++) {
        out[i] <== convert.out[i];
    }
}

template MultiBase64URLToBits(n) {
    signal input in[n];
    signal output out[n * 6];

    for (var i = 0; i < n; i++) {
        var bits[6] = Base64URLToBits()(in[i]);
        for (var j = 0; j < 6; j++) {
            out[i * 6 + j] <== bits[j];
        }
    }
}