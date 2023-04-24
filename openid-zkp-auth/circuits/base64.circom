pragma circom 2.0.0;

include "misc.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

function asciiToBase64Url(i) {
    var base64 = 0;
    if (i >= 65 && i <= 90) {
        base64 = i - 65;
    } else if (i >= 97 && i <= 122) {
        base64 = i - 71;
    } else if (i >= 48 && i <= 57) {
        base64 = i + 4;
    } else if (i == 45) {
        base64 = 62;
    } else if (i == 95) {
        base64 = 63;
    }
    return base64;
}

/**
Takes as input a base64url character and outputs the corresponding 6-bit value. 
Fails if not a valid base64url character.

    - in: The base64url character (assumed to be 8 bits)
    - out: The 6-bit value
*/
template B64URLToBits() {
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
    forceequal1 = ForceEqualIfEnabled();
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
    forceequal2 = ForceEqualIfEnabled();
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
    forceequal3 = ForceEqualIfEnabled();
    forceequal3.enabled <== lt58.out * gt47.out;
    forceequal3.in[0] <== outascii;
    forceequal3.in[1] <== in + 4;

    component eq45;
    eq45 = IsEqual();
    eq45.in[0] <== in;
    eq45.in[1] <== 45;

    component forceequal4;
    forceequal4 = ForceEqualIfEnabled();
    forceequal4.enabled <== eq45.out;
    forceequal4.in[0] <== outascii;
    forceequal4.in[1] <== 62;

    component eq95;
    eq95 = IsEqual();
    eq95.in[0] <== in;
    eq95.in[1] <== 95;

    component forceequal5;
    forceequal5 = ForceEqualIfEnabled();
    forceequal5.enabled <== eq95.out;
    forceequal5.in[0] <== outascii;
    forceequal5.in[1] <== 63;

    (forceequal1.enabled + forceequal2.enabled + forceequal3.enabled + forceequal4.enabled + forceequal5.enabled) === 1;

    component convert = Num2BitsBE(6);
    convert.in <== outascii;
    for (var i = 0; i < 6; i++) {
        out[i] <== convert.out[i];
    }
}

template MultiB64URLToBits(n) {
    signal input in[n];
    signal output out[n * 6];

    component base64[n];
    for (var i = 0; i < n; i++) {
        base64[i] = B64URLToBits();
        base64[i].in <== in[i];
        for (var j = 0; j < 6; j++) {
            out[i * 6 + j] <== base64[i].out[j];
        }
    }
}

// template oldBase64ToASCIIBits() {
//     {
//         component eq[128];
//         component force[128];
//         var x;
//         for (var i = 0; i < 128; i++) {
//             if ((i >= 65 && i <= 90) || (i >= 97 && i <= 122) || (i >= 48 && i <= 57) || (i == 43) || (i == 47)) {
//                 eq[i] = IsEqual();
//                 eq[i].in[0] <== in;
//                 eq[i].in[1] <== i;

//                 force[i] = ForceEqualIfEnabled();
//                 force[i].enabled <== eq[i].out;
//                 force[i].in[0] <== outascii;
//                 force[i].in[1] <== asciiToBase64(i);
//                 x += eq[i].out;
//             }
//         }

//         component eqfinal;
//         eqfinal = IsEqual();
//         eqfinal.in[0] <== x;
//         eqfinal.in[1] <== 0;

//         component forcefinal;
//         forcefinal = ForceEqualIfEnabled();
//         forcefinal.enabled <== eqfinal.out;
//         forcefinal.in[0] <== outascii;
//         forcefinal.in[1] <== 0;

//     }
// }
