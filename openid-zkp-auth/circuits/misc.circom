pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/gates.circom";
include "../node_modules/circomlib/circuits/mux2.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// Returns math.ceil(log2(a)). Assumes a > 0.
function log2(a) {
    if (a == 1) {
        return 0;
    }
    var n = 1;
    var r = 0;
    while (n < a) {
        n *= 2;
        r++;
    }
    return r;
}

template Num2BitsBE(n) {
    signal input in;
    signal output out[n];
    var lc1 = 0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        var b = (n - 1) - i;
        out[b] <-- (in >> i) & 1;
        out[b] * (out[b] - 1 ) === 0;
        lc1 += out[b] * e2;
        e2 = e2 + e2;
    }

    lc1 === in;
}

template Bits2NumBE(n) {
    signal input in[n];
    signal output out;
    var lc1=0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        lc1 += in[(n - 1) - i] * e2;
        e2 = e2 + e2;
    }

    lc1 ==> out;
}

template IsEqualIfEnabled(n) {
    signal input in[2][n];
    signal input enabled;
    signal output out;

    component isz[n];
    component and = MultiAND(n);

    for (var i = 0; i < n; i++) {
        isz[i] = IsZero();
        isz[i].in <== in[0][i] - in[1][i];
        and.in[i] <== isz[i].out;
    }
    
    out <== and.out * enabled;
}

// This circuit returns the sum of the inputs.
// n must be greater than 0.
// Cost: No constraints.
template CalculateTotal(n) {
    signal input nums[n];
    signal output sum;

    signal sums[n];
    sums[0] <== nums[0];

    for (var i = 1; i < n; i++) {
        sums[i] <== sums[i - 1] + nums[i];
    }

    sum <== sums[n - 1];
}

// TODO: Tests to be added.
/**
Packer: Packs a list of numbers into a list of numbers of a different size.
*/
template Packer(inWidth, inCount, outWidth, outCount) {
    signal input in[inCount];
    signal output out[outCount];

    var inBits = inCount * inWidth;
    var myOutCount = inBits \ outWidth;
    if (inBits % outWidth != 0) {
        myOutCount++;
    }
    assert(myOutCount == outCount);

    component expander[inCount];
    for (var i = 0; i < inCount; i++) {
        expander[i] = Num2BitsBE(inWidth);
        expander[i].in <== in[i];
    }

    component compressor[outCount];
    for (var i = 0; i < outCount; i++) {
        compressor[i] = Bits2NumBE(outWidth);
    }

    for(var i = 0; i < inBits; i++) {
        var oB = i % outWidth;
        var o = (i - oB) \ outWidth;

        var mB = i % inWidth;
        var m = (i - mB) \ inWidth;

        compressor[o].in[oB] <== expander[m].out[mB];
    }

    if (inBits % outWidth != 0) {
        var outExtra = inBits % outWidth;
        for(var i = outExtra; i < outWidth; i++) {
            compressor[outCount - 1].in[i] <== 0;
        }
    }

    for(var i = 0; i < outCount; i++) {
        out[i] <== compressor[i].out;
    }
}

template Hasher(nInputs) {
    signal input in[nInputs];
    signal output out;

    component pos1, pos2, pos3;
    if (nInputs <= 15) {
        pos1 = Poseidon(nInputs);
        for (var i = 0; i < nInputs; i++) {
            pos1.inputs[i] <== in[i];
        }
        out <== pos1.out;
    } else if (nInputs <= 30) {
        pos1 = Poseidon(15);
        pos2 = Poseidon(nInputs - 15);

        for (var i = 0; i < 15; i++) {
            pos1.inputs[i] <== in[i];
        }
        for (var i = 15; i < nInputs; i++) {
            pos2.inputs[i - 15] <== in[i];
        }

        pos3 = Poseidon(2);
        pos3.inputs[0] <== pos1.out;
        pos3.inputs[1] <== pos2.out;

        out <== pos3.out;
    } else { // Yet to be implemented
        1 === 0;
    }
}

template RemainderMod4() {
    signal input in;
    signal output out;

    out <-- in % 4;
    signal q <-- in \ 4;
    // TODO: Check if q is in range.

    4 * q + out === in;

    signal tmp1, tmp2;
    tmp1 <== (out - 3) * (out - 2);
    tmp2 <== tmp1 * (out - 1);
    tmp2 * out === 0;
}
