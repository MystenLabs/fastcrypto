pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/gates.circom";
include "../node_modules/circomlib/circuits/mux2.circom";

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

template isEqualIfEnabled(n) {
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

// 00 => 0, 1, 2, 3
// 01 => 1, 2, 3, 0
// 10 => 2, 3, 0, 1
// 11 => 3, 0, 1, 2
template ExpandInitialOffsets() {
    signal input in[2];
    signal output out[4];

    in[0] * (1 - in[0]) === 0; // Check the first bit is 0 or 1
    in[1] * (1 - in[1]) === 0; // Check the second bit is 0 or 1

    component M = MultiMux2(3);
    M.s[0] <== in[0];
    M.s[1] <== in[1];

    M.c[0] <== [1, 2, 3, 0];
    M.c[1] <== [2, 3, 0, 1];
    M.c[2] <== [3, 0, 1, 2];

    out[0] <== 2 * in[1] + in[0];
    out[1] <== M.out[0];
    out[2] <== M.out[1];
    out[3] <== M.out[2];
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

// Returns in[offset:offset+outSize]
// Cost: O(inSize * outSize)
template SliceFixed(inSize, outSize) {
    signal input in[inSize];
    signal input offset;
    
    signal output out[outSize];
    
    component selector[outSize];
    component eqs[inSize][outSize];
    for(var i = 0; i < outSize; i++) {
        selector[i] = CalculateTotal(inSize);
        
        for(var j = 0; j < inSize; j++) {
            eqs[j][i] = IsEqual();
            eqs[j][i].in[0] <== j;
            eqs[j][i].in[1] <== offset + i;
            
            selector[i].nums[j] <== eqs[j][i].out * in[j];
        }

        out[i] <== selector[i].sum;
    }
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