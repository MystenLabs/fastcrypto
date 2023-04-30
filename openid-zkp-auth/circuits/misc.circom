pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/gates.circom";
include "../node_modules/circomlib/circuits/mux2.circom";
include "../node_modules/circomlib/circuits/multiplexer.circom";

/**
RemainderMod4: Calculates in % 4.

Construction Params:
    - n:  The bitwidth of in. 
                
Range checks:
    - 0 <= in < 2^n (Checked in Num2Bits)
**/
template RemainderMod4(n) {
    assert(n <= 252); // n <= log(p) - 2

    signal input in;
    signal output out;

    component toBits = Num2Bits(n);
    toBits.in <== in;
    out <== 2 * toBits.out[1] + toBits.out[0];
}


/**
RangeCheck: Checks if 0 <= in <= max.

Construction params:
    - n: The bitwidth of in and max.
    - max: The maximum value that in can take.

Range checks:
    - 0 <= in (Checked in Num2Bits)
    - in <= max
**/
template RangeCheck(n, max) {
    assert(n <= 252); // n <= log(p) - 2
    assert(max >= 0);
    assert(numBits(max) <= n);

    signal input in;
    var unusedVar[n] = Num2Bits(n)(in);

    signal leq <== LessEqThan(n)([in, max]);
    leq === 1;
}

// Returns the number of bits needed to represent a number.
// Helper function intended to operate only over construction params.
function numBits(a) {
    assert(a >= 0);
    if (a == 0 || a == 1) {
        return 1;
    }
    return 1 + numBits(a >> 1);
}

/**
Num2BitsBE: Converts a number to a list of bits, in big-endian order.

Range checks:
    - 0 <= in < 2^n (Like with Num2Bits).
**/
template Num2BitsBE(n) {
    assert(n <= 252); // n <= log(p) - 2

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

    component and = MultiAND(n);

    for (var i = 0; i < n; i++) {
        and.in[i] <== IsZero()(in[0][i] - in[1][i]);
    }
    
    out <== and.out * enabled;
}

// Optimized version of the official ForceEqualIfEnabled
template MyForceEqualIfEnabled() {
    signal input enabled;
    signal input in[2];

    (in[1] - in[0]) * enabled === 0;
}

template ForceEqualIfEnabledMulti(n) {
    signal input enabled;
    signal input in[2][n];

    for (var i = 0; i < n; i++) {
        MyForceEqualIfEnabled()(enabled, [in[0][i], in[1][i]]);
    }
}

template CalculateTotal(n) {
    signal input nums[n];
    signal output sum;

    var lc;
    for (var i = 0; i < n; i++) {
        lc += nums[i];
    }
    sum <== lc;
}

// out[i] = 1 if i = index, 0 otherwise.
// Assumes index in [0, n). Fails otherwise.
template OneBitVector(n) {
    signal input index;
    signal output out[n];

    component X = Decoder(n);
    X.inp <== index;

    X.success === 1;
    out <== X.out;
}

// out[i] = 1 if i >= index, 0 otherwise
// Assumes index in [0, n). Fails otherwise.
template GTBitVector(n) {
    signal input index;
    signal output out[n];

    signal eq[n] <== OneBitVector(n)(index);

    out[0] <== eq[0];
    for (var i = 1; i < n; i++) {
        out[i] <== eq[i] + out[i - 1];
    }
}

// out[i] = 1 if i < index, 0 otherwise
// Assumes index in [0, n]. Fails otherwise.
template LTBitVector(n) {
    signal input index;
    signal output out[n];

    signal eq[n + 1] <== OneBitVector(n + 1)(index);

    out[n-1] <== eq[n];
    for (var i = n-2; i >= 0; i--) {
        out[i] <== eq[i + 1] + out[i + 1];
    }
}

template SingleMultiplexer(nIn) {
    signal input inp[nIn];
    signal input sel;
    signal output out;

    component dec = OneBitVector(nIn);
    sel ==> dec.index;
    EscalarProduct(nIn)(inp, dec.out) ==> out;
}

/**
Packer: Packs a list of numbers, each of a specified bitwidth, 
        into another list of numbers with a different bitwidth.

- inWidth: The bitwidth of each input number.
- inCount: The number of input numbers.
- outWidth: The bitwidth of each output number.
- outCount: The number of output numbers. (Should be inCount * inWidth / outWidth, rounded up.)
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