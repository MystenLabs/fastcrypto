pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/sha256/constants.circom";
include "../node_modules/circomlib/circuits/sha256/sha256compression.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "misc.circom";

/*
SHA256 Unsafe
    Calculates the SHA256 hash of the input, using a signal to select the output round corresponding to the number of
    non-empty input blocks. This implementation is referred to as "unsafe", as it relies upon the caller to ensure that
    the input is padded correctly, and to ensure that the tBlock input corresponds to the actual terminating data block.
    Crafted inputs could result in Length Extension Attacks.

    Construction Parameters:
    - nBlocks: Maximum number of 512-bit blocks for payload input
    
    Inputs:
    - in:     An array of blocks exactly nBlocks in length, each block containing an array of exactly 512 bits.
              Padding of the input according to RFC4634 Section 4.1 is left to the caller.
              Blocks following tBlock must be supplied, and *should* contain all zeroes
    - tBlock: An integer corresponding to the terminating block of the input, which contains the message padding
    
    Outputs:
    - out:    An array of 256 bits corresponding to the SHA256 output as of the terminating block
*/
template Sha256_unsafe(nBlocks) {
    signal input in[nBlocks][512];
    signal input tBlock;
    
    signal output out[256];

    component ha0 = H(0);
    component hb0 = H(1);
    component hc0 = H(2);
    component hd0 = H(3);
    component he0 = H(4);
    component hf0 = H(5);
    component hg0 = H(6);
    component hh0 = H(7);

    component sha256compression[nBlocks];

    for(var i = 0; i < nBlocks; i++) {
        sha256compression[i] = Sha256compression();
        if (i==0) {
            for(var k = 0; k < 32; k++) {
                sha256compression[i].hin[0*32+k] <== ha0.out[k];
                sha256compression[i].hin[1*32+k] <== hb0.out[k];
                sha256compression[i].hin[2*32+k] <== hc0.out[k];
                sha256compression[i].hin[3*32+k] <== hd0.out[k];
                sha256compression[i].hin[4*32+k] <== he0.out[k];
                sha256compression[i].hin[5*32+k] <== hf0.out[k];
                sha256compression[i].hin[6*32+k] <== hg0.out[k];
                sha256compression[i].hin[7*32+k] <== hh0.out[k];
            }
        } else {
            for(var k = 0; k < 32; k++) {
                sha256compression[i].hin[32*0+k] <== sha256compression[i-1].out[32*0+31-k];
                sha256compression[i].hin[32*1+k] <== sha256compression[i-1].out[32*1+31-k];
                sha256compression[i].hin[32*2+k] <== sha256compression[i-1].out[32*2+31-k];
                sha256compression[i].hin[32*3+k] <== sha256compression[i-1].out[32*3+31-k];
                sha256compression[i].hin[32*4+k] <== sha256compression[i-1].out[32*4+31-k];
                sha256compression[i].hin[32*5+k] <== sha256compression[i-1].out[32*5+31-k];
                sha256compression[i].hin[32*6+k] <== sha256compression[i-1].out[32*6+31-k];
                sha256compression[i].hin[32*7+k] <== sha256compression[i-1].out[32*7+31-k];
            }
        }

        for (var k = 0; k < 512; k++) {
            sha256compression[i].inp[k] <== in[i][k];
        }
    }
    
    // Collapse the hashing result at the terminating data block
    // A modified Quin Selector allows us to select the block based on the tBlock signal
    component calcTotal[256];
    component eqs[nBlocks];

    // Generate a bit vector of size nBlocks, where the bit corresponding to tBlock is raised
    for (var i = 0; i < nBlocks; i++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== i;
        eqs[i].in[1] <== tBlock - 1;
    }

    // For each bit of the output
    for(var k = 0; k < 256; k++) {
        calcTotal[k] = CalculateTotal(nBlocks);

        // For each possible block
        for (var i = 0; i < nBlocks; i++) {
            // eqs[i].out is 1 if the index matches. As such, at most one input to calcTotal is not 0.
            // The bit corresponding to the terminating data block will be raised
            calcTotal[k].nums[i] <== eqs[i].out * sha256compression[i].out[k];
        }
        out[k] <== calcTotal[k].sum;
    }
}
