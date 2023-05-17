pragma circom 2.1.3;

include "../../node_modules/circomlib/circuits/sha256/constants.circom";
include "../../node_modules/circomlib/circuits/sha256/sha256compression.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "misc.circom";

/**
SHA256 Unsafe
    Calculates the SHA256 hash of the input, using a signal to select the output round corresponding to the number of
    non-empty input blocks. This implementation is referred to as "unsafe", as it relies upon the caller to ensure that
    the input is padded correctly, and to ensure that the num_sha2_blocks input corresponds to the actual terminating data block.
    Crafted inputs could result in Length Extension Attacks.

    Construction Parameters:
    - nBlocks: Maximum number of 512-bit blocks for payload input
    
    Inputs:
    - in:           An array of blocks exactly nBlocks in length, each block containing an array of exactly 512 bits.
                    Padding of the input according to RFC4634 Section 4.1 is left to the caller.
    - num_sha2_blocks:   A number representing the number of 64-byte blocks to consider from the input.
    
    Outputs:
    - out:          An array of 256 bits corresponding to the SHA256 output. 
                    We hash the blocks starting from in[0] upto in[num_sha2_blocks-1] (inclusive).
*/
template Sha256_unsafe(nBlocks) {
    signal input in[nBlocks][512];
    signal input num_sha2_blocks;
    
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
    component totals[256];
    signal eqs[nBlocks] <== OneBitVector(nBlocks)(num_sha2_blocks - 1);

    // For each bit of the output
    for(var k = 0; k < 256; k++) {
        totals[k] = Sum(nBlocks);

        // For each possible block
        for (var i = 0; i < nBlocks; i++) {
            // eqs[i].out is 1 if the index matches. As such, at most one input to totals is not 0.
            // The bit corresponding to the terminating data block will be raised
            totals[k].nums[i] <== eqs[i] * sha256compression[i].out[k];
        }
        out[k] <== totals[k].sum;
    }
}

/**
SHA2_Wrapper

    Calculates the SHA2 hash of an arbitrarily shaped input using SHA256_unsafe internally.
    Additionally, it packs the output and checks that all inputs after num_sha2_blocks are indeed 0.

    Construction Parameters:
    - inWidth:      Width of each input segment in bits
    - inCount:      Number of input segments

    Inputs:
    - in:           An array of segments exactly inCount in length, each segment containing an array of exactly inWidth bits.
                    Padding of the input according to RFC4634 Section 4.1 is left to the caller.
    - num_sha2_blocks:    An integer corresponding to the terminating block of the input, which contains the message padding.

    Outputs:
    - hash:         An array of size 2 corresponding to the SHA256 output as of the terminating block split into two.
                    The first element contains the first 128 bits of the hash, and the second element contains the last 128 bits.
*/
template Sha2_wrapper(inWidth, inCount, outWidth, outCount) {
    // Segments must divide evenly into 512 bit blocks
    var inBits = inCount * inWidth;
    assert(inBits % 512 == 0);

    signal input in[inCount];
    signal input num_sha2_blocks;

    assert(outWidth * outCount == 256);
    signal output hash[outCount];

    // The content is decomposed to 512-bit blocks for SHA-256
    var nBlocks = (inWidth * inCount) / 512;
    component sha256 = Sha256_unsafe(nBlocks);

    // How many segments are in each block
    assert(inWidth <= 512);
    assert(512 % inWidth == 0);
    var nSegments = 512 / inWidth;
    component sha256_blocks[nBlocks][nSegments];

    // For each 512-bit block going into SHA-256
    for (var b = 0; b < nBlocks; b++) {
        // For each segment going into that block
        for (var s = 0; s < nSegments; s++) {
            // The index from the content is offset by the block we're composing times the number of segments per block,
            // s is then the segment offset within the block.
            var payloadIndex = (b * nSegments) + s;
            
            // Decompose each segment into an array of individual bits
            sha256_blocks[b][s] = Num2BitsBE(inWidth);
            sha256_blocks[b][s].in <== in[payloadIndex];
            
            // The bit index going into the current SHA-256 block is offset by the segment number times the bit width
            // of each content segment. sOffset + i is then the bit offset within the block (0-511).
            var sOffset = s * inWidth;
            for (var i = 0; i < inWidth; i++) {
                sha256.in[b][sOffset + i] <== sha256_blocks[b][s].out[i];
            }
        }
    }
    sha256.num_sha2_blocks <== num_sha2_blocks;

    /**
        Pack the output of the SHA-256 hash into a vector of size outCount where each element has outWidth bits.
    **/
    component hash_packer[outCount];
    for (var i = 0; i < outCount; i++) {
        hash_packer[i] = Bits2NumBE(outWidth);
        for (var j = 0; j < outWidth; j++) {
            hash_packer[i].in[j] <== sha256.out[i * outWidth + j];
        }
        hash_packer[i].out ==> hash[i];
    }

    /**
        Verify that content[i] for all blocks >= num_sha2_blocks is zero.
    **/
    signal gte[nBlocks] <== GTBitVector(nBlocks)(num_sha2_blocks);

    for (var b = 0; b < nBlocks; b++) {
        for (var s = 0; s < nSegments; s++) {
            var payloadIndex = (b * nSegments) + s;
            gte[b] * in[payloadIndex] === 0;
        }
    }
}