pragma circom 2.0.0;

include "sha256.circom";
include "misc.circom";

// There are broadly two implementation strategies (we take the first as it minimizes ZK comp): 
// 1) Input the Base64 encoded JWT, which can be directly input to SHA-2, but 
//    the mask is imperfect. In particular, some bits of the neighboring character 
//    might be output depending on the location.
// 2) Or input the decoded JWT as input which will make the mask perfect,
//    but wed have to convert it into Base64 before hashing.

/*
JWT Proof
    Takes message content segmented into inWidth chunks and calculates a SHA256 hash, for which an RSA signature is known,
    as well as masking the content to obscure private fields.

    Construction Parameters:
    - inCount:          Number of content inputs of inWidth size

    Inputs:
    - content[inCount]: Segments of JWT as inWidth bit chunks
    - tBlock:           At which 512-bit block to select output hash
    - payloadB64Offset[2]: An offset in the range [0, 3] that when incremented (mod 4) ensures that payload starts at 0.
    - mask[inCount]:    Binary mask of JWT segments
    
    Outputs:
    - hash:             SHA256 hash output truncated to hashWidth bits
    - out[inCount]:     Masked content
*/
template JwtProof(inCount) {
    // Input is Base64 characters encoded as ASCII
    var inWidth = 8;
    // Segments must divide evenly into 512 bit blocks
    assert((inCount * inWidth) % 512 == 0);
    assert(inWidth <= 512);
    assert(512 % inWidth == 0);
    
    var inBits = inCount * inWidth;
    
    // The number of content segments, times the bit width of each is the bit length of the content.
    // The content is decomposed to 512-bit blocks for SHA-256
    var nBlocks = (inCount * inWidth) / 512;
    
    // How many segments are in each block
    var nSegments = 512 / inWidth;
    
    // JWT header + JWT payload + SHA-2 padding
    signal input content[inCount];
    signal input tBlock;    
    signal output hash[256];
    
    /** #1) SHA-256 **/
    component sha256 = Sha256_unsafe(nBlocks);
    component sha256_blocks[nBlocks][nSegments];
    
    // For each 512-bit block going into SHA-256
    for(var b = 0; b < nBlocks; b++) {
        // For each segment going into that block
        for(var s = 0; s < nSegments; s++) {
            // The index from the content is offset by the block we're composing times the number of segments per block,
            // s is then the segment offset within the block.
            var payloadIndex = (b * nSegments) + s;
            
            // Decompose each segment into an array of individual bits
            sha256_blocks[b][s] = Num2BitsLE(inWidth);
            sha256_blocks[b][s].in <== content[payloadIndex];
            
            // The bit index going into the current SHA-256 block is offset by the segment number times the bit width
            // of each content segment. sOffset + i is then the bit offset within the block (0-511).
            var sOffset = s * inWidth;
            for(var i = 0; i < inWidth; i++) {
                sha256.in[b][sOffset + i] <== sha256_blocks[b][s].out[i];
            }
        }
    }
    sha256.tBlock <== tBlock;
    // TODO: Add a check to verify that everything after tBlock is zero.

    for (var i = 0; i < 256; i++) {
        hash[i] <== sha256.out[i];
    }

    signal input payloadB64Offset[2]; // payloadB64Offset[0] is the MSB
    component X = ExpandInitialOffsets();
    X.in[0] <== payloadB64Offset[0];
    X.in[1] <== payloadB64Offset[1];

    signal b64offsets[inCount];
    for (var i = 0; i < inCount; i++) { // TODO: Check that offsets[payloadOffset] is 0
        if (i < 4) {
            b64offsets[i] <== X.out[i];
        } else {
            b64offsets[i] <== b64offsets[i % 4];
        }
    }

    /** 
        #2) sub claim checks 
            2a) Ensures "sub" only appears once (~40k constraints)
            2b) checks the userID (~40k constraints)
        
        Check 2a can be omitted if we can assume that "sub" only appears once.
    **/
    var subKeyLength = 8;
    var subValueLength = 32;

    // ',"sub":'
    var subClaim[3][subKeyLength] = [
        // LCJzdWIi => 4c434a7a64574969 => 0x4c, 0x43, 0x4a, 0x7a, 0x64, 0x57, 0x49, 0x69 => (decimal) 76, 67, 74, 122, 100, 87, 73, 105
        [76, 67, 74, 122, 100, 87, 73, 105], // Appears at 0
        // wic3ViIj => 7769633a53756249
        [119, 105, 99, 51, 86, 105, 73, 106], // Appears at 2
        // InN1YiI6 => 496e4e3159694936
        [73, 110, 78, 49, 89, 105, 73, 54] // Appears at 0
    ];

    // ,"sub":"117912735658541336646",
    var subValue[3][subValueLength] = [
        // LCJzdWIi OiIxMTc5MTI3MzU2NTg1NDEzMzY2NDYi
        [79, 105,  73, 120, 77,  84, 99,  53, 77,  84,  73,  51, 77, 122, 85, 50,
         78,  84, 103,  49, 78,  68, 69, 122, 77, 122,  89,  50, 78,  68, 89, 105],
        // wic3ViIj oiMTE3OTEyNzM1NjU4NTQxMzM2NjQ2Ii
        [111, 105, 77,  84, 69,  51, 79,  84, 69, 121, 78, 122, 77,  49, 78, 106,
         85,  52, 78,  84, 81, 120, 77, 122, 77,  50, 78, 106, 81,  50, 73, 105],
        // InN1YiI6 IjExNzkxMjczNTY1ODU0MTMzNjY0NiIs
        [73, 106, 69, 120, 78, 122, 107, 120, 77, 106, 99, 122, 78,  84,  89,  49, 
         79,  68, 85,  48, 77,  84,  77, 122, 78, 106, 89,  48, 78, 105,  73, 115]
    ];

    component subEQCheck[inCount][3];
    component b64OffsetCheck[inCount][2];

    // Check 2a begins. Cost: O(subKeyLength * inCount)
    var accumulate[3] = [0, 0, 0];
    var subValueOffset;
    for (var i = 0; i < inCount - subKeyLength - subValueLength; i++) { // TODO: Extend it to enable these checks only in [payloadB64Offset, payloadB64Offset + payloadLength]
        // Check if LCJzdWIi is at 0 b64offset
        b64OffsetCheck[i][0] = IsEqual();
        b64OffsetCheck[i][0].in[0] <== b64offsets[i];
        b64OffsetCheck[i][0].in[1] <== 0;

        subEQCheck[i][0] = isEqualIfEnabled(subKeyLength);
        subEQCheck[i][0].enabled <== b64OffsetCheck[i][0].out;

        for (var j = 0; j < subKeyLength; j++) {
            var idx = i + j;
            subEQCheck[i][0].in[0][j] <== content[idx];
            subEQCheck[i][0].in[1][j] <== subClaim[0][j];
        }

        // Check if wic3ViIj is at 2 b64offset
        b64OffsetCheck[i][1] = IsEqual();
        b64OffsetCheck[i][1].in[0] <== b64offsets[i];
        b64OffsetCheck[i][1].in[1] <== 2;

        subEQCheck[i][1] = isEqualIfEnabled(subKeyLength);
        subEQCheck[i][1].enabled <== b64OffsetCheck[i][1].out;

        for (var j = 0; j < subKeyLength; j++) {
            var idx = i + j;
            subEQCheck[i][1].in[0][j] <== content[idx];
            subEQCheck[i][1].in[1][j] <== subClaim[1][j];
        }

        // Check if InN1YiI6 is at 0 b64offset
        subEQCheck[i][2] = isEqualIfEnabled(subKeyLength);
        subEQCheck[i][2].enabled <== b64OffsetCheck[i][0].out; // reuse

        for (var j = 0; j < subKeyLength; j++) {
            var idx = i + j;
            subEQCheck[i][2].in[0][j] <== content[idx];
            subEQCheck[i][2].in[1][j] <== subClaim[2][j];
        }

        subValueOffset += (i + subKeyLength) * (subEQCheck[i][0].out + subEQCheck[i][1].out + subEQCheck[i][2].out);

        accumulate[0] += subEQCheck[i][0].out;
        accumulate[1] += subEQCheck[i][1].out;
        accumulate[2] += subEQCheck[i][2].out;
        // log(i, b64offsets[i], accumulate[0], accumulate[1], accumulate[2]);
    }

    accumulate[0] + accumulate[1] + accumulate[2] === 1; // Adding at most 3*inCount bits, so no concern of wrapping around

    // Check 2b begins.
    component subExtractor = SliceFixed(inCount, subValueLength);
    for (var i = 0; i < inCount; i++) {
        subExtractor.in[i] <== content[i];
    }
    subExtractor.offset <== subValueOffset;
    for (var i = 0; i < subValueLength; i++) {
        subExtractor.out[i] === subValue[0][i] * accumulate[0] + subValue[1][i] * accumulate[1] + subValue[2][i] * accumulate[2];
    }

    /** 
        #3) Masking 
        Cost: (1k constraints) (2*inCount) 
    **/
    signal input mask[inCount];
    signal output out[inCount];

    for(var i = 0; i < inCount; i++) {
        mask[i] * (1 - mask[i]) === 0; // Ensure mask is binary
        out[i] <== content[i] * mask[i];
    }
}
