pragma circom 2.0.0;

include "jwt_proof.circom";

component main {
    public [jwt_sha2_hash, masked_content_hash, payload_index, 
            eph_public_key, max_epoch, nonce]
} = JwtProof(
    448,
    [ // ',"sub":"117912735658541336646",'
    // LCJzdWIiOiIxMTc5MTI3MzU2NTg1NDEzMzY2NDYi
    [76, 67, 74, 122, 100, 87, 73, 105, 79, 105,  73, 120, 77,  84, 99,  53, 77,
      84,  73,  51, 77, 122, 85, 50, 78,  84, 103,  49, 78,  68, 69, 122, 77,
      122,  89,  50, 78,  68, 89, 105],
    // wic3ViIjoiMTE3OTEyNzM1NjU4NTQxMzM2NjQ2Ii
    [119, 105, 99, 51, 86, 105, 73, 106, 111, 105, 77,  84, 69,  51, 79,  84,
        69, 121, 78, 122, 77,  49, 78, 106, 85,  52, 78,  84, 81, 120, 77, 122,
        77,  50, 78, 106, 81,  50, 73, 105],
    // InN1YiI6IjExNzkxMjczNTY1ODU0MTMzNjY0NiIs
    [73, 110, 78, 49, 89, 105, 73, 54, 73, 106, 69, 120, 78, 122, 107, 120, 77,
        106, 99, 122, 78,  84,  89,  49, 79,  68, 85,  48, 77,  84,  77, 122,
        78, 106, 89,  48, 78, 105,  73, 115]
    ],
    40,
    [0, 2, 0]
);
