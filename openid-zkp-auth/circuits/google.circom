pragma circom 2.0.0;

include "jwt_proof.circom";

component main {
    public [hash, out, ephPubKey, maxEpoch, nonce]
} = JwtProof(448);
