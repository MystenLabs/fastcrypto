pragma circom 2.0.0;

include "jwt_proof.circom";

component main {
    public [hash, out, payloadIndex, ephPubKey, maxEpoch, nonce]
} = JwtProof(448);
