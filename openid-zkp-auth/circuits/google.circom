pragma circom 2.0.0;

include "jwt_proof.circom";

component main {public [ephPubKey, maxEpoch]} = JwtProof(448);
