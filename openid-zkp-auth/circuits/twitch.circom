pragma circom 2.0.0;

include "jwt_proof_ua.circom";

component main {
    public [all_inputs_hash]
} = JwtProofUA(64*8, 21);