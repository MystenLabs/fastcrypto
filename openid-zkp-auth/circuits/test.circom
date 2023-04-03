pragma circom 2.0.0;

include "misc.circom";
include "sha256.circom";

template Dummy() {
    signal input in[2];

    log(in[0]);
    log(in[1]);
    in[0] === in[1];
}