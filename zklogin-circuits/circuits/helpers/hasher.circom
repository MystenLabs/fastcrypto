pragma circom 2.1.3;

include "../../node_modules/circomlib/circuits/poseidon.circom";

template Hasher(nInputs) {
    signal input in[nInputs];
    signal output out;

    component pos1, pos2;
    // See https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom#L78. 
    // It implicitly forces t <= 17 or nInputs <= 16. 
    // TODO: The current limitation of 15 comes from the rust library we use (https://github.com/Lightprotocol/light-poseidon).
    if (nInputs <= 15) {
        out <== Poseidon(nInputs)(in);
    } else if (nInputs <= 30) {
        pos1 = Poseidon(15);
        pos2 = Poseidon(nInputs - 15);

        for (var i = 0; i < 15; i++) {
            pos1.inputs[i] <== in[i];
        }
        for (var i = 15; i < nInputs; i++) {
            pos2.inputs[i - 15] <== in[i];
        }

        out <== Poseidon(2)([
            pos1.out,
            pos2.out
        ]);
    } else { // Yet to be implemented
        1 === 0;
    }
}