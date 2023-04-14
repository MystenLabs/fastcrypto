pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

template Hasher(nInputs) {
    signal input in[nInputs];
    signal output out;

    component pos1, pos2, pos3;
    if (nInputs <= 15) {
        pos1 = Poseidon(nInputs);
        for (var i = 0; i < nInputs; i++) {
            pos1.inputs[i] <== in[i];
        }
        out <== pos1.out;
    } else if (nInputs <= 30) {
        pos1 = Poseidon(15);
        pos2 = Poseidon(nInputs - 15);

        for (var i = 0; i < 15; i++) {
            pos1.inputs[i] <== in[i];
        }
        for (var i = 15; i < nInputs; i++) {
            pos2.inputs[i - 15] <== in[i];
        }

        pos3 = Poseidon(2);
        pos3.inputs[0] <== pos1.out;
        pos3.inputs[1] <== pos2.out;

        out <== pos3.out;
    } else { // Yet to be implemented
        1 === 0;
    }
}