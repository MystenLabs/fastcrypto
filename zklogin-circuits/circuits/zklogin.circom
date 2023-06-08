pragma circom 2.1.3;

include "zkloginMain.circom";

component main {
    public [all_inputs_hash]
} = ZKLogin(64*12, 66, 10);