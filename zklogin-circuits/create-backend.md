# Steps to create a back-end service that returns zkLogin proofs

1. Follow the instructions given at https://github.com/mskd12/rapidsnark#compile-prover-in-server-mode  and https://github.com/mskd12/rapidsnark#launch-prover-in-server-mode. You'd also need to copy the zklogin.dat file along with the binary to the `build` folder.

2. Currently, the code above assumes that fastcrypto is cloned at `~`. (See https://github.com/mskd12/rapidsnark/blob/main/src/fullprover.cpp#L120)

3. Set LD_LIBRARY_PATH appropriately before running the `proverServer` binary. The required file is in depends. So if rapidsnark was installed at `~`, then you'd need to set `export LD_LIBRARY_PATH=/home/ubuntu/rapidsnark/depends/pistache/build/src/` and then run `export $LD_LIBRARY_PATH`
