# zkLogin circuits

Install via `npm install`

## Filetree Description

```bash
circuits/
    jwt_proof_ua.circom # Main circuit code
    zklogin.circom # Circom runner
    helpers/
        base64.circom
        hasher.circom
        jwtchecks.circom
        misc.circom
        sha256.circom
        strings.circom
js/
    circuitutils.js # Circuit utilities
    constants.js # Circuit params
    decideparams.js # A script to decide circuit params based on real JWTs
    jwtutils.js # JWT utilities
    prove.js # Helper script to run the ZKP using a given zkey, vkey, JWT
    utils.js # Generic utilities
    verify.js
test/
    testutils.js # Test utilities
    xyz.circom.test.js # testing circom code
    abc.test.js # testing js code
testvectors/
    realJWTs.js # Real JWTs
    sampleWalletInputs.json
    sampleZKPInputs.json
```

## Steps to generate a OpenID signature (using snarkJS prover)

1. Create a folder named `artifacts` inside `openid-zkp-auth`.

```
cd fastcrypto/openid-zkp-auth && mkdir artifacts
```

2. Get pre-generated trusted setup and place it inside `artifacts`.

```
cd artifacts && wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau
```

3. Generate R1CS and witness generator (WASM): 

```
cd ../ && circom circuits/zklogin.circom --r1cs --wasm --output artifacts

# maybe need
npm install
```

4. Run circuit-specific trusted setup: `cd artifacts && snarkjs groth16 setup zklogin.r1cs powersOfTau28_hez_final_20.ptau zklogin.zkey`

5. Export verification key: `snarkjs zkey export verificationkey zklogin.zkey zklogin.vkey`

6. Create a folder named `proof` inside the `artifacts` directory. Generate a OpenID signature: ``npm run prove <provider> <jwt>``. The last two arguments are optional. `provider` can be either `google` (default) or `twitch`. Default JWTs for both are in `testvectors/realJWTs.js`.

It generates three files: the zk proof (`zkp.proof`), auxiliary inputs to the verifier (`aux.json`) and public inputs to the ZKP (`public.json`) inside the `proof` folder.

## Tests

``npm test``

# Steps to create a back-end service that returns zkLogin proofs

1. Follow the instructions given at https://github.com/mskd12/rapidsnark#compile-prover-in-server-mode  and https://github.com/mskd12/rapidsnark#launch-prover-in-server-mode. You'd also need to copy the zklogin.dat file along with the binary to the `build` folder.

2. Currently, the code above assumes that fastcrypto is cloned at `~`. (See https://github.com/mskd12/rapidsnark/blob/main/src/fullprover.cpp#L120)

3. Set LD_LIBRARY_PATH appropriately before running the `proverServer` binary. The required file is in depends. So if rapidsnark was installed at `~`, then you'd need to set `export LD_LIBRARY_PATH=/home/ubuntu/rapidsnark/depends/pistache/build/src/` and then run `export $LD_LIBRARY_PATH`

# Steps to access the back-end

After installing the module, simply run the command: `node tools/request.js <walletInputs.json> zklogin`. The inputs JSON file has the following format:

```
struct {
    jwt: String,
    eph_public_key: String,
    max_epoch: Number,
    jwt_rand: String,
    user_pin: String,
    key_claim_name: String
}
```

An example is in `testvectors/sampleWalletInputs.json`.