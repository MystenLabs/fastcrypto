# zkLogin circuits

Install via `tsc` and `npm install`

## Filetree Description

```bash
circuits/
    zklogin.circom # Main circuit code
    zklogin_wrapper.circom # Circom runner
    helpers/
        base64.circom
        hasher.circom
        jwtchecks.circom
        misc.circom
        sha256.circom
        strings.circom
src/
    circuitutils.ts # Circuit utilities
    constants.ts # Circuit params
    decideparams.ts # A script to decide circuit params based on real JWTs
    jwtutils.ts # JWT utilities
    prove.ts # Helper script to run the ZKP using a given zkey, vkey, JWT
    utils.ts # Generic utilities
    verify.ts
test/
    testutils.js # Test utilities
    xyz.circom.test.js # testing circom code
    abc.test.js # testing js code
testvectors/
    realJWTs.ts # Real JWTs
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

``tsc; npm test``

# Steps to access the back-end

The back-end takes `WalletInputs` as input and returns `PartialZKLoginSig`. Both these structs are defined in `src/common.ts`.

## Example via cURL

```
1. cd testvectors
2. curl -X POST -H "Content-Type: application/json" -d @./sampleWalletInputs.json http://185.209.177.123:8000/zkp
```

Note that the command reads the `WalletInputs` from the JSON file `testvectors/sampleWalletInputs.json`.
