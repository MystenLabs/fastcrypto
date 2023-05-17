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
testvectors.js # Real JWTs
```

## Steps to generate the ZKP

1. Create a folder named `artifacts` inside `openid-zkp-auth`.

2. Get pre-generated trusted setup: wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau. Place it inside `artifacts`.

3. Generate R1CS and witness generator (WASM): `circom circuits/zklogin.circom --r1cs --wasm --output artifacts`

4. Run circuit-specific trusted setup: `snarkjs groth16 setup zklogin.r1cs powersOfTau28_hez_final_20.ptau zklogin.zkey`

5. Export verification key: `snarkjs zkey export verificationkey zklogin.zkey zklogin.vkey`

6. Create a folder named `proof` inside the `artifacts` directory. Generate a OpenID signature: ``npm run prove <provider> <jwt>``. The last two arguments are optional. `provider` can be either `google` (default) or `twitch`. Default JWTs for both are in `testvectors.js`.

It generates three files: the zk proof (`zkp.proof`), auxiliary inputs to the verifier (`aux.json`) and public inputs to the ZKP (`public.json`) inside the `proof` folder.

## Tests

``npm test``