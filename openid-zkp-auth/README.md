# zkLogin circuits

Install via `npm install`

## Filetree Description

```bash
circuits/
    google.circom # Runner with Google's params
    jwt_proof_ua.circom # Starting file for circuit code
    twitch.circom # Runner with Twitch's params
    helpers/
        base64.circom
        misc.circom
        sha256.circom
        strings.circom
        zkhasher.circom
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

1. Create a folder named `google` inside `openid-zkp-auth`.

2. Get pre-generated trusted setup: wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_19.ptau. Place it inside `google`.

3. Generate R1CS and witness generator (WASM): `circom circuits/google.circom --r1cs --wasm --output google`

4. Run circuit-specific trusted setup: `snarkjs groth16 setup google.r1cs powersOfTau28_hez_final_19.ptau google.zkey`

5. Export verification key: `snarkjs zkey export verificationkey google.zkey google.vkey`

6. Generate a OpenID signature (with the default JWT): ``npm run prove``. It generates three files: the zk proof (`google.proof`), auxiliary inputs to the verifier (`aux.json`) and public inputs to the ZKP (`public.json`) inside the `google` folder.

The above steps can be repeated with `twitch` except you'd need to run ``npm run prove twitch``.

## Tests

``npm test``