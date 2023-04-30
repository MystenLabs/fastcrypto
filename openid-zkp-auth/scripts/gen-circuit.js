/** 
 * Given a powers of tau file and a JWT, this file generates a circuit + trusted setup for it
 * 
 * 1. Generates a circuit (circom file) based on the user's JWT 
 * 2. Generates a trusted setup for the circuit
 */ 

// TODO: Guess inCount based on the JWT
genCircuit = (async (jwt, inCount) => {
    const [_, payload, __] = jwt.split('.');
    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const sub_claim = utils.getClaimString(decoded_payload, "sub");
    const sub_in_b64 = utils.removeDuplicates(b64utils.getAllExtendedBase64Variants(sub_claim));

    const circuit = await test.genMain(
        path.join(__dirname, "..", "circuits", "jwt_proof.circom"),
        "JwtProof", [
            inCount, 
            sub_in_b64.map(e => e[0].split('').map(c => c.charCodeAt())),
            sub_in_b64.length, 
            sub_in_b64[0][0].length,
            sub_in_b64.map(e => e[1])
        ]
    );

    return circuit;
});

if (require.main === module) {

}