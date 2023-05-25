const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const expect = chai.expect;

const constants = require('../js/src/common').constants;
const utils = require('../js/src/utils');
const testutils = require("./testutils");

describe("Key claim checks", () => {
    var circuit;
    const maxExtLength = constants.maxExtClaimLen;
    const maxKeyClaimNameLen = constants.maxKeyClaimNameLen;
    const maxKeyClaimValueLen = constants.maxKeyClaimValueLen;

    before(async () => {
        circuit = await testutils.genMain(
            path.join(__dirname, "../circuits/helpers", "jwtchecks.circom"), "KeyClaimChecker", [
                maxExtLength, maxKeyClaimNameLen, maxKeyClaimValueLen, 248
            ]
        );
        await circuit.loadSymbols();
    });

    it("Sub", async () => {
        const keyClaimName = "sub";
        const keyClaimValue = "1234";
        const keyClaimExt = `"${keyClaimName}":"${keyClaimValue}",`;
        console.log(keyClaimExt);

        const inputs = {
            "extended_claim": utils.padWithZeroes(keyClaimExt.split('').map(c => c.charCodeAt()), maxExtLength),
            "extended_claim_len": keyClaimExt.length,
            "name_len": keyClaimName.length,
        };

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);

        const x = testutils.getWitnessValue(witness, circuit.symbols, "main.claim_name_F");
        const y = testutils.getWitnessValue(witness, circuit.symbols, "main.claim_value_F");

        expect(x).equals(await utils.mapToField(keyClaimName, maxKeyClaimNameLen, constants.packWidth));
        expect(y).equals(await utils.mapToField(keyClaimValue, maxKeyClaimValueLen, constants.packWidth));
    })

    it("Email", async () => {
        const keyClaimName = "email";
        const keyClaimValue = "abcdefgh@gmail.com";
        const keyClaimExt = `"${keyClaimName}":"${keyClaimValue}"}`;
        console.log(keyClaimExt);

        const inputs = {
            "extended_claim": utils.padWithZeroes(keyClaimExt.split('').map(c => c.charCodeAt()), maxExtLength),
            "extended_claim_len": keyClaimExt.length,
            "name_len": keyClaimName.length,
        };

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);

        const x = testutils.getWitnessValue(witness, circuit.symbols, "main.claim_name_F");
        const y = testutils.getWitnessValue(witness, circuit.symbols, "main.claim_value_F");

        expect(x).equals(await utils.mapToField(keyClaimName, maxKeyClaimNameLen, constants.packWidth));
        expect(y).equals(await utils.mapToField(keyClaimValue, maxKeyClaimValueLen, constants.packWidth));
    })

    // TODO: Add failing tests

    // TODO: Add tests for corner cases: extended_claim_len = maxExtLength, ...
})