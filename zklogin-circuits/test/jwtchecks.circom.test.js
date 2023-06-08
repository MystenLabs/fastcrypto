const chai = require("chai");
const path = require("path");
const assert = chai.assert;

const params = require('../js/src/common').circuit_params;
const utils = require('../js/src/utils');
const testutils = require("./testutils");
const circuitutils = require("../js/src/circuitutils");

describe("Extended claim parser", () => {
    it("Without any whitespaces", async () => {
        const maxKeyClaimNameLenWithQuotes = 20;
        const maxKeyClaimValueLenWithQuotes = 30;
        const maxExtendedClaimLen = maxKeyClaimNameLenWithQuotes + maxKeyClaimValueLenWithQuotes + 2;
        const circuit = await testutils.genMain(
            path.join(__dirname, "../circuits/helpers", "jwtchecks.circom"), "ExtendedClaimParser", [
                maxExtendedClaimLen, maxKeyClaimNameLenWithQuotes, maxKeyClaimValueLenWithQuotes
            ]
        );
        await circuit.loadSymbols();

        const payload = JSON.stringify({
            'sub': '1234',
            'email': 'abcd@example.com',
            'name': 'John Doe'
        });

        const inputs = circuitutils.genExtClaimParserInputs(payload, "email", maxExtendedClaimLen);
        const witness = await circuit.calculateWitness(inputs, true);

        const parsed_name = testutils.getWitnessArray(witness, circuit.symbols, "main.name").map(Number);
        const parsed_value = testutils.getWitnessArray(witness, circuit.symbols, "main.value").map(Number);

        assert.deepEqual(parsed_name, utils.strToVec('"email"', maxKeyClaimNameLenWithQuotes));
        assert.deepEqual(parsed_value, utils.strToVec('"abcd@example.com"', maxKeyClaimValueLenWithQuotes));
    });

    it("With whitespaces, newlines and tabs", async () => {
        const maxKeyClaimNameLenWithQuotes = 20;
        const maxKeyClaimValueLenWithQuotes = 30;
        const maxExtendedClaimLen = maxKeyClaimNameLenWithQuotes + maxKeyClaimValueLenWithQuotes + 2;
        const circuit = await testutils.genMain(
            path.join(__dirname, "../circuits/helpers", "jwtchecks.circom"), "ExtendedClaimParser", [
                maxExtendedClaimLen, maxKeyClaimNameLenWithQuotes, maxKeyClaimValueLenWithQuotes
            ]
        );
        await circuit.loadSymbols();

        const name = '"email"'; // name.length <= maxKeyClaimNameLenWithQuotes
        const value = '"abcd@example.com"'; // value.length <= maxKeyClaimValueLenWithQuotes
        const extended_claim = name + '   :   \n\t ' + value + '    ,';
        assert.isAtMost(extended_claim.length, maxExtendedClaimLen);
        const inputs = {
            "extended_claim": utils.padWithZeroes(extended_claim.split('').map(c => c.charCodeAt()), maxExtendedClaimLen),
            "name_len": name.length,
            "colon_index": extended_claim.indexOf(':'),
            "value_start": extended_claim.indexOf(value),
            "value_len": value.length,
            "length": extended_claim.length,
        };

        const witness = await circuit.calculateWitness(inputs, true);
        await circuit.checkConstraints(witness);

        const parsed_name = testutils.getWitnessArray(witness, circuit.symbols, "main.name").map(Number);
        const parsed_value = testutils.getWitnessArray(witness, circuit.symbols, "main.value").map(Number);

        assert.deepEqual(parsed_name, utils.strToVec('"email"', maxKeyClaimNameLenWithQuotes));
        assert.deepEqual(parsed_value, utils.strToVec('"abcd@example.com"', maxKeyClaimValueLenWithQuotes));
    });

    // TODO: Add failing tests
    // TODO: Add tests for corner cases: extended_claim_len = maxExtLength, ...
});