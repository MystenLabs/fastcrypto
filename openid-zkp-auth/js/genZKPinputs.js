#!/usr/bin/env node

// Given front-end (wallet) inputs, generate the inputs to the ZKP circuit and the auxiliary inputs to the Authenticator.

const fs = require('fs');

const circuit = require("./circuitutils");
const utils = require("./utils");
const constants = require("./constants");
const claimsToReveal = constants.claimsToReveal;

function readJsonFile(filename) {
    try {
        if (!fs.existsSync(filename)) {
            throw new Error(`File doesn't exist: ${filename}`);
        }

        let rawdata = fs.readFileSync(filename);
        let jsonData = JSON.parse(rawdata);

        // Validate JSON structure
        const requiredFields = ['jwt', 'eph_public_key', 'max_epoch', 'jwt_rand', 'user_pin', 'key_claim_name'];
        for (let field of requiredFields) {
            if (!jsonData.hasOwnProperty(field)) {
                throw new Error(`Missing required field: ${field}`);
            }
        }
        return jsonData;
    } catch (err) {
        console.error(`Error reading or parsing JSON file: ${err.message}`);
        process.exit(1);  // Exit with failure status
    }
}

const genZKPInputs = async (jwt, ephPK, maxEpoch, jwtRand, userPIN, keyClaim='sub', ZKP_INPUTS_FILE_PATH, AUX_INPUTS_FILE_PATH) => {
    const [header, payload, signature] = jwt.split('.');
    const input = header + '.' + payload;

    const maxContentLen = constants.maxContentLen;
    const maxExtClaimLen = constants.maxExtClaimLen;
    const maxKeyClaimNameLen = constants.maxKeyClaimNameLen;
    const maxKeyClaimValueLen = constants.maxKeyClaimValueLen;

    var [inputs, auxiliary_inputs] = await circuit.genJwtProofUAInputs(
        input, maxContentLen, maxExtClaimLen, maxKeyClaimNameLen, maxKeyClaimValueLen, keyClaim,
        claimsToReveal, ephPK, maxEpoch, jwtRand, userPIN
    );

    console.log(`Writing inputs to ${ZKP_INPUTS_FILE_PATH}...`);
    utils.writeJSONToFile(inputs, ZKP_INPUTS_FILE_PATH);

    auxiliary_inputs = Object.assign({}, auxiliary_inputs, {
        "jwt_signature": signature,
    });

    console.log(`Writing auxiliary inputs to ${AUX_INPUTS_FILE_PATH}...`);
    utils.writeJSONToFile(auxiliary_inputs, AUX_INPUTS_FILE_PATH);
};

if (require.main == module) {
    if (process.argv.length < 3) {
        console.log("Usage: node genZKPinputs.js <walletinputs.json> <zkinputs.json> <auxinputs.json>");
        console.log("Last two arguments are optional. If not specified, default filenames will be used.");
        process.exit(1);
    }
    
    let data = readJsonFile(process.argv[2]);

    let zk_inputs_file = process.argv[3];
    // If no output file is specified, use the default
    if (zk_inputs_file === undefined) {
        zk_inputs_file = "zkinputs.json";
    }

    let aux_inputs_file = process.argv[4];
    // If no output file is specified, use the default
    if (aux_inputs_file === undefined) {
        aux_inputs_file = "auxinputs.json";
    }
    
    // Log the data object
    console.log(data);
    
    (async () => {
        try {
            await genZKPInputs(
                data.jwt, BigInt(data.eph_public_key), data.max_epoch,
                BigInt(data.jwt_rand), BigInt(data.user_pin), data.key_claim_name,
                zk_inputs_file, aux_inputs_file
            );
            process.exit(0);
        } catch (error) {
            console.error("Error in processJWT:", error);
        }
    })();
}
