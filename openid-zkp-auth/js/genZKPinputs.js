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

const OUT_DIR = ".";

const genZKPInputs = async (jwt, ephPK, maxEpoch, jwtRand, userPIN, keyClaim='sub') => {
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

    const ZKP_INPUTS_FILE_PATH = `${OUT_DIR}/inputs.json`;
    console.log(`Writing inputs to ${ZKP_INPUTS_FILE_PATH}...`);
    utils.writeJSONToFile(inputs, ZKP_INPUTS_FILE_PATH);

    auxiliary_inputs = Object.assign({}, auxiliary_inputs, {
        "jwt_signature": signature,
    });

    const AUX_INPUTS_FILE_PATH = `${OUT_DIR}/aux.json`;
    console.log(`Writing auxiliary inputs to ${AUX_INPUTS_FILE_PATH}...`);
    utils.writeJSONToFile(auxiliary_inputs, AUX_INPUTS_FILE_PATH);
};

if (require.main == module) {
    if (process.argv.length < 3) {
        console.log("Usage: node geninputs.js <input.json>");
        process.exit(1);
    }
    
    let data = readJsonFile(process.argv[2]);
    
    // Log the data object
    console.log(data);
    
    (async () => {
        try {
            await genZKPInputs(
                data.jwt, BigInt(data.eph_public_key), data.max_epoch,
                BigInt(data.jwt_rand), BigInt(data.user_pin), data.key_claim_name
            );
            process.exit(0);
        } catch (error) {
            console.error("Error in processJWT:", error);
        }
    })();
}
