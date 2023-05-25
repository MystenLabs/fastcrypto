#!/usr/bin/env node

import fs from 'fs';
import * as circuit from './circuitutils';
import * as utils from './utils';
import { constants, WalletInputs} from './common';
const { claimsToReveal } = constants;

function readJsonFile(filename: string): WalletInputs {
    try {
        if (!fs.existsSync(filename)) {
            throw new Error(`File doesn't exist: ${filename}`);
        }

        const rawdata = fs.readFileSync(filename);
        const jsonData = JSON.parse(rawdata.toString());

        // Validate JSON structure
        const requiredFields = ['jwt', 'eph_public_key', 'max_epoch', 'jwt_rand', 'user_pin', 'key_claim_name'];
        for (let field of requiredFields) {
            if (!jsonData.hasOwnProperty(field)) {
                throw new Error(`Missing required field: ${field}`);
            }
        }

        const walletinputs: WalletInputs = {
            jwt: jsonData.jwt,
            eph_public_key: BigInt(jsonData.eph_public_key),
            max_epoch: Number(jsonData.max_epoch),
            jwt_rand: BigInt(jsonData.jwt_rand),
            user_pin: BigInt(jsonData.user_pin),
            key_claim_name: jsonData.key_claim_name,
        }

        return walletinputs;
    } catch (err) {
        console.error(`Error reading or parsing JSON file: ${(err as Error).message}`);
        process.exit(1);  // Exit with failure status
    }
}

async function genZKPInputs (
    walletinputs: WalletInputs,
    ZKP_INPUTS_FILE_PATH: string,
    AUX_INPUTS_FILE_PATH: string
) {
    const [header, payload, signature] = walletinputs.jwt.split('.');
    const input = header + '.' + payload;

    const maxContentLen = constants.maxContentLen;
    const maxExtClaimLen = constants.maxExtClaimLen;
    const maxKeyClaimNameLen = constants.maxKeyClaimNameLen;
    const maxKeyClaimValueLen = constants.maxKeyClaimValueLen;

    const [inputs, auxiliary_inputs] = await circuit.genJwtProofUAInputs(
        input, maxContentLen, maxExtClaimLen, maxKeyClaimNameLen, maxKeyClaimValueLen, 
        walletinputs.key_claim_name, claimsToReveal, 
        walletinputs.eph_public_key,
        walletinputs.max_epoch,
        walletinputs.jwt_rand,
        walletinputs.user_pin
    );

    console.log(`Writing inputs to ${ZKP_INPUTS_FILE_PATH}...`);
    utils.writeJSONToFile(inputs, ZKP_INPUTS_FILE_PATH);

    auxiliary_inputs.jwt_signature = signature;

    console.log(`Writing auxiliary inputs to ${AUX_INPUTS_FILE_PATH}...`);
    utils.writeJSONToFile(auxiliary_inputs, AUX_INPUTS_FILE_PATH);
};

if (require.main === module) {
    if (process.argv.length < 3) {
        console.log("Usage: node genZKPinputs.js <walletinputs.json> <zkinputs.json> <auxinputs.json>");
        console.log("Last two arguments are optional. If not specified, default filenames will be used.");
        process.exit(1);
    }

    const data = readJsonFile(process.argv[2]);

    let zk_inputs_file = process.argv[3];
    // If no output file is specified, use the default
    if (!zk_inputs_file) {
        zk_inputs_file = "zkinputs.json";
    }

    let aux_inputs_file = process.argv[4];
    // If no output file is specified, use the default
    if (!aux_inputs_file) {
        aux_inputs_file = "auxinputs.json";
    }

    // Log the data object
    console.log(data);

    (async () => {
        try {
            await genZKPInputs(
                data, zk_inputs_file, aux_inputs_file
            );
            process.exit(0);
        } catch (error) {
            console.error("Error in processJWT:", error);
        }
    })();
}
