const crypto = require("crypto");
const {toBigIntBE, toBufferBE} = require('bigint-buffer');

const utils = require('./utils');
const jwtutils = require('./jwtutils');

const constants = require('./constants');
const claimsToReveal = constants.claimsToReveal;
const devVars = constants.dev;
const nWidth = constants.inWidth;
const outWidth = constants.outWidth;
const poseidonHash = require('./utils').poseidonHash;

// https://datatracker.ietf.org/doc/html/rfc4634#section-4.1
function padMessage(bits) {
    const L = bits.length;
    const K = (512 + 448 - (L % 512 + 1)) % 512;

    bits = bits.concat([1]);
    if(K > 0) {
        bits = bits.concat(Array(K).fill(0));
    }
    bits = bits.concat(utils.buffer2BitArray(Buffer.from(L.toString(16).padStart(16, '0'), 'hex')));
    return bits;
}

function genJwtMask(input, fields) {
    const [header, payload] = input.split('.');
    var payloadMask = Array(payload.length).fill(0);
    for(const field of fields) {
        var [start, len] = jwtutils.indicesOfB64(payload, field);
        for(var i = 0; i < len; i++) {
            payloadMask[start + i] = 1;
        }
    }

    return Array(header.length + 1).fill(1).concat(payloadMask);
}
  
function genSha256Inputs(input, nCount, nWidth = 8, inParam = "in") {
    var segments = utils.arrayChunk(padMessage(utils.buffer2BitArray(Buffer.from(input))), nWidth);
    const num_sha2_blocks = (segments.length * nWidth) / 512;

    if ((segments.length * nWidth) % 512 != 0) {
        throw new Error("Padding error: Padded message length is not a multiple of 512");
    }
    
    if(segments.length < nCount) {
        segments = segments.concat(Array(nCount-segments.length).fill(Array(nWidth).fill(0)));
    }
    
    if(segments.length > nCount) {
        throw new Error(`Padded message (${segments.length}) exceeds maximum length supported by circuit (${nCount})`);
    }
    
    return { [inParam]: segments, "num_sha2_blocks": num_sha2_blocks }; 
}

async function computeNonce(
    ephemeral_public_key = devVars.ephPK, 
    max_epoch = devVars.maxEpoch, 
    jwt_randomness = devVars.jwtRand,
) {
    const eph_public_key_0 = ephemeral_public_key / 2n**128n;
    const eph_public_key_1 = ephemeral_public_key % 2n**128n;

    const buildPoseidon = require("circomlibjs").buildPoseidon;
    poseidon = await buildPoseidon();
    const bignum = poseidonHash([
        eph_public_key_0,
        eph_public_key_1,
        max_epoch,
        jwt_randomness
    ], poseidon);

    const Z = toBufferBE(bignum, 32); // padded to 32 bytes
    const nonce = Z.toString('base64url');

    if (nonce.length != constants.nonceLen) {
        throw new Error(`Length of nonce ${nonce} (${nonce.length}) is not equal to ${constants.nonceLen}`);
    }

    return nonce;
}

async function genNonceCheckInputs(
    payload, payloadIndex,
    ephemeral_public_key = devVars.ephPK, 
    max_epoch = devVars.maxEpoch, 
    jwt_randomness = devVars.jwtRand,
) {

    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const extended_nonce = jwtutils.getExtendedClaim(decoded_payload, "nonce");
    const [start, len] = jwtutils.indicesOfB64(payload, 'nonce');

    if (extended_nonce.length != constants.extNonceLen) {
        throw new Error(`Length of nonce claim ${extended_nonce} (${extended_nonce.length}) is not equal to ${constants.extNonceLen} characters`);
    }

    return {
        "extended_nonce": extended_nonce.split('').map(c => c.charCodeAt()),
        "nonce_length_ascii": extended_nonce.length,
        "nonce_claim_index_b64": start + payloadIndex,
        "nonce_length_b64": len,
        "eph_public_key": [ephemeral_public_key / 2n**128n, ephemeral_public_key % 2n**128n],
        "max_epoch": max_epoch,
        "jwt_randomness": jwt_randomness
    };
}

async function genSubCheckInputs(payload, maxSubLength, payloadIndex, userPIN) {
    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const extended_sub = jwtutils.getExtendedClaim(decoded_payload, "sub");
    const [start, len] = jwtutils.indicesOfB64(payload, 'sub');

    if (extended_sub.length > maxSubLength) {
        throw new Error(`Subject claim ${extended_sub} exceeds maximum length of ${maxSubLength} characters`);
    }

    const sub_claim_without_last_char = extended_sub.slice(0, -1);
    const subject_id_com = await utils.commitSubID(sub_claim_without_last_char, userPIN, maxSubLength, outWidth);

    const padded_subject_id = utils.padWithZeroes(extended_sub.split('').map(c => c.charCodeAt()), maxSubLength);
    return [{
        "extended_sub": padded_subject_id,
        "sub_length_ascii": extended_sub.length,
        "sub_claim_index_b64": start + payloadIndex,
        "sub_length_b64": len,
        "subject_pin": userPIN
    }, subject_id_com];
}

async function sanityChecks(
    payload,
    ephemeral_public_key = devVars.ephPK, 
    max_epoch = devVars.maxEpoch, 
    jwt_randomness = devVars.jwtRand,
) {
    const nonce = await computeNonce(ephemeral_public_key, max_epoch, jwt_randomness);

    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const json_nonce = JSON.parse(decoded_payload).nonce;
    if (json_nonce !== nonce) {
        throw new Error(`Nonce in the JSON ${json_nonce} does not match computed nonce ${nonce}`);
    }
}

async function genJwtProofUAInputs(
    input, maxContentLen, maxSubLen,
    fields = claimsToReveal, ephPK = devVars.ephPK, maxEpoch = devVars.maxEpoch, 
    jwtRand = devVars.jwtRand, userPIN = devVars.pin,
    dev = true
){
    // init poseidon
    const buildPoseidon = require("circomlibjs").buildPoseidon;
    poseidon = await buildPoseidon();

    // set SHA-2 inputs
    var inputs = genSha256Inputs(input, maxContentLen, nWidth, "content");
    inputs.content = inputs.content.map(bits => toBigIntBE(utils.bitArray2Buffer(bits)));
  
    // set indices
    inputs.payload_start_index = input.split('.')[0].length + 1; // 4x+1, 4x, 4x-1
    const payload = input.split('.')[1];
    inputs.payload_len = payload.length;

    // set sub claim inputs
    const [sub_inputs, subject_id_com] = await genSubCheckInputs(
        payload,
        maxSubLen,
        inputs.payload_start_index,
        userPIN
    );
    inputs = Object.assign({}, inputs, sub_inputs);

    // set hash
    const hash = BigInt("0x" + crypto.createHash("sha256").update(input).digest("hex"));
    const jwt_sha2_hash = [hash / 2n**128n, hash % 2n**128n];

    // masking 
    inputs.mask = genJwtMask(input, fields).concat(Array(maxContentLen - input.length).fill(1));
    const masked_content = utils.applyMask(inputs.content, inputs.mask);
    const packed = utils.pack(masked_content, 8, outWidth);
    const masked_content_hash = poseidonHash(packed, poseidon);

    // set nonce-related inputs
    const nonce_inputs = await genNonceCheckInputs(
        payload, inputs.payload_start_index,
        ephPK, maxEpoch, jwtRand
    );
    inputs = Object.assign({}, inputs, nonce_inputs);

    inputs.all_inputs_hash = poseidonHash([
        jwt_sha2_hash[0],
        jwt_sha2_hash[1],
        masked_content_hash,
        inputs.payload_start_index,
        inputs.payload_len,
        inputs.eph_public_key[0], 
        inputs.eph_public_key[1], 
        inputs.max_epoch,
        inputs.num_sha2_blocks,
        subject_id_com
    ], poseidon);

    const auxiliary_inputs = {
        "masked_content": masked_content,
        "jwt_sha2_hash": jwt_sha2_hash.map(e => e.toString()),
        "payload_start_index": inputs.payload_start_index,
        "payload_len": inputs.payload_len,
        "eph_public_key": inputs.eph_public_key.map(e => e.toString()),
        "max_epoch": inputs.max_epoch,
        "num_sha2_blocks": inputs.num_sha2_blocks,
        "sub_id_com": subject_id_com.toString()
    }

    if (dev) {
        sanityChecks(payload, ephPK, maxEpoch, jwtRand);
    }
  
    return [inputs, auxiliary_inputs];
}  

module.exports = {
    padMessage: padMessage,
    genJwtMask: genJwtMask,
    genSha256Inputs: genSha256Inputs,
    genJwtProofUAInputs: genJwtProofUAInputs,
    computeNonce: computeNonce
}
