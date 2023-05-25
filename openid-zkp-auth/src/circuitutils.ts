import crypto from "crypto";
import { toBigIntBE, toBufferBE } from 'bigint-buffer';

import * as utils from './utils';
import * as jwtutils from './jwtutils';

import { AuxInputs, KCCheckInputs, ZKInputs, constants, bit, NonceCheckInputs } from './common';

const claimsToReveal = constants.claimsToReveal;
const devVars = constants.dev;
const nWidth = constants.inWidth;
const packWidth = constants.packWidth;
const poseidonHash = require('./utils').poseidonHash;

// https://datatracker.ietf.org/doc/html/rfc4634#section-4.1
function padMessage(bits: bit[]): bit[] {
    const L = bits.length;
    const K = (512 + 448 - (L % 512 + 1)) % 512;

    bits = bits.concat([1]);
    if(K > 0) {
        bits = bits.concat(Array(K).fill(0));
    }
    bits = bits.concat(utils.buffer2BitArray(Buffer.from(L.toString(16).padStart(16, '0'), 'hex')));
    return bits;
}

function genJwtMask(input: string, fields: string[]): bit[] {
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
  
function genSha256Inputs(input: string, nCount: number, nWidth = 8) {
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
    
    return {
        ["content"]: segments.map(bits => toBigIntBE(utils.bitArray2Buffer(bits))),
        "num_sha2_blocks": num_sha2_blocks
    };
}

async function computeNonce(
    ephemeral_public_key = devVars.ephPK, 
    max_epoch = devVars.maxEpoch, 
    jwt_randomness = devVars.jwtRand,
) {
    const eph_public_key_0 = ephemeral_public_key / 2n**128n;
    const eph_public_key_1 = ephemeral_public_key % 2n**128n;

    const buildPoseidon = require("circomlibjs").buildPoseidon;
    const poseidon = await buildPoseidon();
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
    payload: string, payloadIndex: number,
    ephemeral_public_key = devVars.ephPK, 
    max_epoch = devVars.maxEpoch, 
    jwt_randomness = devVars.jwtRand,
): Promise<NonceCheckInputs> {
    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const extended_nonce = jwtutils.getExtendedClaim(decoded_payload, "nonce");
    const [start, len] = jwtutils.indicesOfB64(payload, 'nonce');

    if (extended_nonce.length != constants.extNonceLen) {
        throw new Error(`Length of nonce claim ${extended_nonce} (${extended_nonce.length}) is not equal to ${constants.extNonceLen} characters`);
    }

    const eph_public_key: [bigint, bigint] = [ephemeral_public_key / 2n**128n, ephemeral_public_key % 2n**128n];

    return {
        "extended_nonce": extended_nonce.split('').map(c => c.charCodeAt(0)),
        "nonce_claim_index_b64": start + payloadIndex,
        "nonce_length_b64": len,
        "eph_public_key": eph_public_key,
        "max_epoch": max_epoch,
        "jwt_randomness": jwt_randomness
    };
}

async function genKeyClaimCheckInputs(
    payload: string, maxExtClaimLen: number, 
    payloadIndex: number, userPIN: bigint,
    keyClaimName = "sub"
): Promise<KCCheckInputs> {
    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const ext_key_claim = jwtutils.getExtendedClaim(decoded_payload, keyClaimName);
    const [start, len] = jwtutils.indicesOfB64(payload, keyClaimName);

    if (ext_key_claim.length > maxExtClaimLen) {
        throw new Error(`The claim ${ext_key_claim} exceeds the maximum length of ${maxExtClaimLen} characters`);
    }

    const padded_ext_key_claim = utils.padWithZeroes(ext_key_claim.split('').map(c => c.charCodeAt(0)), maxExtClaimLen);
    return {
        "extended_key_claim": padded_ext_key_claim,
        "claim_length_ascii": ext_key_claim.length,
        "claim_index_b64": start + payloadIndex,
        "claim_length_b64": len,
        "subject_pin": userPIN,
        "key_claim_name_length": keyClaimName.length
    };
}

async function sanityChecks(
    payload: string,
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

/**
 * genJwtProofUAInputs
 * 
 * @param input header + '.' + payload
 * @param maxContentLen 
 * @param maxExtClaimLen 
 * @param maxKeyClaimNameLen 
 * @param maxKeyClaimValueLen 
 * @param keyClaimName 
 * @param fields 
 * @param ephPK 
 * @param maxEpoch 
 * @param jwtRand 
 * @param userPIN 
 * @param dev 
 * @returns ZKInputs, AuxInputs (everything minus the signature is set)
 */
async function genJwtProofUAInputs(
    input: string, maxContentLen: number, maxExtClaimLen: number,
    maxKeyClaimNameLen: number, maxKeyClaimValueLen: number,
    keyClaimName = "sub", fields = claimsToReveal,
    ephPK = devVars.ephPK, maxEpoch = devVars.maxEpoch, 
    jwtRand = devVars.jwtRand, userPIN = devVars.pin,
    dev = true
): Promise<[ZKInputs, AuxInputs]> {
    // init poseidon, inputs
    const buildPoseidon = require("circomlibjs").buildPoseidon;
    const poseidon = await buildPoseidon();
    var zk_inputs = new ZKInputs();
    var aux_inputs = new AuxInputs();

    // set SHA-2 inputs
    let sha256inputs = genSha256Inputs(input, maxContentLen, nWidth);
    zk_inputs.content = sha256inputs.content;
    zk_inputs.num_sha2_blocks = sha256inputs.num_sha2_blocks;

    // set indices
    zk_inputs.payload_start_index = input.split('.')[0].length + 1; // 4x+1, 4x, 4x-1
    const payload = input.split('.')[1];
    zk_inputs.payload_len = payload.length;

    // set the key claim inputs
    const key_claim_inputs = await genKeyClaimCheckInputs(
        payload,
        maxExtClaimLen,
        zk_inputs.payload_start_index,
        userPIN,
        keyClaimName
    );
    zk_inputs.extended_key_claim = key_claim_inputs.extended_key_claim;
    zk_inputs.claim_length_ascii = key_claim_inputs.claim_length_ascii;
    zk_inputs.claim_index_b64 = key_claim_inputs.claim_index_b64;
    zk_inputs.claim_length_b64 = key_claim_inputs.claim_length_b64;
    zk_inputs.subject_pin = key_claim_inputs.subject_pin;
    zk_inputs.key_claim_name_length = key_claim_inputs.key_claim_name_length;

    // set hash
    const hash = BigInt("0x" + crypto.createHash("sha256").update(input).digest("hex"));
    aux_inputs.jwt_sha2_hash = [hash / 2n**128n, hash % 2n**128n];

    // masking 
    zk_inputs.mask = genJwtMask(input, fields).concat(Array(maxContentLen - input.length).fill(1));
    aux_inputs.masked_content = utils.applyMask(zk_inputs.content.map(Number), zk_inputs.mask); 
    const packed = utils.pack(aux_inputs.masked_content.map(BigInt), 8, packWidth); // TODO: BigInt -> Number -> BigInt
    const masked_content_hash = poseidonHash(packed, poseidon);

    // set nonce-related inputs
    const nonce_inputs = await genNonceCheckInputs(
        payload, zk_inputs.payload_start_index,
        ephPK, maxEpoch, jwtRand
    );
    zk_inputs.extended_nonce = nonce_inputs.extended_nonce;
    zk_inputs.nonce_claim_index_b64 = nonce_inputs.nonce_claim_index_b64;
    zk_inputs.nonce_length_b64 = nonce_inputs.nonce_length_b64;
    zk_inputs.eph_public_key = nonce_inputs.eph_public_key;
    zk_inputs.max_epoch = nonce_inputs.max_epoch;
    zk_inputs.jwt_randomness = nonce_inputs.jwt_randomness;

    // derive address
    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const key_claim_value = jwtutils.getClaimValue(decoded_payload, keyClaimName);
    const address_seed = await utils.deriveAddrSeed(
        key_claim_value, userPIN, maxKeyClaimValueLen
    );
    console.log(`Seed ${address_seed} derived from ID ${key_claim_value} and PIN ${userPIN}`);
    const key_claim_name_F = await utils.mapToField(keyClaimName, maxKeyClaimNameLen);

    const all_inputs_hash: bigint = poseidonHash([
        aux_inputs.jwt_sha2_hash[0],
        aux_inputs.jwt_sha2_hash[1],
        masked_content_hash,
        zk_inputs.payload_start_index,
        zk_inputs.payload_len,
        zk_inputs.eph_public_key[0], 
        zk_inputs.eph_public_key[1], 
        zk_inputs.max_epoch,
        zk_inputs.num_sha2_blocks,
        key_claim_name_F,
        address_seed
    ], poseidon);

    zk_inputs.all_inputs_hash = all_inputs_hash;

    aux_inputs.payload_start_index = zk_inputs.payload_start_index;
    aux_inputs.payload_len = zk_inputs.payload_len;
    aux_inputs.eph_public_key = zk_inputs.eph_public_key;
    aux_inputs.max_epoch = zk_inputs.max_epoch;
    aux_inputs.num_sha2_blocks = zk_inputs.num_sha2_blocks;
    aux_inputs.key_claim_name = keyClaimName;
    aux_inputs.addr_seed = address_seed;

    if (dev) {
        sanityChecks(payload, ephPK, maxEpoch, jwtRand);
    }
  
    return [zk_inputs, aux_inputs];
}

export {
    padMessage,
    genJwtMask,
    genSha256Inputs,
    genJwtProofUAInputs,
    computeNonce
}
