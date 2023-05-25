export type bit = 0 | 1;

export interface WalletInputs {
    jwt: string,
    eph_public_key: bigint,
    max_epoch: number,
    jwt_rand: bigint,
    user_pin: bigint,
    key_claim_name: string
}

export interface KCCheckInputs {
    "extended_key_claim": number[];
    "claim_length_ascii": number;
    "claim_index_b64": number;
    "claim_length_b64": number;
    "subject_pin": bigint;
    "key_claim_name_length": number;
}

export interface NonceCheckInputs {
    "extended_nonce": number[];
    "nonce_claim_index_b64": number;
    "nonce_length_b64": number;
    "eph_public_key": [bigint, bigint];
    "max_epoch": number;
    "jwt_randomness": bigint;
}

export class ZKInputs implements KCCheckInputs, NonceCheckInputs {
    "content": bigint[];
    "num_sha2_blocks": number;

    "payload_start_index": number;
    "payload_len": number;

    "mask": bit[];

    // KCCheckInputs
    "extended_key_claim": number[];
    "claim_length_ascii": number;
    "claim_index_b64": number;
    "claim_length_b64": number;
    "subject_pin": bigint;
    "key_claim_name_length": number;

    // NonceCheckInputs
    "extended_nonce": number[];
    "nonce_claim_index_b64": number;
    "nonce_length_b64": number;
    "eph_public_key": [bigint, bigint];
    "max_epoch": number;
    "jwt_randomness": bigint;

    "all_inputs_hash": bigint;
}

export class AuxInputs {
    "masked_content": number[];
    "jwt_signature": string;
    "jwt_sha2_hash": [bigint, bigint];
    "payload_start_index": number;
    "payload_len": number;
    "eph_public_key": [bigint, bigint];
    "max_epoch": number;
    "num_sha2_blocks": number;
    "key_claim_name": string;
    "addr_seed": bigint;
}

// missing the tx signature
export class PartialZKLoginSig {
    "zkproof": any;
    "public_inputs": any;
    "auxiliary_inputs": AuxInputs;
}

export const constants = {
    P: 21888242871839275222246405745257275088548364400416034343698204186575808495617n,
    flag: 5,
    inWidth: 8,
    packWidth: 248,
    // const eph_public_key = BigInt("0x" + crypto.randomBytes(32).toString('hex'));
    dev: { // NOTE: Constants meant to be used for dev
        pin: 283089722053851751073973683904920435104n,
        ephPK: 0x0d7dab358c8dadaa4efa0049a75b07436555b10a368219bb680f70571349d775n,
        maxEpoch: 10000,
        jwtRand: 100681567828351849884072155819400689117n
    },
    maskValue: '='.charCodeAt(0),
    nonceLen: Math.ceil(256 / 6), // 43
    extNonceLen: Math.ceil(256 / 6) + 11, // 11 for prefix and suffix
    claimsToReveal: ["iss", "aud"],
    maxContentLen: 64*12,
    maxExtClaimLen: 66, // name + value + 6 chars (four '"', one ':' and one ',' / '}')
    maxKeyClaimNameLen: 10,
    maxKeyClaimValueLen: 50,
    maxIssValueLen: 31 * 3
}
