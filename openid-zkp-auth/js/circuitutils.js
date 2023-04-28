const crypto = require("crypto");
const utils = require('./utils');
const b64utils = require('./b64utils');
const {toBigIntBE} = require('bigint-buffer');

const nWidth = require("./constants").inWidth;
const outWidth = require("./constants").outWidth;
const nOptions = require("./constants").nOptions;

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
      var [start, end] = b64utils.indicesOfB64(payload, field);
      
      for(var i = start; i <= end; i++) {
        payloadMask[i] = 1;
      }
    }
    
    return Array(header.length + 1).fill(1).concat(payloadMask);
    // return [Array(header.length + 1).fill(0).concat(payloadMask), startOffsets];
  }
  
function genSha256Inputs(input, nCount, nWidth = 512, inParam = "in") {
    var segments = utils.arrayChunk(padMessage(utils.buffer2BitArray(Buffer.from(input))), nWidth);
    const num_sha2_blocks = segments.length / (512 / nWidth);
    
    if(segments.length < nCount) {
        segments = segments.concat(Array(nCount-segments.length).fill(Array(nWidth).fill(0)));
    }
    
    if(segments.length > nCount) {
        throw new Error('Padded message exceeds maximum blocks supported by circuit', segments.length, nCount);
    }
    
    return { [inParam]: segments, "num_sha2_blocks": num_sha2_blocks }; 
}

function genNonceInputs() {
    const eph_public_key = 0x0d7dab358c8dadaa4efa0049a75b07436555b10a368219bb680f70571349d775n; // TODO: Fixed for dev
    // const eph_public_key = BigInt("0x" + crypto.randomBytes(32).toString('hex'));
    const max_epoch = 10000; // TODO: Fixed for dev
    const randomness = 50683480294434968413708503290439057629605340925620961559740848568164438166n; // TODO: Fixed for dev
  
    const eph_public_key_0 = eph_public_key / 2n**128n;
    const eph_public_key_1 = eph_public_key % 2n**128n;
  
    return {
      "eph_public_key": [eph_public_key_0, eph_public_key_1],
      "max_epoch": max_epoch,
      "randomness": randomness
    };
  }
  
// TODO: make it return auxiliary inputs
async function genJwtProofInputs(input, nCount, fields) {
    // set SHA-2 inputs
    var inputs = genSha256Inputs(input, nCount, nWidth, "content");
    inputs["content"] = inputs["content"].map(bits => toBigIntBE(utils.bitArray2Buffer(bits)));

    // set indices
    inputs["payload_start_index"] = input.split('.')[0].length + 1; // 4x+1, 4x, 4x-1
    const payload = input.split('.')[1];
    inputs["sub_claim_index"] = b64utils.indicesOfB64(payload, "sub")[0] + inputs["payload_start_index"];
    inputs["payload_len"] = payload.length;

    // set hash
    const hash = BigInt("0x" + crypto.createHash("sha256").update(input).digest("hex"));
    const jwt_sha2_hash = [hash / 2n**128n, hash % 2n**128n];

    // set mask 
    inputs["mask"] = genJwtMask(input, fields).concat(Array(nCount - input.length).fill(1));

    // init poseidon
    const buildPoseidon = require("circomlibjs").buildPoseidon;
    poseidon = await buildPoseidon();

    // set hash of the masked content
    const masked_content_hash = utils.calculateMaskedHash(
        inputs["content"],
        inputs["mask"],
        poseidon,
        outWidth
    );

    // set nonce-related inputs
    inputs = Object.assign({}, inputs, genNonceInputs());
    const nonce = utils.poseidonHash([
        inputs["eph_public_key"][0], 
        inputs["eph_public_key"][1], 
        inputs["max_epoch"], 
        inputs["randomness"]
    ], poseidon);

    inputs["all_inputs_hash"] = utils.poseidonHash([
        jwt_sha2_hash[0],
        jwt_sha2_hash[1],
        masked_content_hash,
        inputs["payload_start_index"],
        inputs["payload_len"],
        inputs["eph_public_key"][0], 
        inputs["eph_public_key"][1], 
        inputs["max_epoch"],
        nonce,
        inputs["num_sha2_blocks"]
    ], poseidon);

    return inputs;
}

function genSubInputs(payload, maxSubstrLen) {
    const decoded_payload = Buffer.from(payload, 'base64url').toString();
    const sub_claim = utils.getClaimString(decoded_payload, "sub");
    const A = utils.removeDuplicates(b64utils.getAllExtendedBase64Variants(sub_claim));
    if (A.length > nOptions) {
        throw new Error("Number of options exceeds maximum supported by circuit", A.length, nOptions);
    }
    const sub_in_b64 = A.map(e => e[0].split('').map(c => c.charCodeAt()));
    console.log(sub_in_b64);
    const option_length = A[0][0].length;

    return {
        "sub_id_array": sub_in_b64.map(e => e.concat(Array(maxSubstrLen - option_length).fill(0))),
        "sub_offsets": A.map(e => e[1]),
        "sub_length": option_length,
        "subject_pin": 1234 // TODO: Fixed for dev
    }
}

function genSubID(inputs, poseidon) {
    return utils.poseidonHash([
        inputs["sub_id_array"][0][0],
        inputs["sub_offsets"][0],
        inputs["sub_length"]
    ], poseidon);
}

async function genJwtProofUAInputs(input, nCount, fields, maxSubstrLen) {  
    // init poseidon
    const buildPoseidon = require("circomlibjs").buildPoseidon;
    poseidon = await buildPoseidon();

    // set SHA-2 inputs
    var inputs = genSha256Inputs(input, nCount, nWidth, "content");
    inputs["content"] = inputs["content"].map(bits => toBigIntBE(utils.bitArray2Buffer(bits)));
  
    // set indices
    inputs["payload_start_index"] = input.split('.')[0].length + 1; // 4x+1, 4x, 4x-1
    const payload = input.split('.')[1];
    inputs["sub_claim_index"] = b64utils.indicesOfB64(payload, "sub")[0] + inputs["payload_start_index"];
    inputs["payload_len"] = payload.length;

    // set sub claim inputs
    inputs = Object.assign({}, inputs, genSubInputs(payload, maxSubstrLen, nOptions));
    subject_id_com = utils.poseidonHash([
        genSubID(inputs, poseidon),
        inputs["subject_pin"]
    ], poseidon);

    // set hash
    const hash = BigInt("0x" + crypto.createHash("sha256").update(input).digest("hex"));
    const jwt_sha2_hash = [hash / 2n**128n, hash % 2n**128n];
  
    // set mask 
    inputs["mask"] = genJwtMask(input, fields).concat(Array(nCount - input.length).fill(1));
  
    // set hash of the masked content
    const masked_content_hash = utils.calculateMaskedHash(
        inputs["content"],
        inputs["mask"],
        poseidon,
        outWidth
    );
  
    // set nonce-related inputs
    inputs = Object.assign({}, inputs, genNonceInputs());
    const nonce = utils.poseidonHash([
        inputs["eph_public_key"][0], 
        inputs["eph_public_key"][1], 
        inputs["max_epoch"], 
        inputs["randomness"]
    ], poseidon);
  
    inputs["all_inputs_hash"] = utils.poseidonHash([
        jwt_sha2_hash[0],
        jwt_sha2_hash[1],
        masked_content_hash,
        inputs["payload_start_index"],
        inputs["payload_len"],
        inputs["eph_public_key"][0], 
        inputs["eph_public_key"][1], 
        inputs["max_epoch"],
        nonce,
        inputs["num_sha2_blocks"],
        subject_id_com
    ], poseidon);
  
    return inputs;
}  

module.exports = {
    padMessage: padMessage,
    genJwtMask: genJwtMask,
    genSha256Inputs: genSha256Inputs,
    genJwtProofInputs: genJwtProofInputs,
    genJwtProofUAInputs: genJwtProofUAInputs
}
