const utils = require('./utils');
const {toBigIntBE} = require('bigint-buffer');

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

function genClaimParams(input, claimField, claimLength, nWidth) {
  const claimPattern = new RegExp(`"${claimField}"\\:\\s*"`);
  const claimOffset = Math.floor(input.search(claimPattern) / (nWidth / 8));
  
  var inputs = { "claimOffset": claimOffset };
  
  if(claimLength !== undefined) {
    inputs = Object.assign({},
      inputs,
      { "claimLength": claimLength }
    );
  }
  
  return inputs;
}

function genJwtMask(input, fields) {
  const [header, payload] = input.split('.');
  
  var payloadMask = Array(payload.length).fill(0);
  // var startOffsets = [];
  for(const field of fields) {
    var [start, end] = utils.getBase64JSONSlice(payload, field);
    // var [start, end, startOffset] = utils.getBase64JSONSlice(payload, field);
    // startOffsets.push(startOffset);
    
    for(var i = start; i <= end; i++) {
      payloadMask[i] = 1;
    }
  }
  
  return Array(header.length + 1).fill(0).concat(payloadMask);
  // return [Array(header.length + 1).fill(0).concat(payloadMask), startOffsets];
}

function genSha256Inputs(input, nCount, nWidth = 512, inParam = "in") {
    var segments = utils.arrayChunk(padMessage(utils.buffer2BitArray(Buffer.from(input))), nWidth);
    const lastBlock = segments.length / (512 / nWidth);
    
    if(segments.length < nCount) {
        segments = segments.concat(Array(nCount-segments.length).fill(Array(nWidth).fill(0)));
    }
    
    if(segments.length > nCount) {
        throw new Error('Padded message exceeds maximum blocks supported by circuit');
    }
    
    return { [inParam]: segments, "lastBlock": lastBlock }; 
}

function genClaimProofInputs(input, nCount, claimField, claimLength = undefined, nWidth = 16, inParam = "content") {
  var inputs = genSha256Inputs(input, nCount, nWidth, inParam);
  inputs[inParam] = inputs[inParam].map(bits => toBigIntBE(utils.bitArray2Buffer(bits)));
  
  inputs = Object.assign({},
    inputs,
    genClaimParams(input, claimField, claimLength, nWidth)
  );
  
  return inputs;
}

function genJwtProofInputs(input, nCount, fields, nWidth = 16, inParam = "content") {
  var inputs = genSha256Inputs(input, nCount, nWidth, inParam);
  inputs[inParam] = inputs[inParam].map(bits => toBigIntBE(utils.bitArray2Buffer(bits)));

  var payloadOffset = input.split('.')[0].length + 1;
  var offset = (4 - (payloadOffset % 4)) % 4;
  
  inputs = Object.assign({},
    inputs,
    { 
      "mask": genJwtMask(input, fields).concat(Array(nCount - input.length).fill(0)),
      "payloadB64Offset": [offset % 2, Math.floor(offset / 2)]
    }
  );
  
  return inputs;
}

module.exports = {
    padMessage: padMessage,
    genClaimParams: genClaimParams,
    genJwtMask: genJwtMask,
    genSha256Inputs: genSha256Inputs,
    genClaimProofInputs: genClaimProofInputs,
    genJwtProofInputs: genJwtProofInputs,
}
