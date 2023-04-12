const chai = require("chai");
const path = require("path");
const assert = chai.assert;
const crypto = require("crypto");
const jose = require("jose");


// describe("Masking", () => {
//     const facebook_jwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjE0ZWJjMDRlNmFjM2QzZTk2MDMxZDJjY2QzODZmY2E5NWRkZjMyZGQifQ.eyJpc3MiOiJodHRwczpcL1wvd3d3LmZhY2Vib29rLmNvbSIsImF1ZCI6IjEyNDE1NTkzNjY3NTUyMTQiLCJzdWIiOiI3MDg1NjI2MTEwMDk1MjUiLCJpYXQiOjE2Nzk5MzIwMTQsImV4cCI6MTY3OTkzNTYxNCwianRpIjoiVEt2ei5kYmVjN2NhMzE5NDJhNWQyZTU2YmQwZGJmYjgyNGIxNzE4NWUwZjMwYjIwZjI1NzNkZTVkNDhmYzlmNTgzZTQzIiwibm9uY2UiOiJ0ZXN0IiwiZ2l2ZW5fbmFtZSI6IkpveSIsImZhbWlseV9uYW1lIjoiV2FuZyIsIm5hbWUiOiJKb3kgV2FuZyIsInBpY3R1cmUiOiJodHRwczpcL1wvcGxhdGZvcm0tbG9va2FzaWRlLmZic2J4LmNvbVwvcGxhdGZvcm1cL3Byb2ZpbGVwaWNcLz9hc2lkPTcwODU2MjYxMTAwOTUyNSZoZWlnaHQ9MTAwJndpZHRoPTEwMCZleHQ9MTY4MjUyNDAxNSZoYXNoPUFlUzBDcW5YTzJjYU94OFg4UWcifQ.ZCJrb_Fsu_cvMy-mCrRrRxSptL-3WhBW7DxasYYaDWGeFcADQKkPW4PW9MZNYrqq00hDqOgUkCJ_brq9Qf1mV2LOfHFmGHUSVwciCFH8f_7KH-Uu1TuPQbduBHgPqXiFkFxxEmz3o25mDO7VjgipRlsez4-XjUYJkSMCYRGkpmRFJPIDtz97dhCLbW16Kb59m8_7Lf4Uz2unDubHnwXeuIPxSmX2wr1WQxiFemFhgvnULZx4PvFnb72eHk9pFlywHrm-bA7qJWnajkrXEDNKAALV2uolgJDlPrlpZLiSW65fT2V3IBZSAsFeq4pCsuxr6eON9KIa8-4TFBy8xL4EZg'
//     const google_jwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6Ijk4NmVlOWEzYjc1MjBiNDk0ZGY1NGZlMzJlM2U1YzRjYTY4NWM4OWQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTc5MTI3MzU2NTg1NDEzMzY2NDYiLCJhdF9oYXNoIjoicm9aYm11cUVXdmNHSThDR2N1SnJmUSIsImlhdCI6MTY3OTY3NDE0NSwiZXhwIjoxNjc5Njc3NzQ1fQ.G8cciXefORmYvdwrfVAO6DjDy7DUWe6NxyanGg4w7EQBu8Ab7PJAeXhU7HL5w_LtTgiLA3Ew07RRzuNuaFITvs_m9lIolxHOl0BZSyGIGlI9BRiBFQQK2OZ2b8xetWz3B1mezcwlrrQMgbLQI0puuaA6917h_3MjIgZu_bQkjQH3Lwl3kkZWp0W-PRuK20KAQneNFB9ehTvSeRkImIr5QlZU6LMb7M3rI_-gP6ePRryAN9UCGBASzNEYLaQz-eMIdYFw-WmqkesTX1IDLQT0n44BhG9-9mWIA6kNRSBo9FV89VGKvYION9PTDds1vsf5h3smBQZjourR2H5pLJ_MUA';
//     const input = google_jwt.split('.').slice(0,2).join('.');

//     it("JWT masking", () => {
//         const mask = circuit.genJwtMask(input, ["iss", "aud", "iat", "exp"]);
//         const masked_input = utils.applyMask(input, mask);
    
//         const claims = masked_input.split(/=+/).filter(e => e !== '');        
//         console.log("claims", claims);
    
//         const payloadIndex = input.split('.')[0].length + 1;
    
//         var searchFromPos = payloadIndex;
//         for (const claim of claims) {
//             const claimIndex = input.indexOf(claim, searchFromPos);
//             assert.isTrue(claimIndex >= payloadIndex, "String not found in input");
    
//             // convert to base64 taking into account the payload index
//             const claimB64Offset = (claimIndex - payloadIndex) % 4;
//             const claimUTF8 = utils.fromBase64WithOffset(claim, claimB64Offset);
//             console.log(claimIndex, claimB64Offset, claimUTF8);
    
//             searchFromPos = claimIndex + claim.length;
//         }
    
//         // assert.equal(claims.length, 2, "Incorrect number of claims");
//         // assert.include(claims[0], '"iss":"https://accounts.google.com"', "Does not contain iss claim");
//         // assert.include(claims[1], '"iat":1679674145', "Does not contain iat claim");
//         // assert.include(claims[2], '"exp":1679677745', "Does not contain exp claim");
//     });

//     // it("JWT masking edge cases", async() => {
//     //     var header = '{"kid":abc}';
//     //     var payload = '{"iss":123,"azp":456,"iat":789,"exp":101112}';
//     //     var encoded_jwt = utils.trimEndByChar(Buffer.from(header).toString('base64'), '=') + '.' + utils.trimEndByChar(Buffer.from(payload).toString('base64'), '=');

//     //     var [mask, startOffsets] = circuit.genJwtMask(encoded_jwt, ["exp"]);
//     //     var consecutiveClaims = ["iss"];
//     //     const circuitOutputClaims = encoded_jwt.split('').map((c, i) => mask[i] == 1 ? c : ' ').join('').split(/\s+/).filter(e => e !== '');
        
//     //     assert.equal(circuitOutputClaims.length, consecutiveClaims.length);

//     //     console.log(circuitOutputClaims, startOffsets);

//     //     // Each element corresponds to a non-consecutive claim
//     //     var claims = [];
//     //     for (const [i, c] of circuitOutputClaims.entries()) {
//     //         claims.push(Buffer.from('0'.repeat(startOffsets[i]) + c, 'base64').toString().slice(startOffsets[i]));
//     //     }
//     //     console.log(claims, "claims");
//     //     assert.equal(claims.length, 1);

//     //     assert.equal(claims[0], '"azp":456,', "Does not contain azp claim");
//     // });
// });