module.exports = {
    inWidth: 8,
    outWidth: 253,
    maskValue: '='.charCodeAt(),
    google: {
        maxContentLen: 64*12,
        claimsToReveal: ["iss", "aud", "nonce"],
        maxSubstrLen: 36,
    },
    twitch: {
        maxContentLen: 64*8,
        claimsToReveal: ["iss", "aud", "nonce"],
        maxSubstrLen: 21,
    }
}