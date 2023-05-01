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
    // facebook: {
    //     maxContentLen: 64*15, // TODO: Come up with an automated way to determine this
    //     claimsToReveal: ["iss", "aud", "nonce"],
    //     maxSubstrLen: 27, // TODO: Come up with an automated way to determine this
    // },
}