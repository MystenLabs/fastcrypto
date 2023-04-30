module.exports = {
    inWidth: 8,
    outWidth: 253,
    maskValue: '='.charCodeAt(),
    google: {
        jwtMaxLen: 64*12, // TODO: Come up with an automated way to determine this
        claimsToReveal: ["iss", "aud", "nonce"],
        maxSubstrLen: 36, // TODO: Come up with an automated way to determine this
    },
    facebook: {
        jwtMaxLen: 64*15, // TODO: Come up with an automated way to determine this
        claimsToReveal: ["iss", "aud", "nonce"],
        maxSubstrLen: 27, // TODO: Come up with an automated way to determine this
    },
    twitch: {
        jwtMaxLen: 64*10, // TODO: Come up with an automated way to determine this
        claimsToReveal: ["iss", "aud", "nonce"],
        maxSubstrLen: 21, // TODO: Come up with an automated way to determine this
    }
}