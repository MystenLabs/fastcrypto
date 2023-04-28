module.exports = {
    inWidth: 8,
    outWidth: 253,
    nOptions: 7,
    maskValue: '='.charCodeAt(),
    google: {
        jwtMaxLen: 64*12, // TODO: Come up with an automated way to determine this
        claimsToReveal: ["iss", "aud", "nonce"],
        maxSubstrLen: 50, // TODO: Come up with an automated way to determine this
    },
    facebook: {
        jwtMaxLen: 64*15, // TODO: Come up with an automated way to determine this
        claimsToReveal: ["iss", "aud", "nonce"],
        maxSubstrLen: 50, // TODO: Come up with an automated way to determine this
    }
}