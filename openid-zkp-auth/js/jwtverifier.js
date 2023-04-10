// jwtVerifierRS256JWK.js
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

// JWT Token, JWK Public Key
const verifyJwt = (token, jwkPublicKey) => {
  try {
    // Convert the JWK to PEM format
    const publicKey = jwkToPem(jwkPublicKey);

    const verifyOptions = {
        algorithms: ["RS256"],
        ignoreExpiration: true
    };
  
    const decoded = jwt.verify(token, publicKey, verifyOptions);
    console.log("JWT is valid:", decoded);
  } catch (error) {
    console.error("Invalid JWT:", error.message);
  }
};

module.exports = verifyJwt;
