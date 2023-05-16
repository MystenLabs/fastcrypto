const utils = require('./utils');

if (require.main === module) {
    var claim_value = process.argv[2];
    if (!claim_value) {
        console.log("Usage: node genAddrSeed.js <claim_value>");
        process.exit(1);
    }

    var pin = process.argv[3];
    if (!pin) {
        pin = require("./constants").dev.pin;
        console.log("Using default pin:", pin);
    }

    (async () => {
        try {
            await utils.deriveAddrSeed(
                claim_value, pin
            ).then(function (res) {
                console.log(res);
            });
            process.exit(0);
        }
        catch (err) {
            console.error("Error:", err.message);
        }
    })();
}