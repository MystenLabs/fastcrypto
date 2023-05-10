const circuitutils = require('./circuitutils');

if (require.main === module) {
    (async () => {
        try {
            await circuitutils.computeNonce().then(function (res) {
                console.log("nonce", res);
            });
            process.exit(0);
        }
        catch (err) {
            console.error("Error:", err.message);
        }
    })();
}