import * as circuitutils from './circuitutils';

if (require.main === module) {
    (async () => {
        try {
            const res = await circuitutils.computeNonce();
            console.log("nonce", res);
            process.exit(0);
        }
        catch (err) {
            console.error("Error:", (err as Error).message);
        }
    })();
}