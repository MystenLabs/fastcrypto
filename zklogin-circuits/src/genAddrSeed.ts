import { deriveAddrSeed } from './utils';
import { constants } from './common';

if (require.main === module) {
    const claimValue = process.argv[2];
    if (!claimValue) {
        console.log("Usage: ts-node genAddrSeed.ts <claim_value>");
        process.exit(1);
    }

    let pin = process.argv[3];
    if (!pin) {
        pin = constants.dev.pin.toString();
        console.log("Using default pin:", pin);
    }

    (async () => {
        try {
            const res = await deriveAddrSeed(claimValue, BigInt(pin));
            console.log(res.toString());
            process.exit(0);
        }
        catch (err) {
            console.error("Error:", (err as Error).message);
        }
    })();
}
