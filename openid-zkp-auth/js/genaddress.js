const utils = require('./utils');

const outWidth = require("./constants").outWidth;
const pin = require("./constants").pin;
const maxSubLength = require("./constants").google.maxSubstrLen;

if (require.main === module) {
    const subjectID = '"sub":110463452167303598383';

    (async () => {
        try {
            await utils.commitSubID(subjectID, pin, maxSubLength, outWidth).then(function (res) {
                console.log(res);
            });
            process.exit(0);
        }
        catch (err) {
            console.error("Error:", err.message);
        }
    })();
}