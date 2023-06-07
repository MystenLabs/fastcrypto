// Code copied from iden3/rapidsnark/tools/request.js

const fs = require("fs");
const fetch = require('node-fetch');

const input = fs.readFileSync(process.argv[2], "utf8");
const circuit = process.argv[3];

async function callInput() {
    const rawResponse = await fetch(`http://185.209.177.123:9080/input/${circuit}`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: input
    });
    if (rawResponse.ok) {
        return true;
    } else {
        throw new Error(rawResponse.status);
    }
};


async function getStatus() {
    const rawResponse = await fetch('http://185.209.177.123:9080/status', {
        method: 'GET',
        headers: {
            'Accept': 'application/json'
        }
    });
    if (!rawResponse.ok) {
        throw new Error(rawResponse.status);
    }
    return rawResponse.json();
}

async function run() {
    await callInput();
    let st;
    st = await getStatus();
    while (st.status == "busy") {
        st = await getStatus();
    }
    console.log(JSON.stringify(st, null,1));
}

run().then(() => {
    process.exit(0);
}, (err) => {
    console.log("ERROR");
    console.log(err);
    process.exit(1);
});
