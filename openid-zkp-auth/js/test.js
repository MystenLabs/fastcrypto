const temp = require("temp");
const path = require("path");
const fs = require("fs");

const circom_wasm = require("circom_tester").wasm;

async function genMain(template_file, template_name, params = [], file_name) {
    temp.track();
    
    const temp_circuit = await temp.open({prefix: template_name, suffix: ".circom"});
    const include_path = path.relative(temp_circuit.path, template_file);
    const params_string = JSON.stringify(params).slice(1, -1);
    
    fs.writeSync(temp_circuit.fd, `
pragma circom 2.0.0;

include "${include_path}";

component main = ${template_name}(${params_string});
    `);

    if (file_name !== undefined) {
      fs.copyFileSync(temp_circuit.path, file_name);
    }
    
    return circom_wasm(temp_circuit.path);
}

module.exports = {
  genMain: genMain
}
