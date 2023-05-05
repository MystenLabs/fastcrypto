const prove = async (inputsFile, wasmFile, zKeyFile) => {
  console.log("Proving...");
  console.time("fullProve");

  const inputs = await fetch(inputsFile).then( function(res) {
    return res.json();
  });

  const fullProof = await snarkjs.groth16.fullProve(
    inputs,
    wasmFile,
    zKeyFile
  );

  console.log({ fullProof });
  console.timeEnd("fullProve");
};

const verify = async (provider) => {
  if (provider === "google") {
    await prove(
      "./google_inputs.json",
      "../google/google_js/google.wasm",
      "../google/google.zkey"
    );
  } else if (provider === "twitch") {
    await prove(
      "./twitch_inputs.json",
      "../twitch/twitch_js/twitch.wasm",
      "../twitch/twitch.zkey"
    );
  } else {
    console.log("Invalid provider");
  }
};