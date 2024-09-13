// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto_vdf::class_group::discriminant::{Discriminant, DISCRIMINANT_3072};
use fastcrypto_vdf::class_group::QuadraticForm;
use fastcrypto_vdf::math::parameterized_group::ParameterizedGroupElement;
use fastcrypto_vdf::vdf::wesolowski::DefaultVDF;
use fastcrypto_vdf::vdf::VDF;
use std::io::{Error, ErrorKind};

/// This discriminant size is based on a lower bound from "Trustless unkown-order groups" by Dobson et al.
/// (https://inria.hal.science/hal-02882161/file/unknown-order.pdf)
///
/// A discriminant size of 3072 bits ensures that the computational hardness of computing the group order of a group
/// with a randomly chosen discriminant is at least 128 bits with probability at least 1 - 2^{-40}.
const DEFAULT_DISCRIMINANT_BIT_LENGTH: u64 = 3072;

#[derive(Parser)]
#[command(name = "vdf-cli")]
#[command(about = "Verifiable delay function using Wesolowski's construction over imaginary class groups", long_about = None)]
enum Command {
    /// Sample a random discriminant from a seed.
    Discriminant(DiscriminantArguments),

    /// Compute VDF output and proof.
    Evaluate(EvaluateArguments),

    /// Verify an output .
    Verify(VerifyArguments),

    /// Hash a binary message to a quadratic form.
    Hash(HashArguments),
}

#[derive(Parser, Clone)]
struct DiscriminantArguments {
    /// The hex encoded discriminant.
    #[clap(short, long)]
    seed: String,

    /// Bit length of the discriminant (default is 3072).
    #[clap(short, long, default_value_t = DEFAULT_DISCRIMINANT_BIT_LENGTH)]
    bit_length: u64,
}

#[derive(Parser, Clone)]
struct EvaluateArguments {
    /// The hex encoded input to the VDF.
    #[clap(long)]
    input: String,

    /// The number of iterations.
    #[clap(long)]
    iterations: u64,
}

#[derive(Parser, Clone)]
struct VerifyArguments {
    /// Iterations
    #[clap(long)]
    iterations: u64,

    /// The input to the VDF.
    #[clap(long)]
    input: String,

    /// The output of the VDF.
    #[clap(short, long)]
    output: String,

    /// The proof of the correctness of the VDF output.
    #[clap(short, long)]
    proof: String,
}

#[derive(Parser, Clone)]
struct HashArguments {
    /// The hex encoded input to the hash function.
    #[clap(short, long)]
    message: String,
}

fn main() {
    match execute(Command::parse()) {
        Ok(res) => {
            println!("{}", res);
            std::process::exit(exitcode::OK);
        }
        Err(e) => {
            println!("Error: {}", e);
            std::process::exit(exitcode::DATAERR);
        }
    }
}

fn execute(cmd: Command) -> Result<String, Error> {
    match cmd {
        Command::Discriminant(arguments) => {
            let seed = hex::decode(arguments.seed)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid seed."))?;
            let discriminant =
                Discriminant::from_seed(&seed, arguments.bit_length as usize).unwrap();
            let discriminant_string = hex::encode(bcs::to_bytes(&discriminant).unwrap());
            let mut result = "Discriminant: ".to_string();
            result.push_str(&discriminant_string);
            Ok(result)
        }

        Command::Evaluate(arguments) => {
            let input_bytes = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input point."))?;
            let g = bcs::from_bytes::<QuadraticForm>(&input_bytes).map_err(|_| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid input point or discriminant.",
                )
            })?;
            if !g.is_in_group(&DISCRIMINANT_3072) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Input point does not match discriminant.",
                ));
            }

            let vdf = DefaultVDF::new(DISCRIMINANT_3072.clone(), arguments.iterations);
            let (output, proof) = vdf
                .evaluate(&g)
                .map_err(|_| Error::new(ErrorKind::Other, "VDF evaluation failed"))?;

            let output_string = hex::encode(bcs::to_bytes(&output).unwrap());
            let proof_string = hex::encode(bcs::to_bytes(&proof).unwrap());

            let mut result = "Output: ".to_string();
            result.push_str(&output_string);
            result.push_str("\nProof:  ");
            result.push_str(&proof_string);
            Ok(result)
        }

        Command::Verify(arguments) => {
            let input =
                bcs::from_bytes::<QuadraticForm>(&hex::decode(arguments.input).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid output hex string.")
                })?)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input."))?;
            if !input.is_in_group(&DISCRIMINANT_3072) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Input has wrong discriminant.",
                ));
            }

            let output =
                bcs::from_bytes::<QuadraticForm>(&hex::decode(arguments.output).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid output hex string.")
                })?)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid output."))?;
            if !output.is_in_group(&DISCRIMINANT_3072) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Output has wrong discriminant.",
                ));
            }

            let proof =
                bcs::from_bytes::<QuadraticForm>(&hex::decode(arguments.proof).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid proof hex string.")
                })?)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid proof."))?;
            if !proof.is_in_group(&DISCRIMINANT_3072) {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Proof has wrong discriminant.",
                ));
            }

            let vdf = DefaultVDF::new(DISCRIMINANT_3072.clone(), arguments.iterations);
            let verifies = vdf.verify(&input, &output, &proof).is_ok();

            let mut result = "Verified: ".to_string();
            result.push_str(&verifies.to_string());
            Ok(result)
        }
        Command::Hash(arguments) => {
            let input = hex::decode(arguments.message)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid message."))?;
            let output =
                QuadraticForm::hash_to_group_with_default_parameters(&input, &DISCRIMINANT_3072)
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidInput, "The discriminant is invalid.")
                    })?;

            let output_bytes = hex::encode(bcs::to_bytes(&output).unwrap());

            let mut result = "Output: ".to_string();
            result.push_str(&output_bytes);
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        execute, Command, DiscriminantArguments, EvaluateArguments, HashArguments, VerifyArguments,
    };

    #[test]
    fn test_discriminant() {
        let seed = "abcd".to_string();
        let result = execute(Command::Discriminant(DiscriminantArguments {
            seed,
            bit_length: 1024,
        }))
        .unwrap();
        let expected = "Discriminant: 8101ff00934fb3e9ece6df62bc7490fe9563c8fc496010c448feaaf14aa9584d20137989988d7d0d22f93a9773aebc63a61a1e061017cfa20e6a8294840cbccb6c99797f174744fad9d3420b2fdf250572a5cbcce66474ac092b784c0c85b54a6b6c0faf2e1d4aca481641e63fdfefaa3f285f824c5559801f1129c49c279aa79975d9".to_string();
        assert_eq!(expected, result);
    }

    #[test]
    fn test_evaluate() {
        let input = "bc01009ed67199c633da0faa75a8ed0ff5c3ae7c278c79aad85953cdf86d57101b1ee941e5239b7d614e5b16eac269c460f16d57a12c75b52c48fac643a1c4918fab86805fe08fcd6b38093a17143cca7550fd018b8bc6871fb441b406bec7a7f3a61c3b2a5aa9daca5f9a6fa474b270688de643323de1acc8073a3418bc1681a614c1abb5fa56b61a7d6df4260547c9f613c5f0dbd7cb91a478ac94b1cce6b1f4784dc161ec3c85bf02cf99fd460b0b25a44d1990dacd1fe7a43b797611ea0210645fef3905f7e1accf97bd3b868a8a99d4a1a546e5a55e20f343fc2724829f1770591b50a73c93ec9b8c01ce1fa6b84eddd5a7ddd077110e21b8e058bf2fed2592a5449db177ec0e32595b20bda5779c2f346b01df8c0d277d9d3a7fe0a04e67b210be60334efdadb7abc5ac001b71509c2d487d9d26443527c1b8b02dfcffc50ef98020f569cdf6fffca5870b0e502493fceee35b79eed99e2c758a0aff4c86b2af0dd223e270ecf84eb7405fe35a9e37d6b080efa3c59806c2ceffa82f38502f9d37b6c298cf07534347cd9ee436406784bd7e0a57d380dd3923ddca13d86f3b2c83a135f125f9429a6802247a0e926b54144d74e4e8f66f0303cdc91843ce7e1fb9c6276c000512c0709c7fbfde2b80e66db77222447ef6b4da4a698e011c6de95ad88738aea465c158288a54223c7f7152577cc48691af57e2631e3224b7c94e2a4c5034db35bbf9e807753fa51da8798bf63b7e6ebd857ca4cf01fcab7a33e63fa89eb386e2ef98046c44491bdf8d62ede2af4ab79ccac88e404abb649b92f49c9f9abcf2216bb628e96400a75a66c12b6ff1c6dae498dd4183ad989921ebc6a1be73127741333671eb72cd25eabc69fecc3c50da06b4a3af155264d4e39e8c681b8c5555d4cab748ed15d119527820e01854fa203c2deba3a67620d47733919e8c71d659e60e86db69905ebdc4dbeda67f77291c2202b2116a05f227f963a97eb8c87104b2df349f01f251aa22bbd41541998ce755309b98d9597d7ee26b6acaef1869885c775e6ceb710c36c07e401e17a8ccb838e33f64e43e4db3491b5cef6e800c4e494610ab81a8b489263b86976160d7d0106cab79bf2a2fce5b01e8f9d1fb069a98e814c94f10d9917b7ea27209bc822b35741f56a9aeadb75a7eae6a8cbd7df08e079db64fd48655f42c24c14bb6c72e744206a3e15deee45cab74d589deb1055e0e69fe508a2ef356dc4e2caaaf89f44a520722490374eade8573429d0d6d16e3c681853f96759cc6e3ea3aaad55284282abd40686281ff944c6a507086143cf76d0f7f93b486d552fa4698656cff8a325fea84943333645b29ee11c99555b2076a09466f6e602db663e1bd45c523a12a7fcd2328d5139d14b25561b94f62f69d436c5d4c92b01ae3a91baa1b5781bd0bf2156e1d0042ab2cbc6e10f4389868fc41d05b19bfe3dfcaacb0478b3dce887da8435c9d49f457fd54e129133e5ce87c39acb9206213daec867fca35e6b612c523fb9fba959542a777ea74".to_string();
        let iterations = 100u64;
        let result = execute(Command::Evaluate(EvaluateArguments {
            input: input.clone(),
            iterations,
        }))
        .unwrap();
        let expected = "Output: c001503be6eff558a40ba145da5aa9d1270367f32cde44c1601846cdd3d0911abce8ab6adb6b82682b45107545e9ae1efca44dd6f3ba8d95a687652b94f479f6b1a37156c44194d6bc5f266098b75251b12de6fa67de6aea14250c0481694db5f24db5e3c89da3354aafc10c4bd0371f9a175d1b5b193190c4c1089ed7a95dc07f1ce29021b55f3aaa7eb65725d61277f0996b783c005a919ba121d81f211f63d188ac525056235504fe4858765dc6498362d98e8540287a0ff78424c18de53abe46c0014f847bd49f599960fe3c3b7cfc571cd854c7d21b0e9984070f7e168c872a6e6480d8fd37d30602f57a237b83ae961e6a4acb94b78c32d04f06058bda037d6ad313c81f823db25c53c265b02a29008f727f95010c82b0cf8745e77a7f4000dac929ba83a4594482b4e6ff59c93a78df5c816f244914329c145e288fd3fd4800a1cc2df23f386112e569608e6de40ee65fe870960b4e3fee4bb188d8db0dd5df3c2384eb24a797eb20cf8524d563663ccde866a405e2713cfafdb760e50c77a797c10100a31fc5ca0a91aa788d5f5df17a1433f1a0e6e4da440ce935b1b48dc6868c8fc00d7ee725ce21797a6c4440af02570466081479e99eee1a5b509a3e1ac2e000ed386c35d9fadd130df2a292fa5f9aa2c195c48c9d11e58ac98c8dbd2169721ed2d2c9f5544de17deeaa9655360ed7baa46820f5e008af1e3f028d819dee3fee50ab55b266385dfc8f65f7f0c1b6149e5295bfefb83b14db3a30b2cefd1495ba4e5ae39d2b729f9644fc28764d03243fad3e61145ed83cbf2708b60c0b7cac7148\nProof:  0101010180032cf35709e1301d02b40a0dbe3dadfe6ec1eeba8fb8060a1decd0c7a126ea3f27fadcad81435601b0e0abca5c89173ef639e5a88043aa29801e6799e430b509e479b57af981f9ddd48d3a8d5919f99258081557a08270bb441233c78030a01e03ec199b5e3eef5ccc9b1a3d4841cbe4ff529c22a8cd1b1b0075338d864e3890942df6b007d2c3e3a8ef1ce7490c6bbec5372adfcbf8704a1ffc9a69db8d9cdc54762f019036e450e457325eef74b794f3f16ff327d68079a5b9de49163d7323937374f8a785a8f9afe84d6a71b336e4de00f239ee3af1d7604a3985e610e1603bd0e1a4998e19fa0c8920ffd8d61b0a87eeee50ac7c03ff7c4708a34f3bc92fd0103758c954ee34032cee2c78ad8cdc79a35dbc810196b7bf6833e1c45c83b09c0d1b78bc6f8753e10770e7045b08d50b4aa16a75b27a096d5ec1331f1fd0a44e95a8737c20240c90307b5497d3470393c2a00da0649e86d13e820591296c644fc1eef9e7c6ca4967c5e19df3153cd7fbd598c271e11c10397349ddc8cc8452ec";
        assert_eq!(expected, result);
    }

    #[test]
    fn test_verify() {
        let iterations = 100u64;
        let input = "bc01009ed67199c633da0faa75a8ed0ff5c3ae7c278c79aad85953cdf86d57101b1ee941e5239b7d614e5b16eac269c460f16d57a12c75b52c48fac643a1c4918fab86805fe08fcd6b38093a17143cca7550fd018b8bc6871fb441b406bec7a7f3a61c3b2a5aa9daca5f9a6fa474b270688de643323de1acc8073a3418bc1681a614c1abb5fa56b61a7d6df4260547c9f613c5f0dbd7cb91a478ac94b1cce6b1f4784dc161ec3c85bf02cf99fd460b0b25a44d1990dacd1fe7a43b797611ea0210645fef3905f7e1accf97bd3b868a8a99d4a1a546e5a55e20f343fc2724829f1770591b50a73c93ec9b8c01ce1fa6b84eddd5a7ddd077110e21b8e058bf2fed2592a5449db177ec0e32595b20bda5779c2f346b01df8c0d277d9d3a7fe0a04e67b210be60334efdadb7abc5ac001b71509c2d487d9d26443527c1b8b02dfcffc50ef98020f569cdf6fffca5870b0e502493fceee35b79eed99e2c758a0aff4c86b2af0dd223e270ecf84eb7405fe35a9e37d6b080efa3c59806c2ceffa82f38502f9d37b6c298cf07534347cd9ee436406784bd7e0a57d380dd3923ddca13d86f3b2c83a135f125f9429a6802247a0e926b54144d74e4e8f66f0303cdc91843ce7e1fb9c6276c000512c0709c7fbfde2b80e66db77222447ef6b4da4a698e011c6de95ad88738aea465c158288a54223c7f7152577cc48691af57e2631e3224b7c94e2a4c5034db35bbf9e807753fa51da8798bf63b7e6ebd857ca4cf01fcab7a33e63fa89eb386e2ef98046c44491bdf8d62ede2af4ab79ccac88e404abb649b92f49c9f9abcf2216bb628e96400a75a66c12b6ff1c6dae498dd4183ad989921ebc6a1be73127741333671eb72cd25eabc69fecc3c50da06b4a3af155264d4e39e8c681b8c5555d4cab748ed15d119527820e01854fa203c2deba3a67620d47733919e8c71d659e60e86db69905ebdc4dbeda67f77291c2202b2116a05f227f963a97eb8c87104b2df349f01f251aa22bbd41541998ce755309b98d9597d7ee26b6acaef1869885c775e6ceb710c36c07e401e17a8ccb838e33f64e43e4db3491b5cef6e800c4e494610ab81a8b489263b86976160d7d0106cab79bf2a2fce5b01e8f9d1fb069a98e814c94f10d9917b7ea27209bc822b35741f56a9aeadb75a7eae6a8cbd7df08e079db64fd48655f42c24c14bb6c72e744206a3e15deee45cab74d589deb1055e0e69fe508a2ef356dc4e2caaaf89f44a520722490374eade8573429d0d6d16e3c681853f96759cc6e3ea3aaad55284282abd40686281ff944c6a507086143cf76d0f7f93b486d552fa4698656cff8a325fea84943333645b29ee11c99555b2076a09466f6e602db663e1bd45c523a12a7fcd2328d5139d14b25561b94f62f69d436c5d4c92b01ae3a91baa1b5781bd0bf2156e1d0042ab2cbc6e10f4389868fc41d05b19bfe3dfcaacb0478b3dce887da8435c9d49f457fd54e129133e5ce87c39acb9206213daec867fca35e6b612c523fb9fba959542a777ea74".to_string();
        let output = "c001503be6eff558a40ba145da5aa9d1270367f32cde44c1601846cdd3d0911abce8ab6adb6b82682b45107545e9ae1efca44dd6f3ba8d95a687652b94f479f6b1a37156c44194d6bc5f266098b75251b12de6fa67de6aea14250c0481694db5f24db5e3c89da3354aafc10c4bd0371f9a175d1b5b193190c4c1089ed7a95dc07f1ce29021b55f3aaa7eb65725d61277f0996b783c005a919ba121d81f211f63d188ac525056235504fe4858765dc6498362d98e8540287a0ff78424c18de53abe46c0014f847bd49f599960fe3c3b7cfc571cd854c7d21b0e9984070f7e168c872a6e6480d8fd37d30602f57a237b83ae961e6a4acb94b78c32d04f06058bda037d6ad313c81f823db25c53c265b02a29008f727f95010c82b0cf8745e77a7f4000dac929ba83a4594482b4e6ff59c93a78df5c816f244914329c145e288fd3fd4800a1cc2df23f386112e569608e6de40ee65fe870960b4e3fee4bb188d8db0dd5df3c2384eb24a797eb20cf8524d563663ccde866a405e2713cfafdb760e50c77a797c10100a31fc5ca0a91aa788d5f5df17a1433f1a0e6e4da440ce935b1b48dc6868c8fc00d7ee725ce21797a6c4440af02570466081479e99eee1a5b509a3e1ac2e000ed386c35d9fadd130df2a292fa5f9aa2c195c48c9d11e58ac98c8dbd2169721ed2d2c9f5544de17deeaa9655360ed7baa46820f5e008af1e3f028d819dee3fee50ab55b266385dfc8f65f7f0c1b6149e5295bfefb83b14db3a30b2cefd1495ba4e5ae39d2b729f9644fc28764d03243fad3e61145ed83cbf2708b60c0b7cac7148".to_string();
        let proof = "0101010180032cf35709e1301d02b40a0dbe3dadfe6ec1eeba8fb8060a1decd0c7a126ea3f27fadcad81435601b0e0abca5c89173ef639e5a88043aa29801e6799e430b509e479b57af981f9ddd48d3a8d5919f99258081557a08270bb441233c78030a01e03ec199b5e3eef5ccc9b1a3d4841cbe4ff529c22a8cd1b1b0075338d864e3890942df6b007d2c3e3a8ef1ce7490c6bbec5372adfcbf8704a1ffc9a69db8d9cdc54762f019036e450e457325eef74b794f3f16ff327d68079a5b9de49163d7323937374f8a785a8f9afe84d6a71b336e4de00f239ee3af1d7604a3985e610e1603bd0e1a4998e19fa0c8920ffd8d61b0a87eeee50ac7c03ff7c4708a34f3bc92fd0103758c954ee34032cee2c78ad8cdc79a35dbc810196b7bf6833e1c45c83b09c0d1b78bc6f8753e10770e7045b08d50b4aa16a75b27a096d5ec1331f1fd0a44e95a8737c20240c90307b5497d3470393c2a00da0649e86d13e820591296c644fc1eef9e7c6ca4967c5e19df3153cd7fbd598c271e11c10397349ddc8cc8452ec".to_string();
        let result = execute(Command::Verify(VerifyArguments {
            iterations,
            input: input.clone(),
            output: output.clone(),
            proof: proof.clone(),
        }))
        .unwrap();
        let expected = "Verified: true";
        assert_eq!(expected, result);

        let other_iterations = 2000u64;
        let result = execute(Command::Verify(VerifyArguments {
            iterations: other_iterations,
            input,
            output,
            proof,
        }))
        .unwrap();
        let expected = "Verified: false";
        assert_eq!(expected, result);
    }

    #[test]
    fn test_hash() {
        let seed = "abcd".to_string();
        let result = execute(Command::Hash(HashArguments {
            message: seed.clone(),
        }))
        .unwrap();
        let expected = "Output: 227afa0a257a3fa140fad0ba29ade524a7cc097c706a7c59c363fede402870cbf192ef33fc06eddf144b2023a50256b388f8fd5a6ef59dd7275e2f7ae1288bef605158fa97e2af2684604395314a5176a655a940bb3ac3de025d92c53e95f69368f53575775e965be811f89c08d0c9dc702daea57afb3d6e5e48b8255fc93901580f01837abf0a6e94e3a29d6a9bcca669c611d3f94256b72c7a67415391607d89e15a3f82880bae011276e96f097895311e45caaa81dc7b35e3fe97d83cd392e7b94e1ddfa0f684be3e9106e0bda15c0153d2f8a6ba1528b796ca6bd24a5164eed50e63f7cd5837ef7c9a6d52451d66fca2221f04efe44b446896843b1bbf4ebc322d80781259afcc1a5780eedd3cde2cd98e44d3bfadb19a0253b6f0e7f957469e41ce8bc48f9516412b61097c858cc9fac2489f5a6467e1516d8ab93cf7849c34428589110b9d1e3d4d4e114480fe14db77eb545cd13b3a4f6fe43dc9002ec52d1400fbdba8a34ffab8b5200a002f0b13691f635304a2d266bee80263dbe996e03fe8840902922d814d5535f97a2602c24a276b95e48dc802d9e09288f411360ae69357d0c0018474992daa45dc6cde5a2fe02ae9d2";
        assert_eq!(expected, result);
    }
}
