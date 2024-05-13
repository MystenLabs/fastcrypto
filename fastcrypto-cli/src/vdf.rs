// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use fastcrypto_vdf::class_group::discriminant::Discriminant;
use fastcrypto_vdf::class_group::QuadraticForm;
use fastcrypto_vdf::math::parameterized_group::Parameter;
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
    /// The hex encoded discriminant.
    #[clap(short, long)]
    discriminant: String,

    /// The hex encoded input to the VDF.
    #[clap(long)]
    input: String,

    /// The number of iterations.
    #[clap(long)]
    iterations: u64,
}

#[derive(Parser, Clone)]
struct VerifyArguments {
    /// The hex encoded discriminant.
    #[clap(short, long)]
    discriminant: String,

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
    /// The hex encoded discriminant.
    #[clap(short, long)]
    discriminant: String,

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
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = bcs::from_bytes::<Discriminant>(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

            let input_bytes = hex::decode(arguments.input)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input point."))?;
            let g = bcs::from_bytes::<QuadraticForm>(&input_bytes).map_err(|_| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid input point or discriminant.",
                )
            })?;
            if g.discriminant() != discriminant {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Input point does not match discriminant.",
                ));
            }

            let vdf = DefaultVDF::new(discriminant, arguments.iterations);
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
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = bcs::from_bytes::<Discriminant>(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

            let input =
                bcs::from_bytes::<QuadraticForm>(&hex::decode(arguments.input).map_err(|_| {
                    Error::new(ErrorKind::InvalidInput, "Invalid output hex string.")
                })?)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid input."))?;
            if input.discriminant() != discriminant {
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
            if output.discriminant() != discriminant {
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
            if proof.discriminant() != discriminant {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Proof has wrong discriminant.",
                ));
            }

            let vdf = DefaultVDF::new(discriminant, arguments.iterations);
            let verifies = vdf.verify(&input, &output, &proof).is_ok();

            let mut result = "Verified: ".to_string();
            result.push_str(&verifies.to_string());
            Ok(result)
        }
        Command::Hash(arguments) => {
            let discriminant_bytes = hex::decode(arguments.discriminant)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;
            let discriminant = bcs::from_bytes(&discriminant_bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid discriminant."))?;

            let input = hex::decode(arguments.message)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid message."))?;
            let output =
                QuadraticForm::hash_to_group_with_default_parameters(&input, &discriminant)
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidInput, "The k parameter was too big")
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
        let discriminant = "8103ff4c32a3d87b3f8bf52fd7c90709480644f84515c11fe7d7884cbce17b64570360148d49faf2a7f93c7d50d68ddba3042718695dfef15759ff8661986f3d2bd86e192a1419f81888adcb15ca9b9819b69fdfaaa17df63d12efb730e1ff3d7f87f04f99928704428ccd93970adef8d06c02b58f755ccb9393fe2b31c9e6c71dbdaf48253fe0b4f0715c438c62dbce5104eb235480d01e3ed7800d965891c98c8eae2743f9bf246ebc6ea33684422d21ac303a403360a5fe19691886dba70a3371b2322c1d61e95c19405eca563933246c87fc3718471438a27ed719e867bc7a7f10bc796d99c79817cddb7c009ca793d5e04446bd4e0ff0020ee3dd72c310db40bfbf229cdaac472ff34c474e1d49cc8e1972890dfbf9a521025f3078ee8df13d8fcb921d0e41e2b07be23c63ee93dcabd2d57a56293617da4a84fb338380bd6ec5a95e320f7f6fcdbf3e12ada0b2e3f1b0f57fc97e6d85e4bb05f7e9bb5a4e6ec0f8441860e4d6da60e8798833ab0ca010a99cf6387b8fbf1a32d888dccdeeb451".to_string();
        let input = "bc01009ed67199c633da0faa75a8ed0ff5c3ae7c278c79aad85953cdf86d57101b1ee941e5239b7d614e5b16eac269c460f16d57a12c75b52c48fac643a1c4918fab86805fe08fcd6b38093a17143cca7550fd018b8bc6871fb441b406bec7a7f3a61c3b2a5aa9daca5f9a6fa474b270688de643323de1acc8073a3418bc1681a614c1abb5fa56b61a7d6df4260547c9f613c5f0dbd7cb91a478ac94b1cce6b1f4784dc161ec3c85bf02cf99fd460b0b25a44d1990dacd1fe7a43b797611ea0210645fef3905f7e1accf97bd3b868a8a99d4a1a546e5a55e20f343fc2724829f1770591b50a73c93ec9b8c01ce1fa6b84eddd5a7ddd077110e21b8e058bf2fed2592a5449db177ec0e32595b20bda5779c2f346b01df8c0d277d9d3a7fe0a04e67b210be60334efdadb7abc5ac001b71509c2d487d9d26443527c1b8b02dfcffc50ef98020f569cdf6fffca5870b0e502493fceee35b79eed99e2c758a0aff4c86b2af0dd223e270ecf84eb7405fe35a9e37d6b080efa3c59806c2ceffa82f38502f9d37b6c298cf07534347cd9ee436406784bd7e0a57d380dd3923ddca13d86f3b2c83a135f125f9429a6802247a0e926b54144d74e4e8f66f0303cdc91843ce7e1fb9c6276c000512c0709c7fbfde2b80e66db77222447ef6b4da4a698e011c6de95ad88738aea465c158288a54223c7f7152577cc48691af57e2631e3224b7c94e2a4c5034db35bbf9e807753fa51da8798bf63b7e6ebd857ca4cf01fcab7a33e63fa89eb386e2ef98046c44491bdf8d62ede2af4ab79ccac88e404abb649b92f49c9f9abcf2216bb628e96400a75a66c12b6ff1c6dae498dd4183ad989921ebc6a1be73127741333671eb72cd25eabc69fecc3c50da06b4a3af155264d4e39e8c681b8c5555d4cab748ed15d119527820e01854fa203c2deba3a67620d47733919e8c71d659e60e86db69905ebdc4dbeda67f77291c2202b2116a05f227f963a97eb8c87104b2df349f01f251aa22bbd41541998ce755309b98d9597d7ee26b6acaef1869885c775e6ceb710c36c07e401e17a8ccb838e33f64e43e4db3491b5cef6e800c4e494610ab81a8b489263b86976160d7d0106cab79bf2a2fce5b01e8f9d1fb069a98e814c94f10d9917b7ea27209bc822b35741f56a9aeadb75a7eae6a8cbd7df08e079db64fd48655f42c24c14bb6c72e744206a3e15deee45cab74d589deb1055e0e69fe508a2ef356dc4e2caaaf89f44a520722490374eade8573429d0d6d16e3c681853f96759cc6e3ea3aaad55284282abd40686281ff944c6a507086143cf76d0f7f93b486d552fa4698656cff8a325fea84943333645b29ee11c99555b2076a09466f6e602db663e1bd45c523a12a7fcd2328d5139d14b25561b94f62f69d436c5d4c92b01ae3a91baa1b5781bd0bf2156e1d0042ab2cbc6e10f4389868fc41d05b19bfe3dfcaacb0478b3dce887da8435c9d49f457fd54e129133e5ce87c39acb9206213daec867fca35e6b612c523fb9fba959542a777ea74".to_string();
        let iterations = 100u64;
        let result = execute(Command::Evaluate(EvaluateArguments {
            discriminant,
            input: input.clone(),
            iterations,
        }))
        .unwrap();
        let expected = "Output: c001503be6eff558a40ba145da5aa9d1270367f32cde44c1601846cdd3d0911abce8ab6adb6b82682b45107545e9ae1efca44dd6f3ba8d95a687652b94f479f6b1a37156c44194d6bc5f266098b75251b12de6fa67de6aea14250c0481694db5f24db5e3c89da3354aafc10c4bd0371f9a175d1b5b193190c4c1089ed7a95dc07f1ce29021b55f3aaa7eb65725d61277f0996b783c005a919ba121d81f211f63d188ac525056235504fe4858765dc6498362d98e8540287a0ff78424c18de53abe46c0014f847bd49f599960fe3c3b7cfc571cd854c7d21b0e9984070f7e168c872a6e6480d8fd37d30602f57a237b83ae961e6a4acb94b78c32d04f06058bda037d6ad313c81f823db25c53c265b02a29008f727f95010c82b0cf8745e77a7f4000dac929ba83a4594482b4e6ff59c93a78df5c816f244914329c145e288fd3fd4800a1cc2df23f386112e569608e6de40ee65fe870960b4e3fee4bb188d8db0dd5df3c2384eb24a797eb20cf8524d563663ccde866a405e2713cfafdb760e50c77a797c10100a31fc5ca0a91aa788d5f5df17a1433f1a0e6e4da440ce935b1b48dc6868c8fc00d7ee725ce21797a6c4440af02570466081479e99eee1a5b509a3e1ac2e000ed386c35d9fadd130df2a292fa5f9aa2c195c48c9d11e58ac98c8dbd2169721ed2d2c9f5544de17deeaa9655360ed7baa46820f5e008af1e3f028d819dee3fee50ab55b266385dfc8f65f7f0c1b6149e5295bfefb83b14db3a30b2cefd1495ba4e5ae39d2b729f9644fc28764d03243fad3e61145ed83cbf2708b60c0b7cac7148\nProof:  0101010180032cf35709e1301d02b40a0dbe3dadfe6ec1eeba8fb8060a1decd0c7a126ea3f27fadcad81435601b0e0abca5c89173ef639e5a88043aa29801e6799e430b509e479b57af981f9ddd48d3a8d5919f99258081557a08270bb441233c78030a01e03ec199b5e3eef5ccc9b1a3d4841cbe4ff529c22a8cd1b1b0075338d864e3890942df6b007d2c3e3a8ef1ce7490c6bbec5372adfcbf8704a1ffc9a69db8d9cdc54762f019036e450e457325eef74b794f3f16ff327d68079a5b9de49163d7323937374f8a785a8f9afe84d6a71b336e4de00f239ee3af1d7604a3985e610e1603bd0e1a4998e19fa0c8920ffd8d61b0a87eeee50ac7c03ff7c4708a34f3bc92fd0103758c954ee34032cee2c78ad8cdc79a35dbc810196b7bf6833e1c45c83b09c0d1b78bc6f8753e10770e7045b08d50b4aa16a75b27a096d5ec1331f1fd0a44e95a8737c20240c90307b5497d3470393c2a00da0649e86d13e820591296c644fc1eef9e7c6ca4967c5e19df3153cd7fbd598c271e11c10397349ddc8cc8452ec";
        assert_eq!(expected, result);

        let invalid_discriminant = "abcx".to_string();
        assert!(execute(Command::Evaluate(EvaluateArguments {
            discriminant: invalid_discriminant,
            input,
            iterations,
        }))
        .is_err());
    }

    #[test]
    fn test_verify() {
        let discriminant = "8103ff4c32a3d87b3f8bf52fd7c90709480644f84515c11fe7d7884cbce17b64570360148d49faf2a7f93c7d50d68ddba3042718695dfef15759ff8661986f3d2bd86e192a1419f81888adcb15ca9b9819b69fdfaaa17df63d12efb730e1ff3d7f87f04f99928704428ccd93970adef8d06c02b58f755ccb9393fe2b31c9e6c71dbdaf48253fe0b4f0715c438c62dbce5104eb235480d01e3ed7800d965891c98c8eae2743f9bf246ebc6ea33684422d21ac303a403360a5fe19691886dba70a3371b2322c1d61e95c19405eca563933246c87fc3718471438a27ed719e867bc7a7f10bc796d99c79817cddb7c009ca793d5e04446bd4e0ff0020ee3dd72c310db40bfbf229cdaac472ff34c474e1d49cc8e1972890dfbf9a521025f3078ee8df13d8fcb921d0e41e2b07be23c63ee93dcabd2d57a56293617da4a84fb338380bd6ec5a95e320f7f6fcdbf3e12ada0b2e3f1b0f57fc97e6d85e4bb05f7e9bb5a4e6ec0f8441860e4d6da60e8798833ab0ca010a99cf6387b8fbf1a32d888dccdeeb451".to_string();
        let iterations = 100u64;
        let input = "bc01009ed67199c633da0faa75a8ed0ff5c3ae7c278c79aad85953cdf86d57101b1ee941e5239b7d614e5b16eac269c460f16d57a12c75b52c48fac643a1c4918fab86805fe08fcd6b38093a17143cca7550fd018b8bc6871fb441b406bec7a7f3a61c3b2a5aa9daca5f9a6fa474b270688de643323de1acc8073a3418bc1681a614c1abb5fa56b61a7d6df4260547c9f613c5f0dbd7cb91a478ac94b1cce6b1f4784dc161ec3c85bf02cf99fd460b0b25a44d1990dacd1fe7a43b797611ea0210645fef3905f7e1accf97bd3b868a8a99d4a1a546e5a55e20f343fc2724829f1770591b50a73c93ec9b8c01ce1fa6b84eddd5a7ddd077110e21b8e058bf2fed2592a5449db177ec0e32595b20bda5779c2f346b01df8c0d277d9d3a7fe0a04e67b210be60334efdadb7abc5ac001b71509c2d487d9d26443527c1b8b02dfcffc50ef98020f569cdf6fffca5870b0e502493fceee35b79eed99e2c758a0aff4c86b2af0dd223e270ecf84eb7405fe35a9e37d6b080efa3c59806c2ceffa82f38502f9d37b6c298cf07534347cd9ee436406784bd7e0a57d380dd3923ddca13d86f3b2c83a135f125f9429a6802247a0e926b54144d74e4e8f66f0303cdc91843ce7e1fb9c6276c000512c0709c7fbfde2b80e66db77222447ef6b4da4a698e011c6de95ad88738aea465c158288a54223c7f7152577cc48691af57e2631e3224b7c94e2a4c5034db35bbf9e807753fa51da8798bf63b7e6ebd857ca4cf01fcab7a33e63fa89eb386e2ef98046c44491bdf8d62ede2af4ab79ccac88e404abb649b92f49c9f9abcf2216bb628e96400a75a66c12b6ff1c6dae498dd4183ad989921ebc6a1be73127741333671eb72cd25eabc69fecc3c50da06b4a3af155264d4e39e8c681b8c5555d4cab748ed15d119527820e01854fa203c2deba3a67620d47733919e8c71d659e60e86db69905ebdc4dbeda67f77291c2202b2116a05f227f963a97eb8c87104b2df349f01f251aa22bbd41541998ce755309b98d9597d7ee26b6acaef1869885c775e6ceb710c36c07e401e17a8ccb838e33f64e43e4db3491b5cef6e800c4e494610ab81a8b489263b86976160d7d0106cab79bf2a2fce5b01e8f9d1fb069a98e814c94f10d9917b7ea27209bc822b35741f56a9aeadb75a7eae6a8cbd7df08e079db64fd48655f42c24c14bb6c72e744206a3e15deee45cab74d589deb1055e0e69fe508a2ef356dc4e2caaaf89f44a520722490374eade8573429d0d6d16e3c681853f96759cc6e3ea3aaad55284282abd40686281ff944c6a507086143cf76d0f7f93b486d552fa4698656cff8a325fea84943333645b29ee11c99555b2076a09466f6e602db663e1bd45c523a12a7fcd2328d5139d14b25561b94f62f69d436c5d4c92b01ae3a91baa1b5781bd0bf2156e1d0042ab2cbc6e10f4389868fc41d05b19bfe3dfcaacb0478b3dce887da8435c9d49f457fd54e129133e5ce87c39acb9206213daec867fca35e6b612c523fb9fba959542a777ea74".to_string();
        let output = "c001503be6eff558a40ba145da5aa9d1270367f32cde44c1601846cdd3d0911abce8ab6adb6b82682b45107545e9ae1efca44dd6f3ba8d95a687652b94f479f6b1a37156c44194d6bc5f266098b75251b12de6fa67de6aea14250c0481694db5f24db5e3c89da3354aafc10c4bd0371f9a175d1b5b193190c4c1089ed7a95dc07f1ce29021b55f3aaa7eb65725d61277f0996b783c005a919ba121d81f211f63d188ac525056235504fe4858765dc6498362d98e8540287a0ff78424c18de53abe46c0014f847bd49f599960fe3c3b7cfc571cd854c7d21b0e9984070f7e168c872a6e6480d8fd37d30602f57a237b83ae961e6a4acb94b78c32d04f06058bda037d6ad313c81f823db25c53c265b02a29008f727f95010c82b0cf8745e77a7f4000dac929ba83a4594482b4e6ff59c93a78df5c816f244914329c145e288fd3fd4800a1cc2df23f386112e569608e6de40ee65fe870960b4e3fee4bb188d8db0dd5df3c2384eb24a797eb20cf8524d563663ccde866a405e2713cfafdb760e50c77a797c10100a31fc5ca0a91aa788d5f5df17a1433f1a0e6e4da440ce935b1b48dc6868c8fc00d7ee725ce21797a6c4440af02570466081479e99eee1a5b509a3e1ac2e000ed386c35d9fadd130df2a292fa5f9aa2c195c48c9d11e58ac98c8dbd2169721ed2d2c9f5544de17deeaa9655360ed7baa46820f5e008af1e3f028d819dee3fee50ab55b266385dfc8f65f7f0c1b6149e5295bfefb83b14db3a30b2cefd1495ba4e5ae39d2b729f9644fc28764d03243fad3e61145ed83cbf2708b60c0b7cac7148".to_string();
        let proof = "0101010180032cf35709e1301d02b40a0dbe3dadfe6ec1eeba8fb8060a1decd0c7a126ea3f27fadcad81435601b0e0abca5c89173ef639e5a88043aa29801e6799e430b509e479b57af981f9ddd48d3a8d5919f99258081557a08270bb441233c78030a01e03ec199b5e3eef5ccc9b1a3d4841cbe4ff529c22a8cd1b1b0075338d864e3890942df6b007d2c3e3a8ef1ce7490c6bbec5372adfcbf8704a1ffc9a69db8d9cdc54762f019036e450e457325eef74b794f3f16ff327d68079a5b9de49163d7323937374f8a785a8f9afe84d6a71b336e4de00f239ee3af1d7604a3985e610e1603bd0e1a4998e19fa0c8920ffd8d61b0a87eeee50ac7c03ff7c4708a34f3bc92fd0103758c954ee34032cee2c78ad8cdc79a35dbc810196b7bf6833e1c45c83b09c0d1b78bc6f8753e10770e7045b08d50b4aa16a75b27a096d5ec1331f1fd0a44e95a8737c20240c90307b5497d3470393c2a00da0649e86d13e820591296c644fc1eef9e7c6ca4967c5e19df3153cd7fbd598c271e11c10397349ddc8cc8452ec".to_string();
        let result = execute(Command::Verify(VerifyArguments {
            discriminant: discriminant.clone(),
            iterations,
            input: input.clone(),
            output: output.clone(),
            proof: proof.clone(),
        }))
        .unwrap();
        let expected = "Verified: true";
        assert_eq!(expected, result);

        let invalid_discriminant = "abcx".to_string();
        assert!(execute(Command::Verify(VerifyArguments {
            discriminant: invalid_discriminant,
            iterations,
            input: input.clone(),
            output: output.clone(),
            proof: proof.clone(),
        }))
        .is_err());

        let other_iterations = 2000u64;
        let result = execute(Command::Verify(VerifyArguments {
            discriminant,
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
        let discriminant = "8103ff4c32a3d87b3f8bf52fd7c90709480644f84515c11fe7d7884cbce17b64570360148d49faf2a7f93c7d50d68ddba3042718695dfef15759ff8661986f3d2bd86e192a1419f81888adcb15ca9b9819b69fdfaaa17df63d12efb730e1ff3d7f87f04f99928704428ccd93970adef8d06c02b58f755ccb9393fe2b31c9e6c71dbdaf48253fe0b4f0715c438c62dbce5104eb235480d01e3ed7800d965891c98c8eae2743f9bf246ebc6ea33684422d21ac303a403360a5fe19691886dba70a3371b2322c1d61e95c19405eca563933246c87fc3718471438a27ed719e867bc7a7f10bc796d99c79817cddb7c009ca793d5e04446bd4e0ff0020ee3dd72c310db40bfbf229cdaac472ff34c474e1d49cc8e1972890dfbf9a521025f3078ee8df13d8fcb921d0e41e2b07be23c63ee93dcabd2d57a56293617da4a84fb338380bd6ec5a95e320f7f6fcdbf3e12ada0b2e3f1b0f57fc97e6d85e4bb05f7e9bb5a4e6ec0f8441860e4d6da60e8798833ab0ca010a99cf6387b8fbf1a32d888dccdeeb451".to_string();
        let seed = "abcd".to_string();
        let result = execute(Command::Hash(HashArguments {
            discriminant: discriminant.clone(),
            message: seed.clone(),
        }))
        .unwrap();
        let expected = "Output: bc010082ee2d187c87dd0253b19d73db019c2f11e29ee9a70ff48082860c05c17f8e786276e999605f086e3d58124f378e06ff904aa3f623f5fd1903d23b381a2b1abc23ea3004f84defb5d1c7c825134305373308a7c287110cce7ff96fed79b366d4272ef03226aecdce76b5f6f946bff527e56391a3f72682403f8f48a584ba6769a96ed0742d299060759f8ba227ff87011035dc097b54a76f4c7ed7d60a530f92500d7228b15ac3addceea196a341b4f06217d5881952025e650e81ea02247f8e37e7ddede21f1f8e34fc1d23aafcfddd9cae9c9fe068b069591abd638bf143b2e7ca646c298a69883dac05dec9b9c77d211f06dd0325b851a464b34d0a4084363c5b8c4fea79d38544f7d583d55931374c467239fd4ba7ba3a9d2ef0457d910c18e42575ff039da6814e585238647f910eb90bd78b750ee315ebbb67703168c9f25d3484191093d7e99ed160041d27188165eef767d6cfe735037a8d33c670087a0c4be4c404022525f2261ce411d4f2afa2c450891eed6ad1fe2ec72d361e3d73a63da32fc8e5f445fe1d559dcc41a13e87bba38827cc5da40ad097da50617b216c4ad7aa6c50a20b0b840273b671e2027f8a3acb3651d9fc8e45ede649d232df111bf9c49c68afc0e699ef359e86e8912d0902b6e908988f6994b51ae2f8ab1a26a0bf96ee722d05f7cddf61d25899645648de8821de536d6175d2d28729c6f56a99fbf383043bccc3183a45ea3b3b4d599443c5672d9a26e6e2d7475bb8b76bcc5d393bc3939904028b278613c65986c0529d0ed75d26567154d61029833cff4bda9e3649b2b7196e43b5182b2b2b27020cf99d90de2aa3f927ea03453352855508a39466098b211f486a5c83ce48005287a2d941c734d93abe091e08860f28a462ea061f060129da80d7998d7cf036be70248c5b96582de577929fae4e77e8ea61419dd6571894e892c57153e79fd80ab68bc1b248a15841e5f91943fc4b71d6e5f841ed6dffca3bef0dafa79211aa607f55d5fa5cd0225d9a9cb26d0438ebaa402019f84ac75aeecb40d2fc75fc9449f117f98c230ad561771a8c621a3bfc2116017549eccd9a52f51a6eb0992d57042f684e95f5a12481c570ff57167be444c7f0b71c2aba4178253f577b488d6007f1ea4d8c05b663c539c334a8fcbb91284881dda609ee18f8133c98dc815ce17154a5bbfb380250895455b6c6ce227de43e8fa0b593e39deb4d280e92579dc344972361372ee1cd1c40197bcbec2262d43331acab5ae8bb0a70b87e7d503c40867b43febefedf7a59dabab669c6e94fc321d2a67816e36b982b21a5914eb0f5e5b343f5d6e0c7db24476ca3a18ae3f4d5fff78d7fc917272db5f21db999faa6626243aeb3d9f2939c0ddc06c94aae74fa58c903fd56ff634ec1eaafb3a7965318946f45473fc3ddea8f9972ea73645bfe132569514e40ac9b9abddcd6fe5623573e3ab724eb2adab38d9064b259952ac83ee999ddea5edae12a0e4d08822c4c9e499f498ca66da90272bf6d3d41ad0d86";
        assert_eq!(expected, result);
    }
}
