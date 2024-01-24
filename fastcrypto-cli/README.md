```
cargo build --bin mnemonics-cli

# to generate a new one

target/release/mnemonics-cli generate
12 word mnemonic: "absurd amused much remove source abandon abandon abandon abandon cactus barely actual"
Public key: hgacKLTiEEvy34Dm2T6Wbq30IX/l/tLEmfFXPx0Ia7s=
Entropy: [1, 1, 6, 68, 90, 253, 0, 0, 0, 0, 0, 0, 4, 0, 74, 1]
Bit array: "0000000100000 0010000011001 0001000101101 0111111010000 0000000000000 0000000000000 0000000000000 0000000000100 0000000001001 01000000001"
8 word mnemonic: "33word-0 1050word-0 558word-0 4049word-4 1word-5 1word-0 1word-0 5word-1"
8 word partial mnemonic: "33word- 1050word- 558word- 4049word- 1word- 1word- 1word- 5word-"

# recover a partial 8-word without digits to 12-word with a target pk

target/release/mnemonics-cli recover-full-mnemonics --short "33word- 1050word- 558word- 4049word- 1word- 1word- 1word- 5word-" --target-pk hgacKLTiEEvy34Dm2T6Wbq30IX/l/tLEmfFXPx0Ia7s=

Partial bit array (missing last 24 bit): "0000000100000 0010000011001 0001000101101 0111111010000 0000000000000 0000000000000 0000000000000 0000000000100 0000000000000 00000000000"
Private key found, 12-word legacy mnemonics: "absurd amused much remove source abandon abandon abandon abandon cactus barely actual"
Last 8 digits: [0, 0, 0, 4, 5, 0, 0, 1]
Full 8-word mnemonics: "33word-0 1050word-0 558word-0 4049word-4 1word-5 1word-0 1word-0 5word-1"
Time elapsed: 24.832128792s
```