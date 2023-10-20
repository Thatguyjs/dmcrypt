# dmcrypt
Decrypt LG multimedia files without the pin

Made with the following references:
 - [LG-Gallery-Decryptor (Github)](https://github.com/kamicater/LG-Gallery-Decryptor)
 - [This research paper (sciencedirect.com, paywall)](https://www.sciencedirect.com/science/article/abs/pii/S266628172100202X)

All that you need to decrypt \*.dm files is your email address used when they were encrypted. This
is usually the same email that you're signed in with on your LG device.

If the email address provided is incorrect, the resulting files might not contain data or might be
invalid.

## Usage
`dmcrypt <email> <inputs...> -o <output_dir> [-r]`
Note: The output directory will be created if it doesn't already exist.

## Example
`dmcrypt example@gmail.com input1.jpg.dm input2.jpg.dm -o ./decrypted`
