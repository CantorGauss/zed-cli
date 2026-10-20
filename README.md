# Zed CLI

A read-only prototype for listing and extracting password-protected `.zed` archives. It does not modify the archive and refuses to overwrite existing output files.

## Requirements

Python 3.10 or newer is required. For AES, the script uses either the system OpenSSL `libcrypto` library (available on macOS and many Linux systems) or the optional `cryptography` package. Install the package if `libcrypto` is unavailable, including on Windows:

```sh
python3 -m pip install cryptography
```

## Usage

List an archive's contents or extract its files:

```sh
python3 zed.py archive.zed --list
python3 zed.py archive.zed -o output_directory
```

The CLI prompts for the password interactively; it does not accept a password as a command-line argument.

## Supported formats and limitations

This prototype supports `passworduser` entries, AES-CBC-STREAM and AES-CBC-CTS (CBC-CS3), PBKDF2-SHA-256, and the PKCS#12 SHA-1/SHA-256 key derivation described in the [Zed format documentation](https://www.beuc.net/zed/zed.md). Certificate-based `rsauser` entries are not supported.

The tests use public vectors. No private archive or password is included in this repository:

```sh
python3 -m unittest discover -s tests
```

This is an independent prototype and is not affiliated with the publisher of Zed.
