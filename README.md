# Zed CLI

A read-only prototype for listing and extracting password-protected `.zed` archives. It does not modify the archive and refuses to overwrite existing output files.

## Requirements

Python 3.10 or newer is required. For AES, the script uses either an OpenSSL `libcrypto` library (the system one on many Linux systems; on macOS a separately installed OpenSSL such as `brew install openssl@3`, because macOS aborts any process that loads its own unversioned `libcrypto`) or the optional `cryptography` package. Install the package if `libcrypto` is unavailable, including on Windows:

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

## Disclaimer

This is an independent, unofficial project. It is not affiliated with, endorsed by or supported by Prim'X Technologies. Zed!, ZoneCentral and Prim'X are trademarks of their respective owners; they are used here only to identify the file format this tool reads.

The tool exists for interoperability: it lets people open `.zed` archives they are entitled to read, for example on systems where the official software is not available. It requires the archive's password and provides no way to bypass, recover or guess it. It never creates or modifies archives.

The implementation was written from Sylvain Beucler's public [description of the .zed file format](https://www.beuc.net/zed/) (© 2017 Sylvain Beucler). No Prim'X code was copied or decompiled.
