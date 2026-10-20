"""Published Zed format vectors; no archive password is stored here."""

import unittest
import zlib

from zed import AES, pkcs12_kdf


class ZedVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.aes = AES()

    def test_stream_short_filename(self):
        plain = self.aes.decrypt_zed(
            bytes.fromhex("6905386c749b7fc088ca40b0419a"),
            bytes.fromhex("4a85bda3df4df0ea3090cc21618901ee"),
            bytes.fromhex("f266ef5a855d0494b6c9a9a8325a4415"),
            103,
        )
        self.assertEqual(plain.decode("utf-16le").rstrip("\0"), "abc.txt")

    def test_cts_partial_filename(self):
        plain = self.aes.decrypt_zed(
            bytes.fromhex("3842bf4e19ccce83deaf9cdf763cdd713d7b"),
            bytes.fromhex("dc30c294eb879cc505961f042ca790d4"),
            bytes.fromhex("696eb7b48347ade4b3d7a0812bc695ea"),
            104,
        )
        self.assertEqual(plain.decode("utf-16le").rstrip("\0"), "empty.txt")

    def test_cts_aligned_file(self):
        key = bytes.fromhex("855ecc286bb4f1adab26bd39514d4f4eb60181849c3bc605fb3fb78846e0cfef")
        global_iv = bytes.fromhex("bf205053393a02f3927c8f0836660a9f")
        ciphertext = bytes.fromhex("5baf62282f9e23d0974aad6eb4f3970da9ac7e5c54356d1c0f5918e378595ba3")
        chunk_iv = self.aes.cipher(global_iv, key, None, False)
        compressed = self.aes.decrypt_zed(ciphertext, key, chunk_iv, 104)
        self.assertEqual(zlib.decompress(compressed), b"1234567890" * 160)

    def test_pkcs12_sha1_pba(self):
        self.assertEqual(
            pkcs12_kdf("123456", bytes.fromhex("d0ee7a995bf3022e"), 200000, "sha1", 3, 8).hex(),
            "98a431f7e9eda53f",
        )


if __name__ == "__main__":
    unittest.main()
