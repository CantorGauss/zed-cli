"""Malformed and hostile inputs; archives are built in memory from fixed keys."""

import contextlib
import hashlib
import io
import os
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

import zed
from zed import AES, Entry, ZedArchive, ZedError, xor

KEY = bytes(range(16))
IV = bytes(range(16, 32))
FILE_ID = bytes.fromhex("f714c09327642647991ff50d4552fb00")
ROOT = bytes(16)


def tlv(kind: str, value: bytes) -> bytes:
    return bytes.fromhex(kind) + len(value).to_bytes(4, "big") + value


def encrypt_stream(aes: AES, plain: bytes, key: bytes, iv: bytes) -> bytes:
    """Inverse of AES.decrypt_zed for mode 103 (AES-CBC-STREAM)."""
    whole = len(plain) // 16 * 16
    body = aes.cipher(plain[:whole], key, iv, False) if whole else b""
    tail = plain[whole:]
    if not tail:
        return body
    mask = aes.cipher(body[-16:] if body else iv, key, None, False)
    return body + xor(tail, mask[:len(tail)])


class FakeCFB:
    def __init__(self, data: bytes):
        self.data = data

    def stream(self, name: str) -> bytes:
        return self.data


def archive_with(entries: list[Entry]) -> ZedArchive:
    archive = ZedArchive.__new__(ZedArchive)
    archive.entries = entries
    return archive


def file_archive(compressed: bytes, size: int) -> ZedArchive:
    archive = archive_with([Entry(FILE_ID, ROOT, "f.bin", size, False)])
    archive.aes = AES()
    archive.key, archive.iv, archive.version, archive.mode = KEY, IV, 1, 103
    chunks = []
    for n, pos in enumerate(range(0, len(compressed), 512)):
        iv = archive.aes.cipher(xor(n.to_bytes(16, "little"), IV), KEY, None, False)
        chunks.append(encrypt_stream(archive.aes, compressed[pos:pos + 512], KEY, iv))
    archive.cfb = FakeCFB(b"".join(chunks))
    return archive


def dir_entry(n: int, parent: bytes = ROOT, name: str | None = None) -> Entry:
    return Entry(n.to_bytes(16, "big"), parent, f"d{n}" if name is None else name, 0, True)


class FileData(unittest.TestCase):
    def test_round_trip_across_chunks(self):
        data = os.urandom(5000)
        archive = file_archive(zlib.compress(data), len(data))
        self.assertEqual(archive.read(archive.entries[0]), data)

    def test_output_larger_than_one_piece(self):
        data = bytes(3 * ZedArchive.MAX_PIECE + 7)
        archive = file_archive(zlib.compress(data), len(data))
        pieces = list(archive.iter_read(archive.entries[0]))
        self.assertEqual(b"".join(pieces), data)
        self.assertLessEqual(max(map(len, pieces)), ZedArchive.MAX_PIECE)

    def test_decompression_stops_at_catalog_size(self):
        archive = file_archive(zlib.compress(bytes(50 << 20)), 10)
        produced = 0
        with self.assertRaisesRegex(ZedError, "size mismatch"):
            for piece in archive.iter_read(archive.entries[0]):
                produced += len(piece)
        self.assertLessEqual(produced, ZedArchive.MAX_PIECE)

    def test_short_output_is_rejected(self):
        archive = file_archive(zlib.compress(b"abc"), 4)
        with self.assertRaisesRegex(ZedError, "size mismatch"):
            archive.read(archive.entries[0])

    def test_truncated_stream_is_rejected(self):
        data = os.urandom(2000)
        archive = file_archive(zlib.compress(data)[:-10], len(data))
        with self.assertRaisesRegex(ZedError, "truncated stream"):
            archive.read(archive.entries[0])

    def test_extract_writes_file(self):
        data = os.urandom(3000)
        with tempfile.TemporaryDirectory() as tmp:
            written = file_archive(zlib.compress(data), len(data)).extract_to(Path(tmp))
            self.assertEqual([p.name for p in written], ["f.bin"])
            self.assertEqual(written[0].read_bytes(), data)

    def test_failed_extract_leaves_no_partial_file(self):
        archive = file_archive(zlib.compress(bytes(4 << 20)), 1 << 20)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ZedError):
                archive.extract_to(Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])


class Catalog(unittest.TestCase):
    def test_deep_nesting(self):
        entries = [dir_entry(1)] + [dir_entry(n, (n - 1).to_bytes(16, "big")) for n in range(2, 3001)]
        names = archive_with(entries).names()
        self.assertEqual(len(names[-1][1].parts), 3000)
        self.assertEqual(names[-1][1].parts[:2], ("d1", "d2"))

    def test_cycle(self):
        a, b = dir_entry(1, (2).to_bytes(16, "big")), dir_entry(2, (1).to_bytes(16, "big"))
        with self.assertRaisesRegex(ZedError, "cycle"):
            archive_with([a, b]).names()

    def test_unsafe_names(self):
        for name in ("", ".", "..", "a/b", "a\\b", "C:x", "a\x00"):
            with self.subTest(name=name), self.assertRaisesRegex(ZedError, "unsafe"):
                archive_with([dir_entry(1, name=name)]).names()

    def test_missing_parent(self):
        with self.assertRaisesRegex(ZedError, "missing parent"):
            archive_with([dir_entry(1, (9).to_bytes(16, "big"))]).names()

    def assert_rejected_before_writing(self, entries: list[Entry]):
        archive = archive_with(entries)
        archive.iter_read = mock.Mock(side_effect=AssertionError("read before checks"))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            with self.assertRaisesRegex(ZedError, "duplicate path"):
                archive.extract_to(out)
            self.assertFalse(out.exists())

    def test_duplicate_files(self):
        self.assert_rejected_before_writing([
            Entry(b"\x01" * 16, ROOT, "x", 1, False),
            Entry(b"\x02" * 16, ROOT, "x", 1, False),
        ])

    def test_case_and_normalization_collisions(self):
        for first, second in (("A.txt", "a.txt"), ("café", "café")):
            with self.subTest(first=first):
                self.assert_rejected_before_writing([
                    Entry(b"\x01" * 16, ROOT, first, 1, False),
                    Entry(b"\x02" * 16, ROOT, second, 1, False),
                ])

    def test_file_and_directory_collision(self):
        self.assert_rejected_before_writing([dir_entry(1, name="x"), Entry(b"\x02" * 16, ROOT, "X", 1, False)])

    def test_duplicate_directories_are_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(archive_with([dir_entry(1, name="x"), dir_entry(2, name="x")]).extract_to(Path(tmp)), [])
            self.assertTrue((Path(tmp) / "x").is_dir())


class Unlock(unittest.TestCase):
    ARCHIVE_KEY = bytes(range(100, 116))

    def setUp(self):
        self.archive = archive_with([])
        self.archive.aes, self.archive.strength = AES(), 16

    def user(self, password: str, corrupt: bool = False, check: bytes | None = None) -> bytes:
        pw = password.encode()
        if check is None:
            check = hashlib.pbkdf2_hmac("sha256", pw, b"pba-salt", 1, 16)
        key_iv = hashlib.pbkdf2_hmac("sha256", pw, b"key-salt", 1, 48)
        ciphertext = self.archive.aes.cipher(self.ARCHIVE_KEY + bytes([16]) * 16, key_iv[:16], key_iv[32:48], False)
        if corrupt:
            # Changing the first block garbles the padding in the second.
            ciphertext = bytes(16) + ciphertext[16:]
        one = (1).to_bytes(4, "big")
        return tlv("80610600", tlv("80780200", (42).to_bytes(4, "big")) + tlv("80790500", check)
                   + tlv("807a0500", b"pba-salt") + tlv("807b0200", one)
                   + tlv("80760500", b"key-salt") + tlv("80770200", one) + tlv("80740500", ciphertext))

    def unlock(self, *users: bytes, password: str = "secret") -> bytes:
        return self.archive._unlock(zed.tlv(b"".join(users)), password)

    def test_valid_user(self):
        self.assertEqual(self.unlock(self.user("secret")), self.ARCHIVE_KEY)

    def test_bad_key_falls_through_to_next_user(self):
        self.assertEqual(self.unlock(self.user("secret", corrupt=True), self.user("secret")), self.ARCHIVE_KEY)

    def test_bad_key_is_reported_when_no_user_unlocks(self):
        with self.assertRaisesRegex(ZedError, "padding"):
            self.unlock(self.user("secret", corrupt=True))

    def test_empty_verifier_never_matches(self):
        with self.assertRaisesRegex(ZedError, "does not match"):
            self.unlock(self.user("secret", check=b""))

    def test_wrong_password(self):
        with self.assertRaisesRegex(ZedError, "does not match"):
            self.unlock(self.user("secret"), password="other")


class Container(unittest.TestCase):
    MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")

    def open_bytes(self, data: bytes):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.zed"
            path.write_bytes(data)
            ZedArchive(path, "pw")

    def test_truncated_header(self):
        with self.assertRaisesRegex(ZedError, "malformed archive"):
            self.open_bytes(self.MAGIC)

    def test_not_ole(self):
        with self.assertRaisesRegex(ZedError, "not an OLE"):
            self.open_bytes(bytes(1024))

    def test_difat_cycle(self):
        header = bytearray(512)
        header[:8] = self.MAGIC
        struct.pack_into("<HH", header, 30, 9, 6)
        struct.pack_into("<II", header, 68, 0, 0xFFFFFFFF)  # first DIFAT sector, DIFAT count
        struct.pack_into("<109I", header, 76, *[0xFFFFFFFF] * 109)
        sector = struct.pack("<128I", *[0xFFFFFFFF] * 127, 0)  # points back to itself
        with self.assertRaisesRegex(ZedError, "DIFAT"):
            self.open_bytes(bytes(header) + sector)


class LibcryptoLoader(unittest.TestCase):
    def load(self, found: str | None, candidates: tuple[str, ...]):
        with mock.patch.object(zed, "Cipher", None), \
                mock.patch.object(zed.sys, "platform", "darwin"), \
                mock.patch.object(zed.ctypes.util, "find_library", return_value=found), \
                mock.patch.object(AES, "MACOS_LIBCRYPTO", candidates), \
                mock.patch.object(zed.ctypes, "CDLL") as cdll:
            try:
                AES()
            finally:
                self.cdll = cdll

    def test_never_loads_macos_system_libcrypto(self):
        with self.assertRaisesRegex(ZedError, "cryptography"):
            self.load("/usr/lib/libcrypto.dylib", ("/nonexistent/libcrypto.3.dylib",))
        self.cdll.assert_not_called()

    def test_falls_back_to_installed_openssl(self):
        with tempfile.NamedTemporaryFile() as lib:
            self.load("/usr/lib/libcrypto.dylib", ("/nonexistent/libcrypto.3.dylib", lib.name))
            self.cdll.assert_called_once_with(lib.name)

    def test_keeps_non_system_library(self):
        self.load("/opt/homebrew/lib/libcrypto.dylib", ())
        self.cdll.assert_called_once_with("/opt/homebrew/lib/libcrypto.dylib")


class CommandLine(unittest.TestCase):
    def run_main(self, argv: list[str], **getpass_behaviour) -> tuple[int, str]:
        stderr = io.StringIO()
        with mock.patch.object(zed.getpass, "getpass", **getpass_behaviour) as prompt, \
                contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            code = zed.main(argv)
        self.prompt = prompt
        return code, stderr.getvalue()

    def test_missing_archive_fails_before_prompt(self):
        code, err = self.run_main(["/nonexistent/a.zed"], return_value="pw")
        self.assertEqual(code, 1)
        self.assertIn("not a file", err)
        self.prompt.assert_not_called()

    def test_malformed_archive_reports_error(self):
        with tempfile.NamedTemporaryFile(suffix=".zed") as f:
            f.write(Container.MAGIC)
            f.flush()
            code, err = self.run_main([f.name], return_value="pw")
        self.assertEqual(code, 1)
        self.assertIn("zed: malformed archive", err)

    def test_interrupt_at_prompt(self):
        with tempfile.NamedTemporaryFile(suffix=".zed") as f:
            code, err = self.run_main([f.name], side_effect=KeyboardInterrupt)
        self.assertEqual(code, 130)
        self.assertIn("interrupted", err)


if __name__ == "__main__":
    unittest.main()
