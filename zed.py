#!/usr/bin/env python3
"""Small, read-only .zed archive extractor (password users only).

Based on the format description at https://www.beuc.net/zed/ . Uses the
system OpenSSL libcrypto or the optional cryptography package for AES.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import getpass
import hashlib
import hmac
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Cipher = algorithms = modes = None


class ZedError(Exception):
    pass


def u32be(data: bytes) -> int:
    if len(data) != 4:
        raise ZedError("invalid uint32 field")
    return int.from_bytes(data, "big")


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


class CFB:
    END = 0xFFFFFFFE
    FREE = 0xFFFFFFFF

    def __init__(self, data: bytes):
        self.data = data
        if data[:8] != bytes.fromhex("d0cf11e0a1b11ae1"):
            raise ZedError("not an OLE/CFB file")
        self.sector_size = 1 << struct.unpack_from("<H", data, 30)[0]
        self.mini_size = 1 << struct.unpack_from("<H", data, 32)[0]
        if self.sector_size not in (512, 4096) or self.mini_size != 64:
            raise ZedError("unsupported CFB sector size")
        self.mini_cutoff = struct.unpack_from("<I", data, 56)[0]
        fat_count = struct.unpack_from("<I", data, 44)[0]
        difat = list(struct.unpack_from("<109I", data, 76))
        next_difat = struct.unpack_from("<I", data, 68)[0]
        for _ in range(struct.unpack_from("<I", data, 72)[0]):
            sector = self.sector(next_difat)
            entries = struct.unpack_from(f"<{self.sector_size // 4}I", sector)
            difat.extend(entries[:-1])
            next_difat = entries[-1]
        fat_sectors = [i for i in difat if i != self.FREE][:fat_count]
        if len(fat_sectors) != fat_count:
            raise ZedError("truncated CFB allocation table")
        self.fat = [i for sid in fat_sectors for i in struct.unpack(f"<{self.sector_size // 4}I", self.sector(sid))]
        first_dir = struct.unpack_from("<I", data, 48)[0]
        directory = self.chain(first_dir, self.fat)
        self.entries = {}
        self.root = None
        for pos in range(0, len(directory), 128):
            record = directory[pos:pos + 128]
            if len(record) != 128 or record[66] not in (1, 2, 5):
                continue
            name_len = struct.unpack_from("<H", record, 64)[0]
            if name_len < 2 or name_len > 64:
                continue
            name = record[:name_len - 2].decode("utf-16le")
            item = (record[66], struct.unpack_from("<I", record, 116)[0],
                    struct.unpack_from("<Q", record, 120)[0])
            self.entries[name] = item
            if record[66] == 5:
                self.root = item
        if self.root is None:
            raise ZedError("missing CFB root entry")
        mini_start = struct.unpack_from("<I", data, 60)[0]
        mini_count = struct.unpack_from("<I", data, 64)[0]
        raw_minifat = self.chain(mini_start, self.fat, mini_count) if mini_count else b""
        self.minifat = list(struct.unpack(f"<{len(raw_minifat) // 4}I", raw_minifat))
        self.ministream = self.chain(self.root[1], self.fat)[:self.root[2]]

    def sector(self, sid: int) -> bytes:
        start = (sid + 1) * self.sector_size
        if start + self.sector_size > len(self.data):
            raise ZedError("CFB sector outside file")
        return self.data[start:start + self.sector_size]

    def chain(self, start: int, table: list[int], limit: int | None = None) -> bytes:
        parts = []
        seen = set()
        while start != self.END and (limit is None or len(parts) < limit):
            if start in seen or start >= len(table):
                raise ZedError("invalid CFB sector chain")
            seen.add(start)
            parts.append(self.sector(start))
            start = table[start]
        return b"".join(parts)

    def stream(self, name: str) -> bytes:
        try:
            kind, start, size = self.entries[name]
        except KeyError as exc:
            raise ZedError(f"missing CFB stream {name!r}") from exc
        if kind != 2:
            raise ZedError(f"not a CFB stream: {name!r}")
        if size >= self.mini_cutoff:
            result = self.chain(start, self.fat)
            if len(result) < size:
                raise ZedError("truncated CFB stream")
            return result[:size]
        parts = []
        seen = set()
        while start != self.END and len(parts) * self.mini_size < size:
            if start in seen or start >= len(self.minifat):
                raise ZedError("invalid CFB mini-sector chain")
            seen.add(start)
            off = start * self.mini_size
            parts.append(self.ministream[off:off + self.mini_size])
            start = self.minifat[start]
        result = b"".join(parts)
        if len(result) < size:
            raise ZedError("truncated CFB stream")
        return result[:size]


class AES:
    def __init__(self):
        # Bundled applications use cryptography; the standalone CLI can still
        # use the system OpenSSL library without installing Python packages.
        if Cipher is not None:
            return
        path = ctypes.util.find_library("crypto")
        if not path:
            raise ZedError("OpenSSL libcrypto not found")
        self.lib = ctypes.CDLL(path)
        ptr = ctypes.c_void_p
        self.lib.EVP_CIPHER_CTX_new.restype = ptr
        self.lib.EVP_CIPHER_CTX_free.argtypes = [ptr]
        self.lib.EVP_aes_128_cbc.restype = ptr
        self.lib.EVP_aes_192_cbc.restype = ptr
        self.lib.EVP_aes_256_cbc.restype = ptr
        self.lib.EVP_aes_128_ecb.restype = ptr
        self.lib.EVP_aes_192_ecb.restype = ptr
        self.lib.EVP_aes_256_ecb.restype = ptr
        self.lib.EVP_CipherInit_ex.argtypes = [ptr, ptr, ptr, ptr, ptr, ctypes.c_int]
        self.lib.EVP_CipherInit_ex.restype = ctypes.c_int
        self.lib.EVP_CIPHER_CTX_set_padding.argtypes = [ptr, ctypes.c_int]
        self.lib.EVP_CIPHER_CTX_set_padding.restype = ctypes.c_int
        self.lib.EVP_CipherUpdate.argtypes = [ptr, ptr, ptr, ptr, ctypes.c_int]
        self.lib.EVP_CipherUpdate.restype = ctypes.c_int
        self.lib.EVP_CipherFinal_ex.argtypes = [ptr, ptr, ptr]
        self.lib.EVP_CipherFinal_ex.restype = ctypes.c_int

    def cipher(self, data: bytes, key: bytes, iv: bytes | None, decrypt: bool) -> bytes:
        if len(key) not in (16, 24, 32) or len(data) % 16:
            raise ZedError("invalid AES key or block length")
        if Cipher is not None:
            if iv is not None and len(iv) != 16:
                raise ZedError("invalid AES IV")
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv) if iv is not None else modes.ECB())
            context = cipher.decryptor() if decrypt else cipher.encryptor()
            return context.update(data) + context.finalize()
        name = f"EVP_aes_{len(key) * 8}_{'cbc' if iv is not None else 'ecb'}"
        method = getattr(self.lib, name)()
        ctx = self.lib.EVP_CIPHER_CTX_new()
        if not ctx:
            raise ZedError("unable to allocate AES context")
        try:
            key_buf = ctypes.create_string_buffer(key)
            iv_buf = ctypes.create_string_buffer(iv) if iv is not None else None
            if not self.lib.EVP_CipherInit_ex(ctx, method, None, key_buf, iv_buf, 0 if decrypt else 1):
                raise ZedError("AES initialization failed")
            self.lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
            out = ctypes.create_string_buffer(len(data) + 16)
            n1, n2 = ctypes.c_int(), ctypes.c_int()
            if not self.lib.EVP_CipherUpdate(ctx, out, ctypes.byref(n1), data, len(data)):
                raise ZedError("AES update failed")
            if not self.lib.EVP_CipherFinal_ex(ctx, ctypes.byref(out, n1.value), ctypes.byref(n2)):
                raise ZedError("AES finalization failed")
            return out.raw[:n1.value + n2.value]
        finally:
            self.lib.EVP_CIPHER_CTX_free(ctx)

    def decrypt_zed(self, ciphertext: bytes, key: bytes, iv: bytes, mode: int) -> bytes:
        if len(iv) != 16:
            raise ZedError("invalid AES IV")
        whole = len(ciphertext) // 16 * 16
        tail = ciphertext[whole:]
        if not tail:
            # CBC-CS3 swaps the final two ciphertext blocks even when the
            # plaintext length is a multiple of the AES block size.
            if mode == 104 and whole >= 32:
                ciphertext = ciphertext[:-32] + ciphertext[-16:] + ciphertext[-32:-16]
            return self.cipher(ciphertext, key, iv, True)
        if mode == 103 or whole == 0:
            prefix = self.cipher(ciphertext[:whole], key, iv, True)
            preceding = ciphertext[whole - 16:whole] if whole else iv
            mask = self.cipher(preceding, key, None, False)
            return prefix + xor(tail, mask[:len(tail)])
        if mode != 104:
            raise ZedError(f"unsupported encryption mode {mode}")
        before = ciphertext[:whole - 16]
        final_full = ciphertext[whole - 16:whole]
        preceding = before[-16:] if before else iv
        x = self.cipher(final_full, key, None, True)
        stolen = tail + x[len(tail):]
        last_partial = xor(x[:len(tail)], tail)
        last_full = xor(self.cipher(stolen, key, None, True), preceding)
        return self.cipher(before, key, iv, True) + last_full + last_partial


def pkcs12_kdf(password: str, salt: bytes, iterations: int, digest: str, purpose: int, length: int) -> bytes:
    if iterations < 1 or iterations > 10_000_000:
        raise ZedError("invalid PKCS#12 iteration count")
    u = hashlib.new(digest).digest_size
    v = 64  # SHA-1 and SHA-256 block size
    p = password.encode("utf-16be") + b"\x00\x00"
    def expand(source: bytes) -> bytes:
        if not source:
            return b""
        size = v * ((len(source) + v - 1) // v)
        return (source * ((size + len(source) - 1) // len(source)))[:size]
    s = expand(salt)
    p = expand(p)
    blocks = [s[i:i + v] for i in range(0, len(s), v)] + [p[i:i + v] for i in range(0, len(p), v)]
    result = bytearray()
    while len(result) < length:
        a = bytes([purpose]) * v + b"".join(blocks)
        for _ in range(iterations):
            a = hashlib.new(digest, a).digest()
        result.extend(a)
        b = (a * ((v + u - 1) // u))[:v]
        increment = int.from_bytes(b, "big") + 1
        blocks = [((int.from_bytes(block, "big") + increment) % (1 << (8 * v))).to_bytes(v, "big") for block in blocks]
    return bytes(result[:length])


def tlv(data: bytes) -> list[tuple[bytes, bytes]]:
    fields = []
    pos = 0
    while pos < len(data):
        if len(data) - pos < 8:
            raise ZedError("truncated TLV header")
        kind = data[pos:pos + 4]
        size = int.from_bytes(data[pos + 4:pos + 8], "big")
        pos += 8
        if size > len(data) - pos:
            raise ZedError("truncated TLV value")
        fields.append((kind, data[pos:pos + size]))
        pos += size
    return fields


def field(fields: list[tuple[bytes, bytes]], kind: str) -> bytes:
    tag = bytes.fromhex(kind)
    for current, value in fields:
        if current == tag:
            return value
    raise ZedError(f"missing TLV field {kind}")


def property_blobs(stream: bytes) -> dict[int, bytes]:
    if len(stream) < 48 or stream[:2] != b"\xfe\xff":
        raise ZedError("invalid OLE property stream")
    section_count = struct.unpack_from("<I", stream, 24)[0]
    result = {}
    for section_index in range(section_count):
        section_offset = struct.unpack_from("<I", stream, 28 + 20 * section_index + 16)[0]
        if section_offset + 8 > len(stream):
            raise ZedError("invalid OLE property section")
        count = struct.unpack_from("<I", stream, section_offset + 4)[0]
        for index in range(count):
            prop_id, offset = struct.unpack_from("<II", stream, section_offset + 8 + 8 * index)
            start = section_offset + offset
            if start + 8 > len(stream):
                raise ZedError("invalid OLE property offset")
            variant = struct.unpack_from("<I", stream, start)[0]
            if variant == 0x41:  # VT_BLOB
                length = struct.unpack_from("<I", stream, start + 4)[0]
                if start + 8 + length > len(stream):
                    raise ZedError("truncated OLE blob")
                result[prop_id] = stream[start + 8:start + 8 + length]
    return result


def strip_nul_utf16(data: bytes) -> str:
    return data.decode("utf-16le").rstrip("\x00")


@dataclass
class Entry:
    file_id: bytes
    parent_id: bytes
    name: str
    size: int
    is_dir: bool


class ZedArchive:
    METADATA_NAME = "\x05" + "5haaaaqaIekzeecnWj31zxh0Nc"
    DELIMITER = bytes.fromhex("0765921a2a0774534752073361719300")
    STATIC_KEY = bytes.fromhex("37f13cf81c780af26b6a52654f794aef")

    def __init__(self, path: Path, password: str):
        self.cfb = CFB(path.read_bytes())
        self.aes = AES()
        blobs = property_blobs(self.cfb.stream(self.METADATA_NAME))
        control_ids = [i for i, blob in blobs.items() if blob.startswith(self.DELIMITER)]
        if len(control_ids) != 1 or control_ids[0] + 1 not in blobs:
            raise ZedError("missing _ctlfile or _catalog property")
        ctl_id = control_ids[0]
        ctl, catalog = blobs[ctl_id], blobs[ctl_id + 1]
        if ctl[16:18] not in (b"\x01\x00", b"\x02\x00"):
            raise ZedError("invalid _ctlfile header")
        self.version = int.from_bytes(ctl[16:18], "little")
        trailer = self.DELIMITER + b"ZoneCentral (R)\x00"
        if not ctl.endswith(trailer):
            raise ZedError("invalid _ctlfile trailer")
        iv = ctl[18:34]
        ciphertext = ctl[34:-len(trailer) - 4]
        claimed = int.from_bytes(ctl[-len(trailer) - 4:-len(trailer)], "big")
        if claimed != 34 + len(ciphertext):
            raise ZedError("invalid _ctlfile length")
        control = tlv(self.aes.decrypt_zed(ciphertext, self.STATIC_KEY, iv, 103))
        props = tlv(field(control, "80110600"))
        self.mode = u32be(field(props, "80270200"))
        self.strength = u32be(field(props, "80260200"))
        self.iv = field(props, "80280500")
        if self.mode not in (103, 104) or self.strength not in (16, 24, 32) or len(self.iv) != 16:
            raise ZedError("unsupported archive encryption settings")
        users = tlv(field(control, "80140600"))
        self.key = self._unlock(users, password)
        self.entries = []
        for kind, value in tlv(catalog):
            if kind != bytes.fromhex("80110600"):
                continue
            props = tlv(value)
            file_id = field(props, "80300500")
            parent_id = field(props, "00370500")
            encrypted_name = field(props, "00380500")
            if len(file_id) != 16 or len(parent_id) != 16:
                raise ZedError("invalid catalog file id")
            name_iv = xor(self.iv, file_id) if self.version == 2 else self.iv
            name = strip_nul_utf16(self.aes.decrypt_zed(encrypted_name, self.key, name_iv, self.mode))
            size = int.from_bytes(field(props, "80330500"), "little")
            is_dir = any(k == bytes.fromhex("80320100") and u32be(v) == 1 for k, v in props)
            self.entries.append(Entry(file_id, parent_id, name, size, is_dir))

    def _unlock(self, users: list[tuple[bytes, bytes]], password: str) -> bytes:
        for kind, value in users:
            if kind != bytes.fromhex("80610600"):
                continue
            user = tlv(value)
            hash_id = u32be(field(user, "80780200"))
            digest = {21: "sha1", 22: "sha256"}.get(hash_id)
            if digest is None and hash_id != 42:
                continue
            check = field(user, "80790500")
            pba_salt = field(user, "807a0500")
            pba_iter = u32be(field(user, "807b0200"))
            if not 1 <= pba_iter <= 10_000_000:
                raise ZedError("invalid password iteration count")
            if hash_id == 42:
                derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), pba_salt, pba_iter, len(check))
            else:
                derived = pkcs12_kdf(password, pba_salt, pba_iter, digest, 3, len(check))
            if not hmac.compare_digest(derived, check):
                continue
            salt = field(user, "80760500")
            iterations = u32be(field(user, "80770200"))
            if not 1 <= iterations <= 10_000_000:
                raise ZedError("invalid password iteration count")
            if hash_id == 42:
                key_iv = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 48)
                key, iv = key_iv[:self.strength], key_iv[32:48]
            else:
                key = pkcs12_kdf(password, salt, iterations, digest, 1, 32)[:self.strength]
                iv = pkcs12_kdf(password, salt, iterations, digest, 2, 16)
            ciphertext = field(user, "80740500")
            plaintext = self.aes.cipher(ciphertext, key, iv, True)
            if not plaintext or plaintext[-1] not in range(1, 17) or plaintext[-plaintext[-1]:] != bytes([plaintext[-1]]) * plaintext[-1]:
                raise ZedError("invalid archive key padding")
            archive_key = plaintext[:-plaintext[-1]]
            if len(archive_key) != self.strength:
                raise ZedError("invalid archive key length")
            return archive_key
        raise ZedError("password does not match any supported password user")

    def names(self) -> list[tuple[Entry, Path]]:
        by_id = {entry.file_id: entry for entry in self.entries}
        def relative(entry: Entry, seen: set[bytes]) -> Path:
            if entry.file_id in seen:
                raise ZedError("directory cycle in catalog")
            if entry.name in ("", ".", "..") or "/" in entry.name or "\\" in entry.name or "\x00" in entry.name:
                raise ZedError("unsafe filename in catalog")
            if not any(entry.parent_id):
                return Path(entry.name)
            parent = by_id.get(entry.parent_id)
            if parent is None or not parent.is_dir:
                raise ZedError("missing parent directory")
            return relative(parent, seen | {entry.file_id}) / entry.name
        return [(entry, relative(entry, set())) for entry in self.entries]

    def read(self, entry: Entry) -> bytes:
        if entry.is_dir:
            raise ZedError("cannot read a directory")
        fid = entry.file_id
        if len(fid) != 16:
            raise ZedError("invalid file id")
        shuffled = bytes([fid[i] for i in (3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15)])
        name = shuffled[:-1].hex().upper() if shuffled[-1] == 0 else shuffled.hex().upper()
        encrypted = self.cfb.stream(name)
        parts = []
        base_iv = xor(self.iv, fid) if self.version == 2 else self.iv
        for n, pos in enumerate(range(0, len(encrypted), 512)):
            counter = n.to_bytes(16, "little")
            # Version 2 mixes the file id into the IV before chunk numbering.
            iv = self.aes.cipher(xor(counter, base_iv), self.key, None, False)
            parts.append(self.aes.decrypt_zed(encrypted[pos:pos + 512], self.key, iv, self.mode))
        try:
            data = zlib.decompress(b"".join(parts))
        except zlib.error as exc:
            raise ZedError(f"decompression failed for {entry.name!r}: {exc}") from exc
        if len(data) != entry.size:
            raise ZedError(f"size mismatch for {entry.name!r}")
        return data

    def extract_to(self, output: Path, progress: Callable[[int, int, Path], None] | None = None) -> list[Path]:
        root = output.resolve()
        names = self.names()
        # Check every path before writing any files.
        for entry, path in names:
            current = root
            for component in path.parts:
                current = current / component
                if current.is_symlink():
                    raise ZedError(f"refusing to follow symlink {current}")
            if entry.is_dir and current.exists() and not current.is_dir():
                raise ZedError(f"not a directory: {current}")
            if not entry.is_dir and current.exists():
                raise ZedError(f"refusing to overwrite {current}")
        root.mkdir(parents=True, exist_ok=True)
        files = [(entry, path) for entry, path in names if not entry.is_dir]
        written = []
        for entry, path in names:
            target = root / path
            if entry.is_dir:
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(self.read(entry))
            written.append(target)
            if progress is not None:
                progress(len(written), len(files), target)
        return written


def main() -> int:
    parser = argparse.ArgumentParser(description="List or extract password-protected .zed archives")
    parser.add_argument("archive", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="extract into this directory")
    parser.add_argument("--list", action="store_true", help="list files without extracting")
    args = parser.parse_args()
    try:
        password = getpass.getpass("Zed password: ")
        archive = ZedArchive(args.archive, password)
        names = archive.names()
        if args.list or args.output is None:
            for entry, path in names:
                print(f"{'d' if entry.is_dir else 'f'} {entry.size:>10}  {path}")
        if args.output is not None:
            for target in archive.extract_to(args.output):
                print(target)
    except (ZedError, OSError, UnicodeError) as exc:
        print(f"zed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
