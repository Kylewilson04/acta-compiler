"""Spec-exact, zero-dependency BLAKE3 (256-bit unkeyed + keyed MAC) for Acta SDK."""

from __future__ import annotations

import struct
from typing import Iterable

try:
    import blake3 as _native_blake3  # type: ignore[import-not-found]
except ImportError:
    _native_blake3 = None

OUT_LEN = 32
KEY_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4

IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_MASK32 = 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & _MASK32)) & _MASK32


def _g(state: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    sa = (state[a] + state[b] + mx) & _MASK32
    sd = _rotr32(state[d] ^ sa, 16)
    sc = (state[c] + sd) & _MASK32
    sb = _rotr32(state[b] ^ sc, 12)
    sa = (sa + sb + my) & _MASK32
    sd = _rotr32(sd ^ sa, 8)
    sc = (sc + sd) & _MASK32
    sb = _rotr32(sb ^ sc, 7)
    state[a], state[b], state[c], state[d] = sa, sb, sc, sd


def _round(state: list[int], m: tuple[int, ...] | list[int]) -> None:
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _compress(
    chaining_value: tuple[int, ...],
    block_words: tuple[int, ...],
    counter: int,
    block_len: int,
    flags: int,
) -> list[int]:
    state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter & _MASK32,
        (counter >> 32) & _MASK32,
        block_len & _MASK32,
        flags & _MASK32,
    ]
    m: tuple[int, ...] | list[int] = block_words
    for r in range(7):
        _round(state, m)
        if r < 6:
            m = [m[i] for i in MSG_PERMUTATION]

    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= chaining_value[i]
    return state


def _words_from_block(block: bytes | bytearray) -> tuple[int, ...]:
    if len(block) < BLOCK_LEN:
        padded = bytes(block) + b"\x00" * (BLOCK_LEN - len(block))
    else:
        padded = bytes(block)
    return struct.unpack("<16I", padded)


class _Output:
    __slots__ = ("input_cv", "block_words", "counter", "block_len", "flags")

    def __init__(
        self,
        input_cv: tuple[int, ...],
        block_words: tuple[int, ...],
        counter: int,
        block_len: int,
        flags: int,
    ) -> None:
        self.input_cv = input_cv
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self) -> tuple[int, ...]:
        out = _compress(
            self.input_cv, self.block_words, self.counter, self.block_len, self.flags
        )
        return tuple(out[:8])

    def root_output_bytes(self) -> bytes:
        words = _compress(
            self.input_cv,
            self.block_words,
            0,
            self.block_len,
            self.flags | ROOT,
        )
        return struct.pack("<8I", *words[:8])


class _ChunkState:
    __slots__ = ("cv", "chunk_counter", "block", "block_len", "blocks_compressed", "flags")

    def __init__(self, key_words: tuple[int, ...], chunk_counter: int, flags: int) -> None:
        self.cv = key_words
        self.chunk_counter = chunk_counter
        self.block = bytearray(BLOCK_LEN)
        self.block_len = 0
        self.blocks_compressed = 0
        self.flags = flags

    def length(self) -> int:
        return BLOCK_LEN * self.blocks_compressed + self.block_len

    def start_flag(self) -> int:
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data: memoryview) -> None:
        offset = 0
        n = len(data)
        while offset < n:
            if self.block_len == BLOCK_LEN:
                words = struct.unpack("<16I", self.block)
                out = _compress(
                    self.cv,
                    words,
                    self.chunk_counter,
                    BLOCK_LEN,
                    self.flags | self.start_flag(),
                )
                self.cv = tuple(out[:8])
                self.blocks_compressed += 1
                self.block = bytearray(BLOCK_LEN)
                self.block_len = 0

            want = BLOCK_LEN - self.block_len
            take = min(want, n - offset)
            self.block[self.block_len : self.block_len + take] = data[offset : offset + take]
            self.block_len += take
            offset += take

    def output(self) -> _Output:
        words = _words_from_block(self.block[: self.block_len])
        return _Output(
            self.cv,
            words,
            self.chunk_counter,
            self.block_len,
            self.flags | self.start_flag() | CHUNK_END,
        )


def _parent_output(
    left_cv: tuple[int, ...],
    right_cv: tuple[int, ...],
    key_words: tuple[int, ...],
    flags: int,
) -> _Output:
    return _Output(key_words, left_cv + right_cv, 0, BLOCK_LEN, PARENT | flags)


class PureBlake3Hasher:
    """Streaming unkeyed & keyed BLAKE3-256 hasher."""

    __slots__ = ("_key_words", "_chunk_state", "_cv_stack", "_flags")

    def __init__(self, key: bytes | None = None) -> None:
        if key is not None:
            if len(key) != KEY_LEN:
                raise ValueError("BLAKE3 keyed_hash key must be exactly 32 bytes")
            self._key_words: tuple[int, ...] = struct.unpack("<8I", key)
            self._flags = KEYED_HASH
        else:
            self._key_words = IV
            self._flags = 0
        self._chunk_state = _ChunkState(self._key_words, 0, self._flags)
        self._cv_stack: list[tuple[int, ...]] = []

    def _add_chunk_cv(self, new_cv: tuple[int, ...], total_chunks: int) -> None:
        while (total_chunks & 1) == 0:
            new_cv = _parent_output(
                self._cv_stack.pop(), new_cv, self._key_words, self._flags
            ).chaining_value()
            total_chunks >>= 1
        self._cv_stack.append(new_cv)

    def update(self, data: bytes | bytearray | memoryview) -> "PureBlake3Hasher":
        view = memoryview(data)
        offset = 0
        total = len(view)
        while offset < total:
            if self._chunk_state.length() == CHUNK_LEN:
                chunk_cv = self._chunk_state.output().chaining_value()
                total_chunks = self._chunk_state.chunk_counter + 1
                self._add_chunk_cv(chunk_cv, total_chunks)
                self._chunk_state = _ChunkState(self._key_words, total_chunks, self._flags)

            want = CHUNK_LEN - self._chunk_state.length()
            take = min(want, total - offset)
            self._chunk_state.update(view[offset : offset + take])
            offset += take
        return self

    def digest(self) -> bytes:
        output = self._chunk_state.output()
        idx = len(self._cv_stack) - 1
        while idx >= 0:
            output = _parent_output(
                self._cv_stack[idx], output.chaining_value(), self._key_words, self._flags
            )
            idx -= 1
        return output.root_output_bytes()

    def hexdigest(self) -> str:
        return self.digest().hex()


def blake3_hash(parts: Iterable[bytes]) -> bytes:
    """Hashes iterable byte chunks into a 32-byte BLAKE3 digest."""
    if _native_blake3 is not None:
        h = _native_blake3.blake3()
        for p in parts:
            h.update(p)
        return h.digest()

    pure = PureBlake3Hasher()
    for p in parts:
        pure.update(p)
    return pure.digest()


def blake3_keyed_hash(key_32: bytes, parts: Iterable[bytes]) -> bytes:
    """Computes a 32-byte Keyed BLAKE3 MAC (`blake3::keyed_hash`)."""
    if len(key_32) != KEY_LEN:
        raise ValueError("key_32 must be exactly 32 bytes")
    if _native_blake3 is not None:
        h = _native_blake3.blake3(key=key_32)
        for p in parts:
            h.update(p)
        return h.digest()

    pure = PureBlake3Hasher(key=key_32)
    for p in parts:
        pure.update(p)
    return pure.digest()
