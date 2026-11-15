"""
Provides a KMAC-based XOF (extendable output function) implementation compliant with NIST SP 800-185, using the
`pycryptodome` library's KMAC implementation.

The KMAC-based XOF is used to generate a variable-length output from a fixed-length input, which is useful in cases
where a deterministic and secure pseudorandom output is required, but the length of the output may not be known in
advance or may need to be adjusted dynamically.

An example application of such an XOF is pseudorandomly selecting a sequence of integers from a finite set, where the
number of integers to select is not known in advance, and this process must be deterministic (and therefore repeatable)
but unpredictable. Similarly, another application is pseudorandom sampling from a chosen distribution, where the number
of needed samples is not known in advance.
"""
from __future__ import annotations

from typing import Final, Literal

from Cryptodome.Hash import cSHAKE128

KMAC_BLOCK_SIZE_BITS: Final[int] = 1600  # note: also used for KMACXOF128 and KMACXOF256
KMAC128_CAPACITY_BITS: Literal[256] = 256  # note: also used for KMACXOF128
KMAC256_CAPACITY_BITS: Literal[512] = 512  # note: also used for KMACXOF256
KMAC128_BLOCK_RATE_BYTES: Final[int] = (KMAC_BLOCK_SIZE_BITS - KMAC128_CAPACITY_BITS) // 8  # Block rate (bytes) for Keccak-1600 with 128-bit security
KMAC256_BLOCK_RATE_BYTES: Final[int] = (KMAC_BLOCK_SIZE_BITS - KMAC256_CAPACITY_BITS) // 8  # Block rate (bytes) for Keccak-1600 with 256-bit security


# noinspection pep8-naming
class KMAC_XOF(cSHAKE128.cSHAKE_XOF):
    # noinspection SpellCheckingInspection
    """
    Provides a KMAC-based eXtendable Output Function (XOF) that implements `KMACXOF128` & `KMACXOF256`, as specified in
    "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash (NIST Special Publication 800-185)"
    [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf), which uses `cSHAKE128`
    and `cSHAKE256` underneath (provided by the `pycryptodome` library).
    """

    def __init__(self, key: bytes, data: bytes, capacity: Literal[256, 512], custom: bytes = b""):
        """
        Do not use this constructor directly.
        Instead, use the kmacxof128() or kmacxof256() factory methods, to create a KMACXOF instance corresponding to
        KMAC128 or KMAC256. These factory methods construct the underlying cSHAKE128 or cSHAKE256 XOF using the
        appropriate capacity (i.e., 256 or 512 bits, respectively).
        :param key: The key to use for the KMAC-based XOF.
        :param data: The input data to be processed by the KMAC-based XOF.
        :param capacity: The capacity of the KMAC-based XOF, which determines the security level (in bits) of the
               output (i.e., 1/2 of the capacity). Must be either 256 or 512 bits (i.e., for KMACXOF128 or KMACXOF256, respectively).
        :param custom:
        """
        match capacity:
            case cap if cap == KMAC128_CAPACITY_BITS:
                new_x = self._bytepad(self._encode_string(key), KMAC128_BLOCK_RATE_BYTES) + data + self._right_encode(0)

                # noinspection argument-list
                super().__init__(data, custom=custom, capacity=KMAC128_CAPACITY_BITS, function=b"KMAC")
            case cap if cap == KMAC256_CAPACITY_BITS:
                new_x = self._bytepad(self._encode_string(key), KMAC256_BLOCK_RATE_BYTES) + data + self._right_encode(0)

                # noinspection argument-list
                super().__init__(data, custom=custom, capacity=KMAC256_CAPACITY_BITS, function=b"KMAC")
            case invalid:
                raise ValueError(
                    f"Invalid KMAC_XOF capacity provided: {invalid} bytes -- Must be either 256 or 512 bytes."
                )

        self.update(new_x)

    @staticmethod
    def _left_encode(x: int) -> bytes:
        if x == 0:
            return b"\x01\x00"

        n = (x.bit_length() + 7) // 8

        return bytes([n]) + x.to_bytes(n, "big")

    @staticmethod
    def _right_encode(x: int) -> bytes:
        if x == 0:
            return b"\x01\x00"

        n = (x.bit_length() + 7) // 8

        return x.to_bytes(n, "big") + bytes([n])

    @staticmethod
    def _encode_string(s: bytes) -> bytes:
        return KMAC_XOF._left_encode(len(s) * 8) + s

    # noinspection SpellCheckingInspection
    @staticmethod
    def _bytepad(x: bytes, w: int) -> bytes:
        z = KMAC_XOF._left_encode(w) + x
        pad_len = (w - (len(z) % w)) % w

        return z + (b"\x00" * pad_len)


# noinspection SpellCheckingInspection
class KMACXOF128(KMAC_XOF):
    """
    KMAC-based XOF (extendable output function) implementation compliant with NIST SP 800-185, using the `pycryptodome`
    library's KMAC implementation, with a capacity of 256 bits (i.e., for KMACXOF128).
    """

    def __init__(self, key: bytes, data: bytes, custom: bytes = b""):
        """
        Do not use this constructor directly.
        Instead, use the `new(...)` factory method, to create a `KMACXOF128` instance corresponding to `KMAC128`.
        This factory method constructs an underlying `KMAC_XOF` instance, initialized with the appropriate Keccak
        sponge capacity (i.e., 256 bits).
        :param key:
        :param data:
        :param custom:
        """
        super().__init__(key, data, capacity=KMAC128_CAPACITY_BITS, custom=custom)

    @classmethod
    def new(cls, key: bytes, data: bytes, custom: bytes = b"") -> KMAC_XOF:
        return cls(key, data, custom=custom)


# noinspection SpellCheckingInspection
class KMACXOF256(KMAC_XOF):
    """
    KMAC-based XOF (extendable output function) implementation compliant with NIST SP 800-185, using the `pycryptodome`
    library's KMAC implementation, with a capacity of 512 bits (i.e., for KMACXOF256).
    """

    def __init__(self, key: bytes, data: bytes, custom: bytes = b""):
        """
        Do not use this constructor directly.
        Instead, use the `new(...)` factory method, to create a `KMACXOF256` instance corresponding to `KMAC256`.
        This factory method constructs an underlying `KMAC_XOF` instance, initialized with the appropriate Keccak sponge
        capacity (i.e., 512 bits).
        :param key:
        :param data:
        :param custom:
        """
        super().__init__(key, data, capacity=KMAC256_CAPACITY_BITS, custom=custom)

    @classmethod
    def new(cls, key: bytes, data: bytes, custom: bytes = b"") -> KMAC_XOF:
        return cls(key, data, custom=custom)
